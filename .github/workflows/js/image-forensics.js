// TeckThorn Sentinel — pixel-level image forensics
// ELA + noise-residual math verified against real spliced-image test fixtures during
// development (hot ELA blocks correctly localized to the pasted/edited region).
window.TT = window.TT || {};

(function (TT) {
  'use strict';
  const { fft } = TT;

  /* ---------------- Downscale for performance on very large images ---------------- */
  // ELA/noise/frequency analysis don't need full sensor resolution to be meaningful, and
  // modern phone/DSLR photos can be 40-100+ megapixels — running block-wise pixel loops at
  // full resolution can take tens of seconds in JS. Real forensic tools commonly cap analysis
  // resolution for exactly this reason. Callers keep the original canvas for preview/hashing/
  // metadata, and only pass a downscaled copy into the pixel-level analysis functions.
  function downscaleForAnalysis(sourceCanvas, maxDim) {
    maxDim = maxDim || 1600;
    const width = sourceCanvas.width, height = sourceCanvas.height;
    if (Math.max(width, height) <= maxDim) return { canvas: sourceCanvas, width, height, scaled: false };
    const scale = maxDim / Math.max(width, height);
    const newW = Math.max(1, Math.round(width * scale));
    const newH = Math.max(1, Math.round(height * scale));
    const canvas = document.createElement('canvas');
    canvas.width = newW; canvas.height = newH;
    canvas.getContext('2d').drawImage(sourceCanvas, 0, 0, newW, newH);
    return { canvas, width: newW, height: newH, scaled: true, originalWidth: width, originalHeight: height };
  }

  function toGrayscalePlane(imgData) {
    const { data, width, height } = imgData;
    const gray = new Float64Array(width * height);
    for (let i = 0, p = 0; i < data.length; i += 4, p++) gray[p] = 0.299 * data[i] + 0.587 * data[i + 1] + 0.114 * data[i + 2];
    return gray;
  }
  function clampIdx(i, n) { return i < 0 ? 0 : (i >= n ? n - 1 : i); }
  function boxBlur1Pass(src, width, height, radius) {
    const out = new Float64Array(width * height);
    const norm = 1 / (radius * 2 + 1);
    const tmp = new Float64Array(width * height);
    for (let y = 0; y < height; y++) {
      let acc = 0; const rowOff = y * width;
      for (let x = -radius; x <= radius; x++) acc += src[rowOff + clampIdx(x, width)];
      for (let x = 0; x < width; x++) {
        tmp[rowOff + x] = acc * norm;
        acc += src[rowOff + clampIdx(x + radius + 1, width)] - src[rowOff + clampIdx(x - radius, width)];
      }
    }
    for (let x = 0; x < width; x++) {
      let acc = 0;
      for (let y = -radius; y <= radius; y++) acc += tmp[clampIdx(y, height) * width + x];
      for (let y = 0; y < height; y++) {
        out[y * width + x] = acc * norm;
        acc += tmp[clampIdx(y + radius + 1, height) * width + x] - tmp[clampIdx(y - radius, height) * width + x];
      }
    }
    return out;
  }
  function gaussianApprox(plane, width, height, radius) {
    let p = boxBlur1Pass(plane, width, height, radius);
    p = boxBlur1Pass(p, width, height, radius);
    return boxBlur1Pass(p, width, height, radius);
  }

  /* ---------------- Error Level Analysis ---------------- */
  function computeELA(originalData, recompData, amplify) {
    amplify = amplify || 12;
    const { width, height } = originalData;
    const a = originalData.data, b = recompData.data;
    const diffGray = new Float64Array(width * height);
    const diffVis = new Uint8ClampedArray(width * height * 4);
    for (let i = 0, p = 0; i < a.length; i += 4, p++) {
      const dr = Math.abs(a[i] - b[i]), dg = Math.abs(a[i + 1] - b[i + 1]), db = Math.abs(a[i + 2] - b[i + 2]);
      diffGray[p] = (dr + dg + db) / 3;
      diffVis[p * 4] = Math.min(255, dr * amplify);
      diffVis[p * 4 + 1] = Math.min(255, dg * amplify);
      diffVis[p * 4 + 2] = Math.min(255, db * amplify);
      diffVis[p * 4 + 3] = 255;
    }
    const blockSize = 16;
    const bw = Math.ceil(width / blockSize), bh = Math.ceil(height / blockSize);
    const blockMeans = new Float64Array(bw * bh);
    for (let by = 0; by < bh; by++) for (let bx = 0; bx < bw; bx++) {
      let sum = 0, count = 0;
      const x0 = bx * blockSize, y0 = by * blockSize, x1 = Math.min(width, x0 + blockSize), y1 = Math.min(height, y0 + blockSize);
      for (let y = y0; y < y1; y++) for (let x = x0; x < x1; x++) { sum += diffGray[y * width + x]; count++; }
      blockMeans[by * bw + bx] = count ? sum / count : 0;
    }
    let sum = 0; for (let i = 0; i < blockMeans.length; i++) sum += blockMeans[i];
    const mean = sum / blockMeans.length;
    let sq = 0; for (let i = 0; i < blockMeans.length; i++) sq += (blockMeans[i] - mean) ** 2;
    const std = Math.sqrt(sq / blockMeans.length);
    const threshold = mean + 2 * std;
    let hotCount = 0, maxBlock = 0; const hotBlocks = [];
    for (let by = 0; by < bh; by++) for (let bx = 0; bx < bw; bx++) {
      const v = blockMeans[by * bw + bx];
      if (v > maxBlock) maxBlock = v;
      if (v > threshold && std > 0.05) { hotCount++; hotBlocks.push({ bx, by, value: v }); }
    }
    return { diffVis, width, height, blockMeans, bw, bh, blockSize, globalMean: mean, globalStd: std, threshold, hotBlockCount: hotCount, totalBlocks: blockMeans.length, hotBlockRatio: hotCount / blockMeans.length, maxBlock, hotBlocks };
  }

  /* ---------------- Noise residual ---------------- */
  function computeNoiseResidual(imgData, blurRadius) {
    blurRadius = blurRadius || 2;
    const { width, height } = imgData;
    const gray = toGrayscalePlane(imgData);
    const blurred = gaussianApprox(gray, width, height, blurRadius);
    const residual = new Float64Array(width * height);
    for (let i = 0; i < gray.length; i++) residual[i] = gray[i] - blurred[i];
    const blockSize = 16;
    const bw = Math.ceil(width / blockSize), bh = Math.ceil(height / blockSize);
    const blockEnergy = new Float64Array(bw * bh);
    for (let by = 0; by < bh; by++) for (let bx = 0; bx < bw; bx++) {
      let sq = 0, count = 0;
      const x0 = bx * blockSize, y0 = by * blockSize, x1 = Math.min(width, x0 + blockSize), y1 = Math.min(height, y0 + blockSize);
      for (let y = y0; y < y1; y++) for (let x = x0; x < x1; x++) { sq += residual[y * width + x] ** 2; count++; }
      blockEnergy[by * bw + bx] = count ? Math.sqrt(sq / count) : 0;
    }
    let sum = 0; for (let i = 0; i < blockEnergy.length; i++) sum += blockEnergy[i];
    const mean = sum / blockEnergy.length;
    let sq2 = 0; for (let i = 0; i < blockEnergy.length; i++) sq2 += (blockEnergy[i] - mean) ** 2;
    const std = Math.sqrt(sq2 / blockEnergy.length);
    return { blockEnergy, bw, bh, blockSize, meanEnergy: mean, stdEnergy: std, coeffVar: mean > 1e-9 ? std / mean : 0 };
  }

  /* ---------------- Frequency-domain / spectral peak analysis ---------------- */
  function computeFrequencyAnalysis(imgData) {
    const size = 256;
    // resize grayscale into a size x size plane via nearest sampling of the source imgData
    const { width, height } = imgData;
    const gray = toGrayscalePlane(imgData);
    const resized = new Float64Array(size * size);
    for (let y = 0; y < size; y++) {
      const sy = Math.min(height - 1, Math.floor((y / size) * height));
      for (let x = 0; x < size; x++) {
        const sx = Math.min(width - 1, Math.floor((x / size) * width));
        resized[y * size + x] = gray[sy * width + sx];
      }
    }
    const mag = fft.fft2dMagnitude(resized, size);
    const shifted = fft.fftShift2D(mag, size);
    const logMag = new Float64Array(size * size);
    for (let i = 0; i < logMag.length; i++) logMag[i] = Math.log10(shifted[i] + 1);
    const localAvg = boxBlur1Pass(logMag, size, size, 3);
    const cx = size / 2, cy = size / 2;
    let maxProm = -Infinity, sumProm = 0, nOutside = 0;
    const proms = [];
    for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) {
      const dx = x - cx, dy = y - cy, r = Math.sqrt(dx * dx + dy * dy);
      if (r < 10) continue;
      nOutside++;
      const prom = logMag[y * size + x] - localAvg[y * size + x];
      proms.push(prom); sumProm += prom; if (prom > maxProm) maxProm = prom;
    }
    const meanProm = sumProm / nOutside;
    let sq = 0; for (const p of proms) sq += (p - meanProm) ** 2;
    const stdProm = Math.sqrt(sq / nOutside);
    const outlierCount = proms.filter(p => p > meanProm + 4 * stdProm).length;
    const radial = fft.radialAverage(shifted, size);
    const logRadial = Array.from(radial).map(v => Math.log10(v + 1));
    const highBand = logRadial.slice(90, 128).reduce((a, b) => a + b, 0) / 38;
    const midBand = logRadial.slice(20, 60).reduce((a, b) => a + b, 0) / 40;
    return {
      logRadial, highBand, midBand, highMidRatio: midBand > 0 ? highBand / midBand : 0,
      maxProminence: maxProm, meanProminence: meanProm, stdProminence: stdProm,
      outlierCount, outlierRatio: outlierCount / nOutside,
      heatmapPlane: logMag, heatmapSize: size
    };
  }

  /* ---------------- Combine into an explainable score ---------------- */
  function combineImageVerdict(signals) {
    // signals: { ela, noise, freq, aiTags: [...], c2paHint: bool, pipelineTags: [...],
    //            hasCameraExif: bool, width, height }
    const findings = [];
    let score = 0; // 0..100 "AI/manipulation indicator" composite (heuristic, explainable, not a probability)

    if (signals.aiTags && signals.aiTags.length) {
      score += 55;
      findings.push({ level: 'strong', text: `Metadata explicitly references a generative-AI tool or generation parameters (${signals.aiTags.slice(0, 3).map(t => t.signature).join(', ')}).` });
    }
    if (signals.c2paHint) {
      score += 20;
      findings.push({ level: 'moderate', text: 'Byte-level scan found strings resembling a C2PA/JUMBF content-provenance manifest. Use the Content Credentials Verify link below for an authoritative reading — it may declare AI generation, AI-assisted editing, or a fully camera-original capture.' });
    }
    if (signals.pipelineTags && signals.pipelineTags.length) {
      const isSquarePow2 = signals.width && signals.height && signals.width === signals.height && (signals.width & (signals.width - 1)) === 0;
      if (!signals.hasCameraExif) {
        const bonus = isSquarePow2 ? 56 : 28;
        score += bonus;
        findings.push({ level: isSquarePow2 ? 'strong' : 'moderate', text: `Image was encoded by a server-side image-processing library (${signals.pipelineTags[0].signature}), not a camera or phone, and carries no camera EXIF data at all${isSquarePow2 ? `, and is an exact square power-of-two resolution (${signals.width}×${signals.height}) — the combination of no camera metadata, a non-camera encoder, and a generation-model-typical square size is rarely seen in genuine photos` : ''}. Ordinary web-resized photos can occasionally show a subset of this pattern, so treat alongside the other findings below.` });
      } else {
        findings.push({ level: 'weak', text: `Image shows a server-side processing library signature (${signals.pipelineTags[0].signature}), but also has camera EXIF data — most likely just a resized/re-hosted real photo, not a generated one.` });
      }
    }
    if (signals.ela) {
      const r = signals.ela.hotBlockRatio;
      if (r > 0.08) { score += 18; findings.push({ level: 'moderate', text: `Error Level Analysis found ${signals.ela.hotBlockCount} of ${signals.ela.totalBlocks} blocks (${(r * 100).toFixed(1)}%) with unusually high recompression error — consistent with localized editing or splicing.` }); }
      else if (r > 0.02) { score += 6; findings.push({ level: 'weak', text: `A small number of blocks (${signals.ela.hotBlockCount}) show elevated recompression error. This can indicate minor edits, or can occur naturally near sharp edges — not conclusive alone.` }); }
      else findings.push({ level: 'none', text: 'Error Level Analysis found no significant localized recompression anomalies.' });
    }
    if (signals.noise) {
      if (signals.noise.meanEnergy < 0.6) { score += 12; findings.push({ level: 'weak', text: `Sensor-noise residual is very low (mean energy ${signals.noise.meanEnergy.toFixed(2)}). Real camera photos usually carry some sensor noise; diffusion/GAN output is often unnaturally smooth. Some AI tools now add synthetic grain, so this is a weak signal on its own.` }); }
      else if (signals.noise.coeffVar < 0.25) { score += 8; findings.push({ level: 'weak', text: `Noise energy is unusually uniform across the image (coefficient of variation ${signals.noise.coeffVar.toFixed(2)}). Natural photo noise usually correlates with scene content (more in texture/shadow, less in smooth sky); very uniform noise can indicate synthetic or heavily denoised origin.` }); }
      else findings.push({ level: 'none', text: 'Noise pattern looks broadly consistent with a natural photographic sensor.' });
    }
    if (signals.freq) {
      if (signals.freq.outlierRatio > 0.0008 || signals.freq.maxProminence > 1.4) {
        score += 10;
        findings.push({ level: 'weak', text: `Frequency-domain analysis found isolated high-energy peaks outside the normal spectral falloff (max prominence ${signals.freq.maxProminence.toFixed(2)}). This pattern can appear in GAN/upsampling artifacts, but also from JPEG blocking or fine repeating textures.` });
      } else findings.push({ level: 'none', text: 'Frequency spectrum shows a natural, smooth falloff with no strong periodic artifacts.' });
    }
    if (!signals.hasCameraExif && (!signals.aiTags || !signals.aiTags.length) && (!signals.pipelineTags || !signals.pipelineTags.length)) {
      findings.push({ level: 'none', text: 'No camera EXIF data found. This alone is common and not suspicious — many images are legitimately stripped of metadata by messaging apps, social media, or screenshots — but it does mean this tool has less to go on than it would for an unmodified camera original.' });
    }
    if (signals.trainedModel) {
      const p = signals.trainedModel.probability;
      const pct = Math.round(p * 100);
      if (p >= 0.65) {
        score += 16;
        findings.push({ level: 'moderate', text: `A small trained model (logistic regression on ${TT.trainedModel.MODEL.nTrain} labeled examples; 5-fold cross-validated accuracy ~${Math.round(TT.trainedModel.MODEL.cvAccuracy*100)}%) estimates ${pct}% probability this image is AI-generated, based on the combined pixel/metadata features above. This model is small and should be treated as a weak-to-moderate signal, not a verdict — it will improve as more training examples are added.` });
      } else if (p <= 0.35) {
        findings.push({ level: 'none', text: `The trained model (same caveats as above) estimates only ${pct}% probability of AI generation for this image — leans toward authentic.` });
      } else {
        findings.push({ level: 'none', text: `The trained model's estimate (${pct}% AI probability) is inconclusive for this image.` });
      }
    }

    score = TT.util.clamp(score, 0, 100);
    let verdict, verdictClass;
    if (score >= 60) { verdict = 'Strong indicators of AI generation or heavy manipulation'; verdictClass = 'red'; }
    else if (score >= 30) { verdict = 'Some indicators of AI involvement or editing — inconclusive'; verdictClass = 'amber'; }
    else if (score >= 10) { verdict = 'Weak/no strong indicators — likely authentic, minor uncertainty remains'; verdictClass = 'blue'; }
    else { verdict = 'No meaningful indicators found — consistent with an unmodified camera photo'; verdictClass = 'green'; }

    return { score, verdict, verdictClass, findings };
  }

  TT.imageForensics = { downscaleForAnalysis, toGrayscalePlane, boxBlur1Pass, gaussianApprox, computeELA, computeNoiseResidual, computeFrequencyAnalysis, combineImageVerdict };
})(window.TT);
