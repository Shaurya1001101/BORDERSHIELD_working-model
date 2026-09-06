'use strict';
// Extracts the same forensic features the browser app computes (ELA, noise, frequency,
// metadata flags, resolution) for a directory of images, and writes them to a CSV.
// Reuses the REAL site JS (via jsdom + node-canvas) so features are byte-for-byte identical
// to what the live tool computes — critical to avoid train/serve skew.
const fs = require('fs');
const path = require('path');
const { JSDOM } = require('jsdom');
const { createCanvas, Image: NodeImage } = require('canvas');

async function makeEnv() {
  // The shipped project layout is: <project-root>/index.html + js/ + training/ (this file).
  // So the app root is simply the parent of this training/ folder — not a "site" subfolder.
  const SITE = path.join(__dirname, '..');
  // Strip the external Google Fonts <link> tags for local extraction runs: jsdom's resource
  // loader retries the network fetch (blocked in this sandbox) on every single invocation,
  // adding a large fixed delay before any actual work starts. Doesn't affect the shipped site.
  const rawHtml = fs.readFileSync(path.join(SITE, 'index.html'), 'utf8');
  const strippedHtml = rawHtml.replace(/<link rel="preconnect"[^>]*>/, '').replace(/<link href="https:\/\/fonts\.googleapis\.com[^>]*>/, '');
  const tmpHtmlPath = path.join(__dirname, '_extract_env.html');
  fs.writeFileSync(tmpHtmlPath, strippedHtml);
  const dom = await JSDOM.fromFile(tmpHtmlPath, {
    url: 'file://' + SITE + '/index.html', runScripts: 'dangerously', resources: 'usable', pretendToBeVisual: true
  });
  const { window } = dom;
  await new Promise((resolve) => { if (window.document.readyState === 'complete') resolve(); else window.addEventListener('load', resolve); });
  window.HTMLCanvasElement.prototype.getContext = function () {
    if (!this._nc || this._nc.width !== this.width || this._nc.height !== this.height) this._nc = createCanvas(this.width || 300, this.height || 150);
    return this._nc.getContext('2d');
  };
  window.HTMLCanvasElement.prototype.toDataURL = function (m, q) { return this._nc.toDataURL(m, q); };
  // node-canvas's real drawImage rejects jsdom's <canvas> element wrapper as a source (it wants
  // its own Canvas/Image objects) — real browsers accept any canvas element fine, so this is a
  // test-harness-only shim: unwrap our stashed node-canvas backing object before delegating.
  {
    const probeCtx = createCanvas(1, 1).getContext('2d');
    const proto = Object.getPrototypeOf(probeCtx);
    const originalDrawImage = proto.drawImage;
    proto.drawImage = function (source, ...rest) {
      const real = (source && source._nc) ? source._nc : source;
      return originalDrawImage.call(this, real, ...rest);
    };
  }
  window.Image = NodeImage;
  if (!window.crypto || !window.crypto.subtle) Object.defineProperty(window, 'crypto', { value: globalThis.crypto, configurable: true });
  return window;
}

function loadImageDataFromBuffer(window, buf, mimeType) {
  return new Promise((resolve, reject) => {
    const img = new window.Image();
    img.onload = () => {
      const canvas = window.document.createElement('canvas');
      canvas.width = img.width; canvas.height = img.height;
      const ctx = canvas.getContext('2d');
      ctx.drawImage(img, 0, 0);
      resolve({ canvas, ctx, imageData: ctx.getImageData(0, 0, img.width, img.height), width: img.width, height: img.height });
    };
    img.onerror = reject;
    img.src = `data:${mimeType};base64,${buf.toString('base64')}`;
  });
}

async function extractFeatures(window, buf, filename) {
  const bytes = new Uint8Array(buf);
  const detected = window.TT.signatures.detectFormat(bytes);
  const sigMatches = window.TT.signatures.signatureScan(bytes);
  const pipelineMatches = window.TT.signatures.pipelineSignatureScan(bytes);

  let imgMeta = null, xmpC2pa = false, hasCameraExif = false;
  if (detected.format === 'JPEG image') {
    imgMeta = window.TT.metaImage.analyzeJPEG(bytes);
    xmpC2pa = imgMeta.hasAPP11 || /c2pa|jumbf|contentauth/i.test(imgMeta.xmp || '');
    hasCameraExif = !!(imgMeta.exif && imgMeta.exif.ifd0 && imgMeta.exif.ifd0.some(t => (t.name === 'Make' || t.name === 'Model') && t.value));
  } else if (detected.format.startsWith('PNG')) {
    imgMeta = window.TT.metaImage.analyzePNG(bytes);
    xmpC2pa = imgMeta.hasC2PAChunk;
  }

  const mimeType = detected.format === 'PNG image' ? 'image/png' : 'image/jpeg';
  const loaded = await loadImageDataFromBuffer(window, buf, mimeType);
  const width = loaded.width, height = loaded.height;
  const dsz = window.TT.imageForensics.downscaleForAnalysis(loaded.canvas, 1600);
  const imageData = dsz.scaled ? dsz.canvas.getContext('2d').getImageData(0, 0, dsz.width, dsz.height) : loaded.imageData;

  const recomp = await window.TT.videoForensics.recompressCanvasJPEG(dsz.canvas, 0.9);
  const ela = window.TT.imageForensics.computeELA(imageData, recomp, 12);
  const noise = window.TT.imageForensics.computeNoiseResidual(imageData, 2);
  const freq = window.TT.imageForensics.computeFrequencyAnalysis(imageData);
  const lsb = window.TT.anomaly.analyzeLSBSteganography(imageData);

  const isSquarePow2 = width === height && (width & (width - 1)) === 0;

  return {
    filename,
    width, height, aspect: width / height, isSquarePow2: isSquarePow2 ? 1 : 0, megapixels: (width * height) / 1e6,
    hasCameraExif: hasCameraExif ? 1 : 0,
    hasAITag: sigMatches.length ? 1 : 0,
    hasPipelineTag: pipelineMatches.length ? 1 : 0,
    hasC2paHint: xmpC2pa ? 1 : 0,
    elaGlobalMean: ela.globalMean, elaGlobalStd: ela.globalStd, elaHotBlockRatio: ela.hotBlockRatio, elaMaxBlock: ela.maxBlock,
    noiseMeanEnergy: noise.meanEnergy, noiseStdEnergy: noise.stdEnergy, noiseCoeffVar: noise.coeffVar,
    freqHighBand: freq.highBand, freqMidBand: freq.midBand, freqHighMidRatio: freq.highMidRatio,
    freqMaxProminence: freq.maxProminence, freqMeanProminence: freq.meanProminence, freqOutlierRatio: freq.outlierRatio,
    lsbMaxP: lsb.maxP, lsbHighPWindows: lsb.highPWindows,
    pipelineSignature: pipelineMatches.length ? pipelineMatches[0].signature : '',
  };
}

function toCSV(rows) {
  if (!rows.length) return '';
  const cols = Object.keys(rows[0]);
  const lines = [cols.join(',')];
  for (const r of rows) lines.push(cols.map(c => {
    const v = r[c];
    if (typeof v === 'string' && (v.includes(',') || v.includes('"'))) return `"${v.replace(/"/g, '""')}"`;
    return v;
  }).join(','));
  return lines.join('\n');
}

async function main() {
  const [, , dirArg, labelArg, outArg] = process.argv;
  if (!dirArg || !labelArg || !outArg) {
    console.error('Usage: node extract_features.js <image-dir> <label:ai|real> <output.csv> [--append]');
    process.exit(1);
  }
  const window = await makeEnv();
  const files = fs.readdirSync(dirArg).filter(f => /\.(jpe?g|png)$/i.test(f)).sort();
  console.log(`Extracting features from ${files.length} images in ${dirArg} (label=${labelArg})...`);

  const append = process.argv.includes('--append') && fs.existsSync(outArg);
  let cols = null;
  let existingKeys = new Set();
  if (append) {
    const existingLines = fs.readFileSync(outArg, 'utf8').trim().split('\n');
    cols = existingLines[0].split(',');
    const fnIdx = cols.indexOf('filename'), labelIdx = cols.indexOf('label');
    // resume support keyed by (label, filename) — plain filename alone collides across
    // classes when both datasets happen to use the same sequential naming scheme.
    for (const line of existingLines.slice(1)) {
      const parts = line.split(',');
      existingKeys.add(parts[labelIdx] + '::' + parts[fnIdx]);
    }
  } else {
    fs.writeFileSync(outArg, '');
  }

  let written = 0, failed = 0;
  for (let i = 0; i < files.length; i++) {
    const f = files[i];
    const key = labelArg + '::' + f;
    if (existingKeys.has(key)) { process.stdout.write(`  [${i + 1}/${files.length}] ${f} (already done, skip)\n`); continue; }
    try {
      const buf = fs.readFileSync(path.join(dirArg, f));
      const feats = await extractFeatures(window, buf, f);
      feats.label = labelArg;
      if (!cols) cols = Object.keys(feats);
      const lineNeedsHeader = !append && written === 0 && !fs.existsSync(outArg + '.header');
      if (!fs.readFileSync(outArg, 'utf8').trim()) fs.appendFileSync(outArg, cols.join(',') + '\n');
      const line = cols.map(c => {
        const v = feats[c];
        if (typeof v === 'string' && (v.includes(',') || v.includes('"'))) return `"${v.replace(/"/g, '""')}"`;
        return v;
      }).join(',');
      fs.appendFileSync(outArg, line + '\n');
      written++;
      process.stdout.write(`  [${i + 1}/${files.length}] ${f} \u2713\n`);
    } catch (e) {
      failed++;
      console.error(`  [${i + 1}/${files.length}] ${f} FAILED: ${e.message}`);
    }
  }
  console.log(`\nDone. Wrote ${written} new rows, ${failed} failed, ${existingKeys.size} already present -> ${outArg}`);
  process.exit(0);
}

main();
