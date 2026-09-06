// TeckThorn Sentinel — application shell & orchestration
'use strict';

// Exposed on window (not `const`) so it's reachable from devtools and behaves predictably
// across classic <script> tags.
window.STATE = {
  currentPage: 'dashboard',
  sessionLog: [],
  sightengine: { apiUser: '', apiSecret: '' }
};
const STATE = window.STATE;

/* ===================== BOOT ===================== */
const BOOT_MESSAGES = [
  'Loading forensic modules…',
  'Initializing metadata parsers (EXIF / PNG / ID3 / MP4)…',
  'Preparing frequency-domain analysis (FFT)…',
  'Preparing anomaly & entropy scanners…',
  'Ready.'
];
window.addEventListener('DOMContentLoaded', () => {
  let progress = 0, msgIdx = 0;
  const bar = document.getElementById('boot-bar');
  const status = document.getElementById('boot-status');
  const interval = setInterval(() => {
    progress += 18 + Math.random() * 10;
    if (progress > 100) progress = 100;
    bar.style.width = progress + '%';
    const targetIdx = Math.min(BOOT_MESSAGES.length - 1, Math.floor((progress / 100) * BOOT_MESSAGES.length));
    if (targetIdx !== msgIdx) { msgIdx = targetIdx; status.textContent = BOOT_MESSAGES[msgIdx]; }
    if (progress >= 100) { clearInterval(interval); setTimeout(launchApp, 400); }
  }, 140);
});

function launchApp() {
  document.getElementById('boot-screen').classList.add('fade-out');
  document.getElementById('app').classList.remove('hidden');
  setTimeout(initApp, 250);
}

function initApp() {
  startClock();
  checkConnectivity();
  wireUpload('detect-upload-zone', 'detect-file-input', onDetectFileChosen);
  wireUpload('anomaly-upload-zone', 'anomaly-file-input', onAnomalyFileChosen);
  renderDashboard();
  renderMethodology();
  updateLogBadge();
}

function startClock() {
  const clockEl = document.getElementById('clock');
  function tick() { clockEl.textContent = new Date().toLocaleTimeString(); }
  tick(); setInterval(tick, 1000);
}
function checkConnectivity() {
  const dot = document.getElementById('online-status-dot');
  const text = document.getElementById('online-status-text');
  function update() {
    const online = navigator.onLine;
    dot.className = 'status-dot ' + (online ? 'green' : 'amber');
    text.textContent = online ? 'Online (link-out tools available)' : 'Offline (local analysis still works)';
  }
  update();
  window.addEventListener('online', update);
  window.addEventListener('offline', update);
}

/* ===================== NAVIGATION ===================== */
function navigate(page) {
  STATE.currentPage = page;
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.getElementById('page-' + page).classList.add('active');
  document.querySelectorAll('.nav-item').forEach(n => n.classList.toggle('active', n.dataset.page === page));
  const titles = { dashboard: 'Dashboard', detect: 'AI Media Detection', anomaly: 'Anomaly Detection', log: 'Session Log', methodology: 'Methodology', settings: 'Settings' };
  document.getElementById('breadcrumb').textContent = titles[page] || page;
  if (page === 'dashboard') renderDashboard();
  if (window.innerWidth <= 900) document.getElementById('sidebar').classList.remove('open');
}
function toggleSidebar() { document.getElementById('sidebar').classList.toggle('open'); }

/* ===================== UPLOAD WIRING ===================== */
function wireUpload(zoneId, inputId, handler) {
  const zone = document.getElementById(zoneId);
  const input = document.getElementById(inputId);
  zone.addEventListener('click', () => input.click());
  input.addEventListener('change', (e) => { if (e.target.files[0]) handler(e.target.files[0]); });
  ['dragenter', 'dragover'].forEach(ev => zone.addEventListener(ev, (e) => { e.preventDefault(); zone.classList.add('drag-over'); }));
  ['dragleave', 'drop'].forEach(ev => zone.addEventListener(ev, (e) => { e.preventDefault(); zone.classList.remove('drag-over'); }));
  zone.addEventListener('drop', (e) => { const f = e.dataTransfer.files[0]; if (f) handler(f); });
}

/* ===================== STEP PROGRESS UI ===================== */
function makeStepper(containerId, steps) {
  const container = document.getElementById(containerId);
  container.parentElement.style.display = '';
  container.innerHTML = '';
  const rows = steps.map(label => {
    const row = TT.util.el('div', { class: 'step-row pending' }, [
      TT.util.el('span', { class: 'step-dot' }, []),
      TT.util.el('span', { class: 'step-label' }, [label])
    ]);
    container.appendChild(row);
    return row;
  });
  return {
    start(i) { rows[i].className = 'step-row active'; },
    done(i) { rows[i].className = 'step-row done'; },
    fail(i, msg) { rows[i].className = 'step-row failed'; if (msg) rows[i].querySelector('.step-label').textContent += ' — ' + msg; }
  };
}

/* ===================== AI MEDIA DETECTION PIPELINE ===================== */
async function onDetectFileChosen(file) {
  document.getElementById('detect-file-info').classList.remove('hidden');
  document.getElementById('detect-file-info').innerHTML = `<b>${TT.util.escapeHtml(file.name)}</b> · ${TT.util.formatBytes(file.size)} · ${file.type || 'unknown type'}`;
  document.getElementById('detect-results-placeholder').style.display = 'none';
  const resultsEl = document.getElementById('detect-results');
  resultsEl.classList.add('hidden'); resultsEl.innerHTML = '';

  const arrayBuffer = await TT.util.readFileAsArrayBuffer(file);
  const bytes = new Uint8Array(arrayBuffer);
  const detected = TT.signatures.detectFormat(bytes);
  const kind = classifyKind(detected, file.type);

  renderPreview(file, kind);

  const baseSteps = ['Reading file', 'Computing hashes', 'Scanning metadata & signatures'];
  const kindSteps = kind === 'image' ? ['Running Error Level Analysis', 'Running frequency-domain analysis', 'Running noise-residual analysis']
    : kind === 'video' ? ['Extracting sample frames', 'Running per-frame forensic pipeline']
    : kind === 'audio' ? ['Decoding audio', 'Computing waveform & spectrogram', 'Computing spectral statistics']
    : [];
  const steps = baseSteps.concat(kindSteps, ['Scoring & building report']);
  const stepper = makeStepper('detect-steps', steps);
  let s = 0;

  try {
    stepper.start(s);
    const sha256 = await TT.util.sha256Hex(arrayBuffer);
    stepper.done(s++); 

    stepper.start(s);
    const sigMatches = TT.signatures.signatureScan(bytes);
    const pipelineMatches = TT.signatures.pipelineSignatureScan(bytes);
    let imgMeta = null, xmpC2pa = false;
    if (detected.format === 'JPEG image') { imgMeta = TT.metaImage.analyzeJPEG(bytes); xmpC2pa = imgMeta.hasAPP11 || /c2pa|jumbf|contentauth/i.test(imgMeta.xmp || ''); }
    else if (detected.format.startsWith('PNG')) { imgMeta = TT.metaImage.analyzePNG(bytes); xmpC2pa = imgMeta.hasC2PAChunk; }
    stepper.done(s++);

    let analysis = { kind, detected, sha256, sigMatches, pipelineMatches, imgMeta };

    if (kind === 'image') {
      const imageEls = await loadImageElementAndCanvas(file);
      const dsz = TT.imageForensics.downscaleForAnalysis(imageEls.canvas, 1600);
      const analysisImageData = dsz.scaled ? dsz.canvas.getContext('2d').getImageData(0, 0, dsz.width, dsz.height) : imageEls.imageData;
      stepper.start(s);
      const recomp = await TT.videoForensics.recompressCanvasJPEG(dsz.canvas, 0.9);
      const ela = TT.imageForensics.computeELA(analysisImageData, recomp, 12);
      stepper.done(s++);
      stepper.start(s);
      const freq = TT.imageForensics.computeFrequencyAnalysis(analysisImageData);
      stepper.done(s++);
      stepper.start(s);
      const noise = TT.imageForensics.computeNoiseResidual(analysisImageData, 2);
      stepper.done(s++);
      const lsb = TT.anomaly.analyzeLSBSteganography(analysisImageData);
      const hasCameraExif = !!(imgMeta && imgMeta.exif && imgMeta.exif.ifd0 && imgMeta.exif.ifd0.some(t => (t.name === 'Make' || t.name === 'Model') && t.value));
      const featVec = TT.trainedModel.buildFeatureVector({ ela, noise, freq, lsb, pipelineTags: pipelineMatches, hasCameraExif, width: imageEls.width, height: imageEls.height });
      const trainedModel = TT.trainedModel.predict(featVec);
      const verdict = TT.imageForensics.combineImageVerdict({ ela, noise, freq, aiTags: sigMatches, c2paHint: xmpC2pa, pipelineTags: pipelineMatches, hasCameraExif, width: imageEls.width, height: imageEls.height, trainedModel });
      if (dsz.scaled) verdict.findings.push({ level: 'info', text: `This is a ${dsz.originalWidth}×${dsz.originalHeight} image (${((dsz.originalWidth*dsz.originalHeight)/1e6).toFixed(1)}MP). Pixel-level analysis (ELA/noise/frequency) ran on a downscaled ${dsz.width}×${dsz.height} copy for performance — standard practice for high-resolution forensic analysis. Metadata, hashing, and signature scanning still used the full original file.` });
      analysis = Object.assign(analysis, { imageEls, ela, freq, noise, lsb, verdict, width: imageEls.width, height: imageEls.height });
    } else if (kind === 'video') {
      stepper.start(s);
      const { frames, duration, width, height } = await TT.videoForensics.extractFrames(file, 5);
      stepper.done(s++);
      stepper.start(s);
      const frameAnalysis = frames.length ? await TT.videoForensics.analyzeFrames(frames) : { perFrame: [], avgScore: 0, maxScore: 0, scoreSpread: 0 };
      stepper.done(s++);
      const verdict = { score: frameAnalysis.avgScore, verdictClass: scoreToClass(frameAnalysis.avgScore), verdict: scoreToLabel(frameAnalysis.avgScore),
        findings: [
          { level: 'info', text: `Sampled ${frames.length} frame(s) across a ${duration ? duration.toFixed(1) + 's' : 'unknown-length'} video (${width}×${height}).` },
          ...(sigMatches.length ? [{ level: 'strong', text: `Metadata/byte scan found generator references: ${sigMatches.slice(0,3).map(m=>m.signature).join(', ')}.` }] : []),
          { level: frameAnalysis.scoreSpread > 25 ? 'weak' : 'none', text: `Per-frame indicator scores ranged from ${Math.min(...frameAnalysis.perFrame.map(p=>p.verdict.score), 0).toFixed(0)} to ${frameAnalysis.maxScore.toFixed(0)} (spread ${frameAnalysis.scoreSpread.toFixed(0)}). ${frameAnalysis.scoreSpread > 25 ? 'Large spread can indicate inconsistent editing across the clip.' : 'Frames look consistent with each other.'}` }
        ] };
      if (sigMatches.length) verdict.score = Math.max(verdict.score, 55);
      analysis = Object.assign(analysis, { frameAnalysis, duration, width, height, verdict });
    } else if (kind === 'audio') {
      stepper.start(s);
      const { audioBuffer, ctx } = await TT.audioForensics.decodeAudio(file);
      stepper.done(s++);
      stepper.start(s);
      const samples = TT.audioForensics.getMonoSamples(audioBuffer);
      const peaks = TT.audioForensics.computeWaveformPeaks(samples, 600);
      const spec = TT.audioForensics.computeSpectrogram(samples, audioBuffer.sampleRate);
      stepper.done(s++);
      stepper.start(s);
      const flatness = TT.audioForensics.spectralFlatness(spec.frames);
      const silence = TT.audioForensics.silenceRegularity(samples, audioBuffer.sampleRate);
      let id3 = null;
      if (detected.format.includes('MP3')) id3 = TT.metaContainer.parseID3v2(bytes);
      const verdict = TT.audioForensics.combineAudioVerdict({ flatness, silence, aiTags: sigMatches });
      stepper.done(s++);
      analysis = Object.assign(analysis, { audioBuffer, peaks, spec, flatness, silence, id3, verdict, duration: audioBuffer.duration });
      try { ctx.close(); } catch (e) {}
    } else {
      const verdict = { score: sigMatches.length ? 40 : 0, verdictClass: sigMatches.length ? 'amber' : 'blue', verdict: sigMatches.length ? 'Generator references found in file bytes' : 'Not a recognized image/video/audio format — limited analysis available',
        findings: sigMatches.length ? [{ level: 'moderate', text: `Found: ${sigMatches.map(m=>m.signature).join(', ')}` }] : [{ level: 'none', text: 'Try the Anomaly Detection tab for a general file-integrity scan of this file type.' }] };
      analysis.verdict = verdict;
    }

    stepper.start(s); stepper.done(s++);

    renderDetectResults(file, analysis);
    logAnalysis(file, analysis, 'detect');
  } catch (err) {
    console.error(err);
    stepper.fail(s, err.message);
    TT.util.toast('Analysis error: ' + err.message, 'error');
    const resultsEl = document.getElementById('detect-results');
    resultsEl.classList.remove('hidden');
    resultsEl.innerHTML = `<div class="card"><div class="card-header"><h3>Error</h3></div><p>${TT.util.escapeHtml(err.message)}</p><p class="muted small">This can happen if your browser can't decode this specific codec/container. Try the Anomaly Detection tab for a format-agnostic scan instead.</p></div>`;
  }
}

function classifyKind(detected, mimeType) {
  if (detected && detected.kind === 'image') return 'image';
  if (detected && detected.kind === 'video') return 'video';
  if (detected && detected.kind === 'audio') return 'audio';
  if (mimeType && mimeType.startsWith('image/')) return 'image';
  if (mimeType && mimeType.startsWith('video/')) return 'video';
  if (mimeType && mimeType.startsWith('audio/')) return 'audio';
  return 'other';
}

function loadImageElementAndCanvas(file) {
  return new Promise((resolve, reject) => {
    const url = URL.createObjectURL(file);
    const img = new Image();
    img.onload = () => {
      const canvas = document.createElement('canvas');
      canvas.width = img.width; canvas.height = img.height;
      const ctx = canvas.getContext('2d');
      ctx.drawImage(img, 0, 0);
      let imageData;
      try { imageData = ctx.getImageData(0, 0, img.width, img.height); }
      catch (e) { URL.revokeObjectURL(url); return reject(new Error('Could not read pixel data (possibly a tainted canvas).')); }
      URL.revokeObjectURL(url);
      resolve({ img, canvas, ctx, imageData, width: img.width, height: img.height });
    };
    img.onerror = () => { URL.revokeObjectURL(url); reject(new Error('Could not decode this image file.')); };
    img.src = url;
  });
}

function scoreToClass(score) { return score >= 60 ? 'red' : score >= 30 ? 'amber' : score >= 10 ? 'blue' : 'green'; }
function scoreToLabel(score) { return score >= 60 ? 'Strong indicators found' : score >= 30 ? 'Some indicators — inconclusive' : score >= 10 ? 'Weak/no strong indicators' : 'No meaningful indicators found'; }

function renderPreview(file, kind) {
  const card = document.getElementById('detect-preview-card');
  const preview = document.getElementById('detect-preview');
  card.style.display = '';
  preview.innerHTML = '';
  const url = URL.createObjectURL(file);
  if (kind === 'image') preview.appendChild(TT.util.el('img', { src: url, class: 'preview-media' }, []));
  else if (kind === 'video') preview.appendChild(TT.util.el('video', { src: url, class: 'preview-media', controls: 'true' }, []));
  else if (kind === 'audio') preview.appendChild(TT.util.el('audio', { src: url, controls: 'true', style: 'width:100%' }, []));
  else preview.appendChild(TT.util.el('p', { class: 'muted' }, ['No visual preview for this file type.']));
}

function findingBadgeClass(level) { return { strong: 'red', moderate: 'amber', weak: 'blue', info: 'blue', none: 'muted' }[level] || 'muted'; }

function renderDetectResults(file, a) {
  const el = document.getElementById('detect-results');
  el.classList.remove('hidden');
  el.innerHTML = '';

  // Verdict card
  el.appendChild(TT.util.el('div', { class: 'card verdict-card verdict-' + a.verdict.verdictClass }, [
    TT.util.el('div', { class: 'verdict-score' }, [String(Math.round(a.verdict.score))]),
    TT.util.el('div', { class: 'verdict-text' }, [
      TT.util.el('div', { class: 'verdict-title' }, [a.verdict.verdict]),
      TT.util.el('div', { class: 'verdict-sub' }, ['Composite heuristic indicator score (0–100) — not a probability, not proof. See findings below.'])
    ])
  ]));

  // Findings list
  const findingsCard = TT.util.el('div', { class: 'card' }, [TT.util.el('div', { class: 'card-header' }, [TT.util.el('h3', {}, ['Findings'])])]);
  const findingsList = TT.util.el('div', { class: 'findings-list' }, []);
  (a.verdict.findings || []).forEach(f => {
    findingsList.appendChild(TT.util.el('div', { class: 'finding-row' }, [
      TT.util.el('span', { class: 'finding-badge ' + findingBadgeClass(f.level) }, [f.level.toUpperCase()]),
      TT.util.el('span', { class: 'finding-text' }, [f.text])
    ]));
  });
  findingsCard.appendChild(findingsList);
  el.appendChild(findingsCard);

  // Image-specific visuals
  if (a.kind === 'image') {
    const visCard = TT.util.el('div', { class: 'card' }, [TT.util.el('div', { class: 'card-header' }, [TT.util.el('h3', {}, ['Visual Forensics'])])]);
    const grid = TT.util.el('div', { class: 'vis-grid' }, []);

    const elaCanvas = document.createElement('canvas'); elaCanvas.className = 'vis-canvas';
    elaCanvas.width = a.ela.width; elaCanvas.height = a.ela.height;
    const elaCtx = elaCanvas.getContext('2d');
    const elaImgData = elaCtx.createImageData(a.ela.width, a.ela.height);
    elaImgData.data.set(a.ela.diffVis);
    elaCtx.putImageData(elaImgData, 0, 0);
    grid.appendChild(TT.util.el('div', { class: 'vis-item' }, [elaCanvas, TT.util.el('p', { class: 'vis-caption' }, [`ELA heatmap — ${a.ela.hotBlockCount}/${a.ela.totalBlocks} blocks flagged`])]));

    const noiseCanvas = document.createElement('canvas'); noiseCanvas.className = 'vis-canvas';
    TT.viz.renderBlockHeatmap(noiseCanvas, a.noise.blockEnergy, a.noise.bw, a.noise.bh, 256, 256);
    grid.appendChild(TT.util.el('div', { class: 'vis-item' }, [noiseCanvas, TT.util.el('p', { class: 'vis-caption' }, [`Noise energy map — coeff. var ${a.noise.coeffVar.toFixed(2)}`])]));

    const freqCanvas = document.createElement('canvas'); freqCanvas.className = 'vis-canvas';
    TT.viz.renderScalarHeatmap(freqCanvas, a.freq.heatmapPlane, a.freq.heatmapSize, { gamma: 0.6 });
    grid.appendChild(TT.util.el('div', { class: 'vis-item' }, [freqCanvas, TT.util.el('p', { class: 'vis-caption' }, [`Frequency spectrum — max prominence ${a.freq.maxProminence.toFixed(2)}`])]));

    visCard.appendChild(grid);
    el.appendChild(visCard);

    if (a.lsb) {
      const lsbCard = TT.util.el('div', { class: 'card' }, [
        TT.util.el('div', { class: 'card-header' }, [TT.util.el('h3', {}, ['Statistical LSB Steganalysis (heuristic)'])]),
        TT.util.el('p', { class: 'muted small' }, [`Sampled ${a.lsb.sampledPixels.toLocaleString()} pixels. Highest region p-value: ${a.lsb.maxP.toFixed(3)}. ${a.lsb.highPWindows} of 36 windows exceeded p>0.95 (a classic but imperfect chi-square "pairs of values" test — see Methodology).`])
      ]);
      el.appendChild(lsbCard);
    }
  }

  // Video filmstrip
  if (a.kind === 'video' && a.frameAnalysis) {
    const filmCard = TT.util.el('div', { class: 'card' }, [TT.util.el('div', { class: 'card-header' }, [TT.util.el('h3', {}, ['Sampled Frames'])])]);
    const strip = TT.util.el('div', { class: 'filmstrip' }, []);
    a.frameAnalysis.perFrame.forEach(f => {
      const thumb = document.createElement('canvas');
      thumb.width = 120; thumb.height = Math.round(120 * (f.thumbCanvas.height / f.thumbCanvas.width));
      thumb.getContext('2d').drawImage(f.thumbCanvas, 0, 0, thumb.width, thumb.height);
      strip.appendChild(TT.util.el('div', { class: 'filmstrip-item' }, [
        thumb,
        TT.util.el('div', { class: 'filmstrip-score ' + scoreToClass(f.verdict.score) }, [Math.round(f.verdict.score) + '']),
        TT.util.el('div', { class: 'muted small' }, [f.timestamp.toFixed(1) + 's'])
      ]));
    });
    filmCard.appendChild(strip);
    el.appendChild(filmCard);
  }

  // Audio visuals
  if (a.kind === 'audio') {
    const audCard = TT.util.el('div', { class: 'card' }, [TT.util.el('div', { class: 'card-header' }, [TT.util.el('h3', {}, ['Waveform &amp; Spectral Stats'])])]);
    const waveCanvas = document.createElement('canvas'); waveCanvas.width = 600; waveCanvas.height = 100; waveCanvas.className = 'vis-canvas-wide';
    drawWaveform(waveCanvas, a.peaks);
    audCard.appendChild(waveCanvas);
    audCard.appendChild(TT.util.el('p', { class: 'muted small mt-8' }, [`Duration ${a.duration.toFixed(1)}s · Spectral flatness ${a.flatness.toFixed(3)} · Silence gaps: ${a.silence.gapCount} (coeff. var ${a.silence.coeffVar.toFixed(2)})`]));
    el.appendChild(audCard);
    if (a.id3 && a.id3.frames.length) {
      const id3Card = TT.util.el('div', { class: 'card' }, [TT.util.el('div', { class: 'card-header' }, [TT.util.el('h3', {}, ['ID3 Tags'])])]);
      a.id3.frames.forEach(f => id3Card.appendChild(TT.util.el('div', { class: 'kv-row' }, [TT.util.el('span', { class: 'kv-key' }, [f.id]), TT.util.el('span', { class: 'kv-val' }, [f.text || '(binary)'])])));
      el.appendChild(id3Card);
    }
  }

  // Metadata & signatures
  const metaCard = TT.util.el('div', { class: 'card' }, [TT.util.el('div', { class: 'card-header' }, [TT.util.el('h3', {}, ['Metadata &amp; Signature Scan'])])]);
  metaCard.appendChild(TT.util.el('div', { class: 'kv-row' }, [TT.util.el('span', { class: 'kv-key' }, ['Detected format']), TT.util.el('span', { class: 'kv-val' }, [a.detected.format])]));
  metaCard.appendChild(TT.util.el('div', { class: 'kv-row' }, [TT.util.el('span', { class: 'kv-key' }, ['SHA-256']), TT.util.el('span', { class: 'kv-val mono' }, [a.sha256])]));
  if (a.imgMeta && a.imgMeta.exif && a.imgMeta.exif.ifd0 && a.imgMeta.exif.ifd0.length) {
    a.imgMeta.exif.ifd0.filter(t => t.value !== null).slice(0, 8).forEach(t => metaCard.appendChild(TT.util.el('div', { class: 'kv-row' }, [TT.util.el('span', { class: 'kv-key' }, ['EXIF ' + t.name]), TT.util.el('span', { class: 'kv-val' }, [String(t.value)])])));
    metaCard.appendChild(TT.util.el('div', { class: 'kv-row' }, [TT.util.el('span', { class: 'kv-key' }, ['GPS data present']), TT.util.el('span', { class: 'kv-val' }, [a.imgMeta.exif.hasGPS ? 'Yes' : 'No'])]));
  }
  if (a.imgMeta && a.imgMeta.texts && a.imgMeta.texts.length) {
    a.imgMeta.texts.forEach(t => metaCard.appendChild(TT.util.el('div', { class: 'kv-row' }, [TT.util.el('span', { class: 'kv-key' }, [t.key]), TT.util.el('span', { class: 'kv-val mono small-wrap' }, [t.value.slice(0, 400)])])));
  }
  if (a.sigMatches.length) {
    metaCard.appendChild(TT.util.el('div', { class: 'kv-row' }, [TT.util.el('span', { class: 'kv-key' }, ['AI/provenance keyword matches']), TT.util.el('span', { class: 'kv-val' }, [a.sigMatches.map(m => m.signature).join(', ')])]));
  } else {
    metaCard.appendChild(TT.util.el('div', { class: 'kv-row' }, [TT.util.el('span', { class: 'kv-key' }, ['AI/provenance keyword matches']), TT.util.el('span', { class: 'kv-val muted' }, ['None found'])]));
  }
  if (a.pipelineMatches && a.pipelineMatches.length) {
    metaCard.appendChild(TT.util.el('div', { class: 'kv-row' }, [TT.util.el('span', { class: 'kv-key' }, ['Encoder/pipeline signature']), TT.util.el('span', { class: 'kv-val' }, [a.pipelineMatches.map(m => m.signature).join(', ') + ' (server-side library, not a camera)'])]));
  }
  el.appendChild(metaCard);

  // Online tools
  const toolsCard = TT.util.el('div', { class: 'card' }, [TT.util.el('div', { class: 'card-header' }, [TT.util.el('h3', {}, ['Cross-check Online'])])]);
  const toolsContainer = TT.util.el('div', {}, []);
  toolsCard.appendChild(toolsContainer);
  el.appendChild(toolsCard);
  TT.onlineTools.renderToolsPanel(toolsContainer, a.kind === 'other' ? 'file' : a.kind, { sha256: a.sha256 });

  // Optional Sightengine
  if ((a.kind === 'image' || a.kind === 'video' || a.kind === 'audio')) {
    const seCard = TT.util.el('div', { class: 'card' }, [TT.util.el('div', { class: 'card-header' }, [TT.util.el('h3', {}, ['Optional: Live Sightengine Check'])])]);
    if (STATE.sightengine.apiUser && STATE.sightengine.apiSecret) {
      const btn = TT.util.el('button', { class: 'action-btn green-btn' }, ['Run Sightengine genai check']);
      const resultDiv = TT.util.el('div', { class: 'mt-8' }, []);
      btn.onclick = async () => {
        btn.disabled = true; btn.textContent = 'Calling Sightengine…';
        try {
          const res = await TT.onlineTools.callSightengine(file, a.kind, STATE.sightengine.apiUser, STATE.sightengine.apiSecret);
          const p = res.type && res.type.ai_generated !== undefined ? res.type.ai_generated : (res.genai || null);
          resultDiv.innerHTML = `<pre class="mono small-wrap">${TT.util.escapeHtml(JSON.stringify(res, null, 2)).slice(0, 2000)}</pre>`;
        } catch (err) {
          resultDiv.innerHTML = `<p class="muted small">${TT.util.escapeHtml(err.message)}</p>`;
        }
        btn.disabled = false; btn.textContent = 'Run Sightengine genai check again';
      };
      seCard.appendChild(btn); seCard.appendChild(resultDiv);
    } else {
      seCard.appendChild(TT.util.el('p', { class: 'muted small' }, ['Not configured. Add your free Sightengine API credentials in ']));
      seCard.querySelector('p').appendChild(TT.util.el('a', { href: '#', onclick: (e) => { e.preventDefault(); navigate('settings'); } }, ['Settings']));
      seCard.querySelector('p').appendChild(document.createTextNode(' to enable this.'));
    }
    el.appendChild(seCard);
  }

  // Export
  const exportRow = TT.util.el('div', { class: 'card' }, [
    TT.util.el('button', { class: 'action-btn', onclick: () => exportSingleReport(file, a) }, ['Export this report (JSON)'])
  ]);
  el.appendChild(exportRow);
}

function drawWaveform(canvas, peaks) {
  const ctx = canvas.getContext('2d');
  const W = canvas.width, H = canvas.height, mid = H / 2;
  ctx.clearRect(0, 0, W, H);
  ctx.fillStyle = '#00c8ff';
  const buckets = peaks.length / 2;
  const bw = W / buckets;
  for (let i = 0; i < buckets; i++) {
    const mn = peaks[i * 2], mx = peaks[i * 2 + 1];
    ctx.fillRect(i * bw, mid + mn * mid, Math.max(1, bw), Math.max(1, (mx - mn) * mid));
  }
}

/* ===================== ANOMALY DETECTION PIPELINE ===================== */
async function onAnomalyFileChosen(file) {
  document.getElementById('anomaly-file-info').classList.remove('hidden');
  document.getElementById('anomaly-file-info').innerHTML = `<b>${TT.util.escapeHtml(file.name)}</b> · ${TT.util.formatBytes(file.size)} · ${file.type || 'unknown type'}`;
  document.getElementById('anomaly-results-placeholder').style.display = 'none';
  const resultsEl = document.getElementById('anomaly-results');
  resultsEl.classList.add('hidden'); resultsEl.innerHTML = '';

  const steps = ['Reading file', 'Computing hashes', 'Detecting format & checking extension', 'Validating file structure', 'Scanning entropy', 'Scanning for known signatures', 'Building report'];
  const stepper = makeStepper('anomaly-steps', steps);
  let s = 0;

  try {
    stepper.start(s);
    const arrayBuffer = await TT.util.readFileAsArrayBuffer(file);
    const bytes = new Uint8Array(arrayBuffer);
    stepper.done(s++);

    stepper.start(s);
    const [sha256, sha1] = await Promise.all([TT.util.sha256Hex(arrayBuffer), TT.util.sha1Hex(arrayBuffer)]);
    stepper.done(s++);

    stepper.start(s);
    const detected = TT.signatures.detectFormat(bytes);
    const extFindings = TT.anomaly.checkExtensionAndExecutable(file.name, detected);
    stepper.done(s++);

    stepper.start(s);
    const structureFindings = TT.anomaly.validateStructure(bytes, detected);
    stepper.done(s++);

    stepper.start(s);
    const entropyResult = TT.anomaly.entropyScan(bytes);
    document.getElementById('anomaly-entropy-card').style.display = '';
    TT.viz.drawLineChart(document.getElementById('anomaly-entropy-canvas'), [{ values: Array.from(entropyResult.values), color: '#00c8ff' }], { min: 0, max: 8, decimals: 0 });
    let lsbResult = null;
    if (detected.kind === 'image') {
      try { const imageEls = await loadImageElementAndCanvas(file); lsbResult = TT.anomaly.analyzeLSBSteganography(imageEls.imageData); } catch (e) {}
    }
    stepper.done(s++);

    stepper.start(s);
    const sigMatches = TT.signatures.signatureScan(bytes);
    stepper.done(s++);

    stepper.start(s);
    const report = TT.anomaly.combineAnomalyReport(structureFindings, extFindings, entropyResult, lsbResult, sigMatches);
    stepper.done(s++);

    renderAnomalyResults(file, { detected, sha256, sha1, report, entropyResult, sigMatches, size: file.size });
    logAnalysis(file, { kind: 'anomaly', detected, sha256, verdict: { score: TT.anomaly.severityRank(report.worstSeverity) * 25, verdictClass: severityToClass(report.worstSeverity), verdict: report.worstSeverity.toUpperCase() + ' severity' } }, 'anomaly');
  } catch (err) {
    console.error(err);
    stepper.fail(s, err.message);
    TT.util.toast('Scan error: ' + err.message, 'error');
  }
}

function severityToClass(sev) { return { critical: 'red', high: 'red', medium: 'amber', low: 'blue', info: 'green' }[sev] || 'blue'; }

function renderAnomalyResults(file, r) {
  const el = document.getElementById('anomaly-results');
  el.classList.remove('hidden');
  el.innerHTML = '';

  el.appendChild(TT.util.el('div', { class: 'card verdict-card verdict-' + severityToClass(r.report.worstSeverity) }, [
    TT.util.el('div', { class: 'verdict-score small' }, [r.report.worstSeverity.toUpperCase()]),
    TT.util.el('div', { class: 'verdict-text' }, [
      TT.util.el('div', { class: 'verdict-title' }, [`${r.report.findings.length} finding(s), worst severity: ${r.report.worstSeverity}`]),
      TT.util.el('div', { class: 'verdict-sub' }, [`Format: ${r.detected.format}`])
    ])
  ]));

  const findingsCard = TT.util.el('div', { class: 'card' }, [TT.util.el('div', { class: 'card-header' }, [TT.util.el('h3', {}, ['Findings'])])]);
  const list = TT.util.el('div', { class: 'findings-list' }, []);
  r.report.findings.forEach(f => {
    list.appendChild(TT.util.el('div', { class: 'finding-row' }, [
      TT.util.el('span', { class: 'finding-badge ' + severityToClass(f.severity) }, [f.severity.toUpperCase()]),
      TT.util.el('div', {}, [TT.util.el('div', { class: 'finding-title' }, [f.title]), TT.util.el('div', { class: 'finding-text' }, [f.detail])])
    ]));
  });
  findingsCard.appendChild(list);
  el.appendChild(findingsCard);

  const hashCard = TT.util.el('div', { class: 'card' }, [TT.util.el('div', { class: 'card-header' }, [TT.util.el('h3', {}, ['File Info &amp; Hashes'])])]);
  [['Size', TT.util.formatBytes(r.size)], ['Detected format', r.detected.format], ['SHA-256', r.sha256], ['SHA-1', r.sha1]].forEach(([k, v]) => {
    hashCard.appendChild(TT.util.el('div', { class: 'kv-row' }, [TT.util.el('span', { class: 'kv-key' }, [k]), TT.util.el('span', { class: 'kv-val mono small-wrap' }, [v])]));
  });
  el.appendChild(hashCard);

  if (r.sigMatches.length) {
    const sigCard = TT.util.el('div', { class: 'card' }, [TT.util.el('div', { class: 'card-header' }, [TT.util.el('h3', {}, ['Signature Matches'])])]);
    r.sigMatches.forEach(m => sigCard.appendChild(TT.util.el('div', { class: 'kv-row' }, [TT.util.el('span', { class: 'kv-key' }, [m.signature]), TT.util.el('span', { class: 'kv-val mono small' }, ['…' + m.context + '…'])])));
    el.appendChild(sigCard);
  }

  const toolsCard = TT.util.el('div', { class: 'card' }, [TT.util.el('div', { class: 'card-header' }, [TT.util.el('h3', {}, ['Cross-check Online'])])]);
  const toolsContainer = TT.util.el('div', {}, []);
  toolsCard.appendChild(toolsContainer);
  el.appendChild(toolsCard);
  TT.onlineTools.renderToolsPanel(toolsContainer, 'file', { sha256: r.sha256 });

  el.appendChild(TT.util.el('div', { class: 'card' }, [
    TT.util.el('button', { class: 'action-btn', onclick: () => exportSingleReport(file, { kind: 'anomaly', ...r }) }, ['Export this report (JSON)'])
  ]));
}

/* ===================== SESSION LOG & DASHBOARD ===================== */
function logAnalysis(file, analysis, mode) {
  const entry = {
    id: TT.util.uid(), time: new Date(), name: file.name, size: file.size,
    kind: analysis.kind, mode, score: analysis.verdict.score, verdictClass: analysis.verdict.verdictClass,
    verdict: analysis.verdict.verdict, sha256: analysis.sha256 || ''
  };
  STATE.sessionLog.unshift(entry);
  updateLogBadge();
  renderDashboard();
  renderSessionLog();
}
function updateLogBadge() { document.getElementById('log-badge').textContent = STATE.sessionLog.length; }

function renderDashboard() {
  const log = STATE.sessionLog;
  document.getElementById('stat-total').textContent = log.length;
  const clean = log.filter(l => l.verdictClass === 'green').length;
  const uncertain = log.filter(l => l.verdictClass === 'blue' || l.verdictClass === 'amber').length;
  const flagged = log.filter(l => l.verdictClass === 'red').length;
  document.getElementById('stat-clean').textContent = clean;
  document.getElementById('stat-uncertain').textContent = uncertain;
  document.getElementById('stat-flagged').textContent = flagged;

  const emptyState = document.getElementById('dashboard-empty');
  const chartWrap = document.getElementById('dashboard-chart-wrap');
  const activityCard = document.getElementById('recent-activity-card');
  if (!log.length) {
    emptyState.classList.remove('hidden'); chartWrap.classList.add('hidden'); activityCard.style.display = 'none';
    return;
  }
  emptyState.classList.add('hidden'); chartWrap.classList.remove('hidden'); activityCard.style.display = '';
  TT.viz.drawDonut(document.getElementById('donut-chart'), [
    { value: clean || 0.0001, color: '#00e676' }, { value: uncertain || 0.0001, color: '#ffab40' }, { value: flagged || 0.0001, color: '#ff4f4f' }
  ]);
  document.getElementById('donut-legend').innerHTML = `
    <div class="legend-item"><span class="dot green"></span>No strong indicators (${clean})</div>
    <div class="legend-item"><span class="dot amber"></span>Weak/uncertain (${uncertain})</div>
    <div class="legend-item"><span class="dot red"></span>Strong indicators (${flagged})</div>`;

  const body = document.getElementById('recent-activity-body');
  body.innerHTML = '';
  log.slice(0, 8).forEach(e => {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${e.time.toLocaleTimeString()}</td><td>${TT.util.escapeHtml(e.name)}</td><td>${e.kind}</td><td>${Math.round(e.score)}</td><td><span class="pill ${e.verdictClass}">${TT.util.escapeHtml(e.verdict)}</span></td><td>${e.mode}</td>`;
    body.appendChild(tr);
  });
}

function renderSessionLog() {
  const log = STATE.sessionLog;
  document.getElementById('log-empty').classList.toggle('hidden', log.length > 0);
  document.getElementById('log-table-wrap').classList.toggle('hidden', log.length === 0);
  const body = document.getElementById('log-table-body');
  body.innerHTML = '';
  log.forEach(e => {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${e.time.toLocaleTimeString()}</td><td>${TT.util.escapeHtml(e.name)}</td><td>${TT.util.formatBytes(e.size)}</td><td>${e.kind} / ${e.mode}</td><td>${Math.round(e.score)}</td><td><span class="pill ${e.verdictClass}">${TT.util.escapeHtml(e.verdict)}</span></td><td class="mono small">${e.sha256 ? e.sha256.slice(0, 16) + '…' : '—'}</td>`;
    body.appendChild(tr);
  });
}

function clearSessionLog() {
  STATE.sessionLog = [];
  updateLogBadge(); renderDashboard(); renderSessionLog();
  TT.util.toast('Session log cleared');
}

function exportSessionReport() {
  const report = { generatedAt: new Date().toISOString(), tool: 'TeckThorn Sentinel', entries: STATE.sessionLog };
  TT.util.downloadBlob('sentinel-session-report-' + Date.now() + '.json', JSON.stringify(report, null, 2), 'application/json');
  TT.util.toast('Report exported');
}
function exportSingleReport(file, analysis) {
  const clean = JSON.parse(JSON.stringify(analysis, (k, v) => {
    if (v instanceof Uint8Array || v instanceof Uint8ClampedArray || v instanceof Float64Array || v instanceof Float32Array) return '[binary data omitted]';
    if (k === 'imageEls' || k === 'canvas' || k === 'ctx' || k === 'img' || k === 'audioBuffer' || k === 'thumbCanvas') return undefined;
    return v;
  }));
  const report = { generatedAt: new Date().toISOString(), tool: 'TeckThorn Sentinel', file: { name: file.name, size: file.size, type: file.type }, analysis: clean };
  TT.util.downloadBlob('sentinel-report-' + file.name.replace(/[^a-z0-9.]/gi, '_') + '.json', JSON.stringify(report, null, 2), 'application/json');
  TT.util.toast('Report exported');
}

/* ===================== SETTINGS ===================== */
function saveSightengineKeys() {
  STATE.sightengine.apiUser = document.getElementById('se-api-user').value.trim();
  STATE.sightengine.apiSecret = document.getElementById('se-api-secret').value.trim();
  document.getElementById('se-save-status').textContent = STATE.sightengine.apiUser && STATE.sightengine.apiSecret
    ? '✓ Saved in memory for this session.' : 'Cleared — enter both fields to enable the live check.';
  TT.util.toast('Sightengine settings updated');
}

/* ===================== METHODOLOGY ===================== */
function renderMethodology() {
  const items = [
    { title: 'Metadata & Signature Scan', body: 'We parse EXIF (JPEG), PNG text chunks, ID3 tags (MP3), and RIFF/MP4 box structures directly from the file bytes, and run a keyword scan for known generative-AI tool names, prompt/parameter dumps (e.g. Stable Diffusion "parameters" chunks), and C2PA/JUMBF provenance strings. This is often the strongest and most reliable signal — many AI tools leave explicit traces — but a clean scan proves nothing: metadata is trivially stripped or forged.' },
    { title: 'Encoder / Pipeline Fingerprint', body: 'Many AI image-generation APIs re-encode their output through a server-side library like GD (libgd) or ImageMagick before serving it — leaving a plaintext signature (e.g. "CREATOR: gd-jpeg…") in the JPEG comment segment. Real camera and phone photos are essentially never encoded this way. Combined with the total absence of camera EXIF data and an exact square, power-of-two resolution (512/768/1024/2048 — common generation-model defaults), this is a genuinely strong combined signal, though on its own a GD/ImageMagick signature just means "processed by a web backend," which ordinary websites also do to real photos — hence it\u2019s only scored heavily when all three conditions line up.' },
    { title: 'Trained Model (logistic regression)', body: `A small, deliberately simple linear model trained on ${TT.trainedModel.MODEL.nTrain} real labeled examples (${TT.trainedModel.MODEL.nAi} AI-generated across two different generator batches, ${TT.trainedModel.MODEL.nReal} genuine photos from mixed sources) using the exact same ELA/noise/frequency/metadata features described on this page — extracted with this app's own code, not a separate pipeline. 5-fold cross-validated performance: ROC-AUC ${TT.trainedModel.MODEL.cvRocAuc.toFixed(2)}, accuracy ~${Math.round(TT.trainedModel.MODEL.cvAccuracy*100)}%. That is real, meaningfully-better-than-chance signal — and also an honest admission that 141 examples is a small dataset. We chose a linear model specifically so every weight is inspectable rather than a black box, and weighted its contribution to the overall score modestly for exactly this reason. Tested against 71 held-out real photos, it produced zero false "strong AI" verdicts; tested against 71 known-AI images from a source it wasn\u2019t tuned on, it correctly moved the majority from "no signal" to at least a weak/moderate indicator. It will keep improving as more labeled examples are added — see the project README for how to extend the training set.` },
    { title: 'Error Level Analysis (ELA)', body: 'Recompresses the image at a fixed JPEG quality and diffs it against the original. Regions that were edited or spliced in after the original compression pass tend to respond differently to recompression than the rest of the image, showing up as bright blocks. This is a decades-old forensic technique (see FotoForensics) — real, but it has known false positives near sharp edges and on already-compressed images, and false negatives on heavily-recompressed patches.' },
    { title: 'Frequency-Domain (FFT) Analysis', body: 'Computes a real 2D Fast Fourier Transform of the image and looks at how energy falls off from low to high frequencies, plus isolated spectral peaks. Natural photos usually show a smooth power-law falloff; some GAN/upsampling pipelines leave periodic, checkerboard-like artifacts that show up as unusual peaks. This is an active, imperfect area of AI-detection research — treat it as a weak signal, not a verdict.' },
    { title: 'Noise-Residual Analysis', body: 'Subtracts a blurred version of the image from itself to isolate high-frequency "noise," then measures how that noise energy varies across the image. Real camera sensor noise usually correlates with scene content; unnaturally flat or unnaturally uniform noise can indicate synthetic or heavily-processed origin. Many modern generators now add synthetic grain specifically to defeat this check, so it is a weak signal.' },
    { title: 'Statistical LSB Steganalysis', body: 'Runs a chi-square "pairs of values" test (Westfeld & Pfitzmann, 1999) on the least-significant bits of pixel color channels, in sequential windows. A very high p-value in a region is classically associated with LSB-embedded data. This is a real, textbook technique — validated here against synthetic embedded/non-embedded test images — but it produces false positives on smooth or already-noisy regions and only catches naive LSB-replacement steganography, not more sophisticated hiding methods.' },
    { title: 'File-Structure & Entropy Anomaly Detection', body: 'Validates PNG chunk CRCs, JPEG/PNG/ZIP/PDF end-of-file markers, and MP4 box structure; flags any data appended after a file\u2019s expected end (a common way to hide payloads); and scans byte-level Shannon entropy in sliding windows to surface localized high-entropy regions that can indicate embedded encrypted or compressed content.' },
    { title: 'Video & Audio', body: 'Video: samples several evenly-spaced frames using your browser\u2019s own video decoder and runs the same image pipeline on each, then compares scores across frames. Audio: computes a real waveform and spectrogram, plus spectral flatness and pause-timing regularity as weak, exploratory signals — client-side audio deepfake detection is a much less mature science than image forensics, so we lean harder on metadata/signature checks and link-outs here.' },
    { title: 'What this tool cannot do', body: 'No detector — ours or any commercial one — reliably identifies AI-generated content from the newest generation models; published 2026 accuracy figures for the best commercial tools range roughly 75–95% depending on the generator, and drop further on recompressed/cropped/screenshotted images. A "no indicators found" result means exactly that: none of these specific checks fired, not that the file is proven authentic. Treat every score here as one input among several, especially the linked third-party tools, human judgement, and — where it matters (legal, journalistic, safety-critical) — a qualified forensic examiner.' }
  ];
  const container = document.getElementById('methodology-content');
  container.innerHTML = '';
  items.forEach(i => container.appendChild(TT.util.el('div', { class: 'card method-card' }, [
    TT.util.el('div', { class: 'card-header' }, [TT.util.el('h3', {}, [i.title])]),
    TT.util.el('p', {}, [i.body])
  ])));
}
