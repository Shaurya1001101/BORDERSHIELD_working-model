# BORDERSHIELD — AI Media Forensics & Anomaly Detection

A complete rebuild of the original prototype. Every screen here does real work — there is
no `Math.random()` fakery, no scripted "boot sequence" demo data, and no canned presets.
Everything runs **entirely client-side** in plain HTML/CSS/JavaScript (no build step, no
server, no framework) — open `index.html` in a browser and it works.

## What actually works

### 🧠 AI Media Detection (`AI Media Detection` tab)
Upload an image, video, or audio file. The app runs a real, explainable pipeline:

- **Metadata & signature forensics** — hand-written parsers for JPEG/EXIF, PNG chunks,
  ID3v2, RIFF/WAV, and MP4/MOV boxes, plus a keyword scan for known generative-AI tool
  names, Stable-Diffusion-style prompt dumps, and C2PA/JUMBF provenance strings.
- **Error Level Analysis (ELA)** — recompresses the image and diffs it against the
  original to surface locally-edited/spliced regions, rendered as a heatmap.
- **Frequency-domain (FFT) analysis** — a real, from-scratch 2D Fast Fourier Transform
  looks for the periodic spectral artifacts sometimes left by GAN/diffusion upsampling.
- **Noise-residual analysis** — isolates high-frequency sensor-noise-like content and
  checks whether its distribution looks like a natural photo or an unnaturally smooth/
  uniform synthetic image.
- **Statistical LSB steganalysis** — a textbook chi-square "pairs of values" test.
- **Video** — samples several frames via the browser's own video decoder and re-runs the
  image pipeline per frame, comparing scores across the clip.
- **Audio** — real waveform + spectrogram (via a from-scratch STFT), plus spectral
  flatness and pause-timing regularity as honestly-labeled weak/exploratory signals.
- **Cross-check online** — real, live links to Content Credentials Verify, Hive
  Moderation, Illuminarty, AI or Not, WasItAI, FotoForensics, reverse image search, and
  VirusTotal. Nothing is uploaded to any of these unless you click through.
- **Optional live API** — an off-by-default panel (Settings) lets you paste your own free
  Sightengine API credentials for a real, documented, model-based `genai` check, called
  directly from your browser.

Every score is a **composite heuristic indicator (0–100) with an explicit findings
list** — never a bare "97% AI" number. See the in-app Methodology tab for exactly what
each signal means and, importantly, what it *can't* tell you.

### ⚠️ Anomaly Detection (`Anomaly Detection` tab)
Upload **any** file. Real, severity-graded checks:

- File-signature vs. extension mismatch (catches disguised executables/scripts).
- Format-specific structural validation: PNG chunk CRC32 verification, JPEG/PNG/ZIP/PDF
  end-of-file checks, MP4 box-tree walking.
- Detection of data appended after a file's expected end (a classic way to hide payloads).
- Shannon-entropy sliding-window scan with an interactive chart, flagging statistical
  outliers via a robust median-based method.
- The same LSB chi-square steganalysis for images.
- SHA-256 / SHA-1 hashing (native Web Crypto) with a one-click VirusTotal lookup.

### 📊 Dashboard & Session Log
Real counts and a real verdict-breakdown chart built from files you've actually analyzed
this session — empty until you analyze something. Exportable as JSON. Nothing is saved
to disk or any server; the log clears on reload.

## Why you can trust the numbers
Every non-trivial algorithm here (CRC32, Shannon entropy, the FFT, the PNG/JPEG/EXIF/
RIFF/ZIP/PDF/MP4/ID3 parsers, the chi-square p-value function, and the ELA/noise-residual
pixel math) was independently written and unit-tested against known reference values and
real generated test files (a spliced photo, an EXIF-tagged JPEG, a Stable-Diffusion-
metadata PNG, synthetic LSB-embedded images, etc.) during development, then verified again
end-to-end against the actual shipped files. See `Methodology` in the app for the honest
limitations of each technique — this tool is designed to never overclaim.

## File structure
```
index.html            Page shell — all 6 views (Dashboard, AI Media Detection,
                       Anomaly Detection, Session Log, Methodology, Settings)
style.css              Everything visual
js/utils.js             Hashing, entropy, CRC32, chi-square p-values, DOM/toast helpers
js/fft.js               From-scratch FFT + 2D frequency-spectrum utilities
js/signatures.js         Magic-byte format detection + AI/provenance keyword scanning
js/metadata-image.js     JPEG/EXIF + PNG chunk parsers
js/metadata-container.js RIFF/WAV, ZIP, PDF, MP4/MOV, ID3v2 parsers
js/image-forensics.js    ELA, noise-residual, frequency analysis, score combination
js/video-forensics.js    Frame sampling + per-frame pipeline
js/audio-forensics.js    Waveform, spectrogram, spectral stats
js/anomaly-detection.js  File-structure validation, entropy scan, LSB steganalysis
js/online-tools.js       Real third-party tool links + optional Sightengine API call
js/viz.js                Dependency-free canvas heatmaps/charts
js/app.js                Boot sequence, navigation, orchestration, rendering, session log
```

## Running it
Just open `index.html` in any modern browser. No install, no server, no build step.
(Scripts are loaded as classic `<script>` tags — not ES modules — specifically so this
keeps working when opened directly via a `file://` URL.)

## Privacy
No file you analyze is ever sent anywhere by this app, with one narrow exception: if you
explicitly enable the optional Sightengine panel in Settings and click "Run," that one
file is sent directly from your browser to `api.sightengine.com` using your own API
credentials. Everything else — ELA, FFT, entropy, metadata parsing, hashing — happens
locally in JavaScript in your tab.
