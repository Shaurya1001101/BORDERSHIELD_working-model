// TeckThorn Sentinel — audio forensics
// Client-side heuristics for audio are inherently weaker than for images/video (there is
// no widely-agreed, easily-computed spectral "tell" for synthetic speech the way there is
// for GAN checkerboarding). We compute honest, real statistics (spectral flatness, silence
// regularity, noise floor) and present them as weak/exploratory signals, pointing users to
// specialised online detectors for anything that matters.
window.TT = window.TT || {};

(function (TT) {
  'use strict';

  async function decodeAudio(file) {
    const arrayBuffer = await TT.util.readFileAsArrayBuffer(file);
    const AC = window.AudioContext || window.webkitAudioContext;
    const ctx = new AC();
    try {
      const audioBuffer = await ctx.decodeAudioData(arrayBuffer.slice(0));
      return { audioBuffer, ctx };
    } finally {
      // leave ctx open for potential reuse by caller; caller should close() when done
    }
  }

  function getMonoSamples(audioBuffer) {
    const ch0 = audioBuffer.getChannelData(0);
    if (audioBuffer.numberOfChannels === 1) return ch0.slice();
    const ch1 = audioBuffer.getChannelData(1);
    const mono = new Float32Array(ch0.length);
    for (let i = 0; i < ch0.length; i++) mono[i] = (ch0[i] + ch1[i]) / 2;
    return mono;
  }

  function computeWaveformPeaks(samples, buckets) {
    const peaks = new Float32Array(buckets * 2); // min,max per bucket
    const bucketSize = Math.max(1, Math.floor(samples.length / buckets));
    for (let b = 0; b < buckets; b++) {
      let mn = 1, mx = -1;
      const start = b * bucketSize, end = Math.min(samples.length, start + bucketSize);
      for (let i = start; i < end; i++) { const v = samples[i]; if (v < mn) mn = v; if (v > mx) mx = v; }
      if (end <= start) { mn = 0; mx = 0; }
      peaks[b * 2] = mn; peaks[b * 2 + 1] = mx;
    }
    return peaks;
  }

  function computeSpectrogram(samples, sampleRate, windowSize, hopSize) {
    windowSize = windowSize || 1024; hopSize = hopSize || 512;
    const frames = TT.fft.stft(samples, windowSize, hopSize);
    return { frames, windowSize, hopSize, sampleRate, freqBins: windowSize / 2 };
  }

  /* Spectral flatness (Wiener entropy): geometric mean / arithmetic mean of the power spectrum.
     Near 1.0 = noise-like/flat spectrum; near 0 = tonal/peaky spectrum. Averaged across frames. */
  function spectralFlatness(spectrogramFrames) {
    let sumFlat = 0, n = 0;
    for (const frame of spectrogramFrames) {
      let logSum = 0, sum = 0, count = 0;
      for (let i = 1; i < frame.length; i++) { // skip DC bin
        const p = frame[i] * frame[i] + 1e-12;
        logSum += Math.log(p); sum += p; count++;
      }
      if (count === 0) continue;
      const gm = Math.exp(logSum / count);
      const am = sum / count;
      sumFlat += am > 0 ? gm / am : 0;
      n++;
    }
    return n ? sumFlat / n : 0;
  }

  /* Detects unusually regular silence gaps (TTS systems often pad with very uniform silence). */
  function silenceRegularity(samples, sampleRate, thresholdDb) {
    thresholdDb = thresholdDb === undefined ? -45 : thresholdDb;
    const thresholdAmp = Math.pow(10, thresholdDb / 20);
    const frameSize = Math.round(sampleRate * 0.02); // 20ms frames
    const gaps = [];
    let inSilence = false, gapStart = 0;
    for (let i = 0; i < samples.length; i += frameSize) {
      let sumSq = 0, count = 0;
      for (let j = i; j < Math.min(samples.length, i + frameSize); j++) { sumSq += samples[j] * samples[j]; count++; }
      const rms = Math.sqrt(sumSq / (count || 1));
      const silent = rms < thresholdAmp;
      if (silent && !inSilence) { inSilence = true; gapStart = i; }
      else if (!silent && inSilence) { inSilence = false; gaps.push((i - gapStart) / sampleRate); }
    }
    if (!gaps.length) return { gapCount: 0, meanGap: 0, stdGap: 0, coeffVar: 0 };
    const mean = gaps.reduce((a, b) => a + b, 0) / gaps.length;
    const std = Math.sqrt(gaps.reduce((a, b) => a + (b - mean) ** 2, 0) / gaps.length);
    return { gapCount: gaps.length, meanGap: mean, stdGap: std, coeffVar: mean > 0 ? std / mean : 0 };
  }

  function combineAudioVerdict(signals) {
    const findings = [];
    let score = 0;
    if (signals.aiTags && signals.aiTags.length) {
      score += 55;
      findings.push({ level: 'strong', text: `Metadata/byte scan references a known voice-synthesis or generative-audio tool (${signals.aiTags.slice(0, 3).map(t => t.signature).join(', ')}).` });
    }
    if (signals.flatness !== undefined) {
      if (signals.flatness < 0.15) { score += 8; findings.push({ level: 'weak', text: `Spectral flatness is quite low (${signals.flatness.toFixed(3)}), meaning the spectrum is fairly tonal/clean. Natural room recordings usually carry more broadband noise; very clean spectra are common in both studio recordings and synthetic speech, so this is a weak signal.` }); }
      else findings.push({ level: 'none', text: `Spectral flatness (${signals.flatness.toFixed(3)}) is within a broadly normal range for recorded audio.` });
    }
    if (signals.silence && signals.silence.gapCount >= 4) {
      if (signals.silence.coeffVar < 0.15) { score += 10; findings.push({ level: 'weak', text: `Silence gaps between speech segments are unusually uniform in length (coefficient of variation ${signals.silence.coeffVar.toFixed(2)}). Some text-to-speech systems produce very regular pauses; natural speech pausing is typically more variable. Not conclusive alone.` }); }
      else findings.push({ level: 'none', text: 'Pause/silence timing looks naturally variable.' });
    }
    score = TT.util.clamp(score, 0, 100);
    let verdict, verdictClass;
    if (score >= 50) { verdict = 'Some indicators of synthetic/AI-generated audio'; verdictClass = 'amber'; }
    else if (score >= 15) { verdict = 'Weak/exploratory signals only — inconclusive'; verdictClass = 'blue'; }
    else { verdict = 'No strong indicators found in these limited heuristics'; verdictClass = 'green'; }
    findings.push({ level: 'none', text: 'Audio deepfake detection is genuinely hard from simple heuristics alone. For anything that matters, cross-check with a dedicated audio-forensics tool (see the online tools panel).' });
    return { score, verdict, verdictClass, findings };
  }

  TT.audioForensics = { decodeAudio, getMonoSamples, computeWaveformPeaks, computeSpectrogram, spectralFlatness, silenceRegularity, combineAudioVerdict };
})(window.TT);
