// TeckThorn Sentinel — video forensics
// Samples N evenly-spaced frames using the browser's native <video> decoder + canvas,
// then reuses the same image-forensics pipeline (ELA/noise/frequency) per frame.
window.TT = window.TT || {};

(function (TT) {
  'use strict';

  function loadVideo(file) {
    return new Promise((resolve, reject) => {
      const url = URL.createObjectURL(file);
      const video = document.createElement('video');
      video.preload = 'metadata';
      video.muted = true;
      video.src = url;
      video.onloadedmetadata = () => resolve({ video, url });
      video.onerror = () => { URL.revokeObjectURL(url); reject(new Error('Could not decode video — codec may be unsupported by this browser.')); };
    });
  }

  function seekTo(video, t) {
    return new Promise((resolve, reject) => {
      const onSeeked = () => { video.removeEventListener('seeked', onSeeked); resolve(); };
      video.addEventListener('seeked', onSeeked);
      try { video.currentTime = t; } catch (e) { reject(e); }
    });
  }

  async function extractFrames(file, count) {
    count = count || 5;
    const { video, url } = await loadVideo(file);
    const duration = video.duration && isFinite(video.duration) ? video.duration : 0;
    const width = video.videoWidth, height = video.videoHeight;
    const frames = [];
    try {
      if (duration > 0 && width && height) {
        for (let i = 0; i < count; i++) {
          // avoid the very first/last frame which are sometimes black/duplicated
          const t = (duration * (i + 0.5)) / count;
          await seekTo(video, Math.min(duration - 0.01, Math.max(0, t)));
          const canvas = document.createElement('canvas');
          canvas.width = width; canvas.height = height;
          const ctx = canvas.getContext('2d');
          ctx.drawImage(video, 0, 0, width, height);
          frames.push({ timestamp: t, canvas, ctx, width, height, imageData: ctx.getImageData(0, 0, width, height) });
        }
      }
    } finally {
      URL.revokeObjectURL(url);
    }
    return { frames, duration, width, height };
  }

  async function recompressCanvasJPEG(canvas, quality) {
    return new Promise((resolve) => {
      const dataUrl = canvas.toDataURL('image/jpeg', quality);
      const img = new Image();
      img.onload = () => {
        const c2 = document.createElement('canvas');
        c2.width = img.width; c2.height = img.height;
        const ctx2 = c2.getContext('2d');
        ctx2.drawImage(img, 0, 0);
        resolve(ctx2.getImageData(0, 0, img.width, img.height));
      };
      img.src = dataUrl;
    });
  }

  async function analyzeFrames(frames, onProgress) {
    const IF = TT.imageForensics;
    const perFrame = [];
    for (let i = 0; i < frames.length; i++) {
      const f = frames[i];
      const recomp = await recompressCanvasJPEG(f.canvas, 0.9);
      const ela = IF.computeELA(f.imageData, recomp, 12);
      const noise = IF.computeNoiseResidual(f.imageData, 2);
      const freq = IF.computeFrequencyAnalysis(f.imageData);
      const verdict = IF.combineImageVerdict({ ela, noise, freq, aiTags: [], c2paHint: false });
      perFrame.push({ timestamp: f.timestamp, ela, noise, freq, verdict, thumbCanvas: f.canvas });
      if (onProgress) onProgress(i + 1, frames.length);
    }
    const avgScore = perFrame.reduce((a, b) => a + b.verdict.score, 0) / (perFrame.length || 1);
    const maxScore = Math.max(0, ...perFrame.map(p => p.verdict.score));
    const scoreSpread = maxScore - Math.min(...perFrame.map(p => p.verdict.score));
    return { perFrame, avgScore, maxScore, scoreSpread };
  }

  TT.videoForensics = { loadVideo, extractFrames, analyzeFrames, recompressCanvasJPEG };
})(window.TT);
