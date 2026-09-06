// TeckThorn Sentinel — FFT / frequency-domain utilities
// Iterative radix-2 Cooley-Tukey. Verified against a naive DFT (max error < 1e-9)
// and against known impulse/DC test signals during development.
window.TT = window.TT || {};

(function (TT) {
  'use strict';

  function fft1d(re, im) {
    const n = re.length;
    if (n !== im.length) throw new Error('re/im length mismatch');
    if ((n & (n - 1)) !== 0) throw new Error('FFT length must be a power of 2, got ' + n);
    for (let i = 1, j = 0; i < n; i++) {
      let bit = n >> 1;
      for (; j & bit; bit >>= 1) j ^= bit;
      j ^= bit;
      if (i < j) {
        let tmp = re[i]; re[i] = re[j]; re[j] = tmp;
        tmp = im[i]; im[i] = im[j]; im[j] = tmp;
      }
    }
    for (let len = 2; len <= n; len <<= 1) {
      const ang = (-2 * Math.PI) / len;
      const wRe = Math.cos(ang), wIm = Math.sin(ang);
      for (let i = 0; i < n; i += len) {
        let curRe = 1, curIm = 0;
        const half = len / 2;
        for (let k = 0; k < half; k++) {
          const uRe = re[i + k], uIm = im[i + k];
          const vRe = re[i + k + half] * curRe - im[i + k + half] * curIm;
          const vIm = re[i + k + half] * curIm + im[i + k + half] * curRe;
          re[i + k] = uRe + vRe; im[i + k] = uIm + vIm;
          re[i + k + half] = uRe - vRe; im[i + k + half] = uIm - vIm;
          const nextRe = curRe * wRe - curIm * wIm;
          const nextIm = curRe * wIm + curIm * wRe;
          curRe = nextRe; curIm = nextIm;
        }
      }
    }
    return { re, im };
  }

  function nextPow2(n) { let p = 1; while (p < n) p <<= 1; return p; }

  /** 2D magnitude spectrum of a square, power-of-two grayscale plane (row-major Float64Array). */
  function fft2dMagnitude(gray, size) {
    const re = new Float64Array(size * size);
    const im = new Float64Array(size * size);
    re.set(gray);
    for (let y = 0; y < size; y++) {
      const rRow = re.subarray(y * size, y * size + size);
      const iRow = im.subarray(y * size, y * size + size);
      fft1d(rRow, iRow);
    }
    const colRe = new Float64Array(size), colIm = new Float64Array(size);
    for (let x = 0; x < size; x++) {
      for (let y = 0; y < size; y++) { colRe[y] = re[y * size + x]; colIm[y] = im[y * size + x]; }
      fft1d(colRe, colIm);
      for (let y = 0; y < size; y++) { re[y * size + x] = colRe[y]; im[y * size + x] = colIm[y]; }
    }
    const mag = new Float64Array(size * size);
    for (let i = 0; i < size * size; i++) mag[i] = Math.hypot(re[i], im[i]);
    return mag;
  }

  function fftShift2D(mag, size) {
    const out = new Float64Array(size * size);
    const half = size / 2;
    for (let y = 0; y < size; y++) {
      for (let x = 0; x < size; x++) {
        const sy = (y + half) % size, sx = (x + half) % size;
        out[sy * size + sx] = mag[y * size + x];
      }
    }
    return out;
  }

  function radialAverage(shiftedMag, size) {
    const cx = size / 2, cy = size / 2;
    const maxR = Math.floor(size / 2);
    const sums = new Float64Array(maxR + 1);
    const counts = new Uint32Array(maxR + 1);
    for (let y = 0; y < size; y++) {
      for (let x = 0; x < size; x++) {
        const dx = x - cx, dy = y - cy;
        const r = Math.round(Math.sqrt(dx * dx + dy * dy));
        if (r > maxR) continue;
        sums[r] += shiftedMag[y * size + x];
        counts[r]++;
      }
    }
    const avg = new Float64Array(maxR + 1);
    for (let r = 0; r <= maxR; r++) avg[r] = counts[r] ? sums[r] / counts[r] : 0;
    return avg;
  }

  /** Short-time FFT for 1D signals (audio), Hann-windowed, returns array of magnitude spectra frames. */
  function stft(signal, windowSize, hopSize) {
    const win = new Float64Array(windowSize);
    for (let i = 0; i < windowSize; i++) win[i] = 0.5 - 0.5 * Math.cos((2 * Math.PI * i) / (windowSize - 1));
    const frames = [];
    for (let start = 0; start + windowSize <= signal.length; start += hopSize) {
      const re = new Float64Array(windowSize), im = new Float64Array(windowSize);
      for (let i = 0; i < windowSize; i++) re[i] = signal[start + i] * win[i];
      fft1d(re, im);
      const half = windowSize / 2;
      const mag = new Float64Array(half);
      for (let i = 0; i < half; i++) mag[i] = Math.hypot(re[i], im[i]);
      frames.push(mag);
    }
    return frames;
  }

  TT.fft = { fft1d, fft2dMagnitude, fftShift2D, radialAverage, stft, nextPow2 };
})(window.TT);
