// TeckThorn Sentinel — shared utilities
// Classic script (no ES modules) so the app works when opened directly via file://
window.TT = window.TT || {};

(function (TT) {
  'use strict';

  /* ---------------- CRC32 (verified against standard test vector) ---------------- */
  const CRC_TABLE = (() => {
    const t = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
      t[n] = c >>> 0;
    }
    return t;
  })();
  function crc32(bytes, start, end) {
    start = start || 0; end = end === undefined ? bytes.length : end;
    let c = 0xFFFFFFFF;
    for (let i = start; i < end; i++) c = CRC_TABLE[(c ^ bytes[i]) & 0xFF] ^ (c >>> 8);
    return (c ^ 0xFFFFFFFF) >>> 0;
  }

  /* ---------------- Shannon entropy ---------------- */
  function shannonEntropy(bytes, start, end) {
    start = start || 0; end = end === undefined ? bytes.length : end;
    const len = end - start;
    if (len <= 0) return 0;
    const freq = new Uint32Array(256);
    for (let i = start; i < end; i++) freq[bytes[i]]++;
    let ent = 0;
    for (let i = 0; i < 256; i++) {
      if (freq[i] === 0) continue;
      const p = freq[i] / len;
      ent -= p * Math.log2(p);
    }
    return ent;
  }

  /* ---------------- Regularized incomplete gamma (for chi-square p-values) ---------------- */
  function gammln(x) {
    const g = 7;
    const c = [0.99999999999980993, 676.5203681218851, -1259.1392167224028,
      771.32342877765313, -176.61502916214059, 12.507343278686905,
      -0.13857109526572012, 9.9843695780195716e-6, 1.5056327351493116e-7];
    if (x < 0.5) return Math.log(Math.PI / Math.sin(Math.PI * x)) - gammln(1 - x);
    x -= 1;
    let a = c[0];
    const t = x + g + 0.5;
    for (let i = 1; i < g + 2; i++) a += c[i] / (x + i);
    return 0.5 * Math.log(2 * Math.PI) + (x + 0.5) * Math.log(t) - t + Math.log(a);
  }
  function gammaSeries(a, x) {
    if (x <= 0) return 0;
    let sum = 1 / a, del = sum, ap = a;
    for (let n = 1; n <= 200; n++) {
      ap += 1; del *= x / ap; sum += del;
      if (Math.abs(del) < Math.abs(sum) * 1e-14) break;
    }
    return sum * Math.exp(-x + a * Math.log(x) - gammln(a));
  }
  function gammaCF(a, x) {
    const FPMIN = 1e-300;
    let b = x + 1 - a, c = 1 / FPMIN, d = 1 / b, h = d;
    for (let i = 1; i <= 200; i++) {
      const an = -i * (i - a);
      b += 2; d = an * d + b; if (Math.abs(d) < FPMIN) d = FPMIN;
      c = b + an / c; if (Math.abs(c) < FPMIN) c = FPMIN;
      d = 1 / d;
      const del = d * c; h *= del;
      if (Math.abs(del - 1) < 1e-14) break;
    }
    return Math.exp(-x + a * Math.log(x) - gammln(a)) * h;
  }
  function gammq(a, x) {
    if (x < 0 || a <= 0) return NaN;
    if (x === 0) return 1;
    if (x < a + 1) return 1 - gammaSeries(a, x);
    return gammaCF(a, x);
  }
  function chiSquarePValue(chi2stat, k) { return gammq(k / 2, chi2stat / 2); }

  /* ---------------- Hashing (native Web Crypto — always correct) ---------------- */
  async function sha256Hex(arrayBuffer) {
    const buf = await crypto.subtle.digest('SHA-256', arrayBuffer);
    return bufToHex(buf);
  }
  async function sha1Hex(arrayBuffer) {
    const buf = await crypto.subtle.digest('SHA-1', arrayBuffer);
    return bufToHex(buf);
  }
  function bufToHex(buf) {
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /* ---------------- Byte/text helpers ---------------- */
  function bytesToLatin1(bytes, start, end) {
    start = start || 0; end = end === undefined ? bytes.length : end;
    let s = '';
    const CHUNK = 8192;
    for (let i = start; i < end; i += CHUNK) {
      const sub = bytes.subarray(i, Math.min(end, i + CHUNK));
      s += String.fromCharCode.apply(null, sub);
    }
    return s;
  }
  function readFileAsArrayBuffer(file) {
    return new Promise((resolve, reject) => {
      const fr = new FileReader();
      fr.onload = () => resolve(fr.result);
      fr.onerror = () => reject(fr.error);
      fr.readAsArrayBuffer(file);
    });
  }
  function formatBytes(n) {
    if (n < 1024) return n + ' B';
    const units = ['KB', 'MB', 'GB', 'TB'];
    let i = -1;
    do { n /= 1024; i++; } while (n >= 1024 && i < units.length - 1);
    return n.toFixed(n < 10 ? 2 : 1) + ' ' + units[i];
  }
  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }
  function clamp(v, lo, hi) { return v < lo ? lo : (v > hi ? hi : v); }
  function uid() { return Math.random().toString(36).slice(2, 10) + Date.now().toString(36); }

  /* ---------------- Misc DOM helpers ---------------- */
  function el(tag, attrs, children) {
    const e = document.createElement(tag);
    if (attrs) for (const k in attrs) {
      if (k === 'class') e.className = attrs[k];
      else if (k === 'html') e.innerHTML = attrs[k];
      else if (k.startsWith('on') && typeof attrs[k] === 'function') e.addEventListener(k.slice(2), attrs[k]);
      else e.setAttribute(k, attrs[k]);
    }
    (children || []).forEach(c => e.appendChild(typeof c === 'string' ? document.createTextNode(c) : c));
    return e;
  }
  let toastTimer = null;
  function toast(msg, kind) {
    const t = document.getElementById('toast');
    if (!t) return;
    t.textContent = msg;
    t.className = 'toast show' + (kind ? ' ' + kind : '');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { t.className = 'toast'; }, 3200);
  }
  function downloadBlob(filename, content, mime) {
    const blob = content instanceof Blob ? content : new Blob([content], { type: mime || 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 4000);
  }

  TT.util = {
    crc32, shannonEntropy, chiSquarePValue,
    sha256Hex, sha1Hex, bufToHex,
    bytesToLatin1, readFileAsArrayBuffer, formatBytes, escapeHtml, clamp, uid,
    el, toast, downloadBlob
  };
})(window.TT);
