// TeckThorn Sentinel — lightweight canvas visualization helpers (no chart library dependency)
window.TT = window.TT || {};

(function (TT) {
  'use strict';

  function heatColor(t) {
    // simple blue -> cyan -> yellow -> red ramp, t in [0,1]
    t = TT.util.clamp(t, 0, 1);
    const stops = [
      [8, 15, 40], [0, 140, 220], [0, 220, 200], [255, 220, 40], [255, 60, 40]
    ];
    const seg = 1 / (stops.length - 1);
    const idx = Math.min(stops.length - 2, Math.floor(t / seg));
    const localT = (t - idx * seg) / seg;
    const a = stops[idx], b = stops[idx + 1];
    return [
      Math.round(a[0] + (b[0] - a[0]) * localT),
      Math.round(a[1] + (b[1] - a[1]) * localT),
      Math.round(a[2] + (b[2] - a[2]) * localT)
    ];
  }

  function renderScalarHeatmap(canvas, plane, size, opts) {
    opts = opts || {};
    canvas.width = size; canvas.height = size;
    const ctx = canvas.getContext('2d');
    const imgData = ctx.createImageData(size, size);
    let min = Infinity, max = -Infinity;
    for (let i = 0; i < plane.length; i++) { if (plane[i] < min) min = plane[i]; if (plane[i] > max) max = plane[i]; }
    const range = max - min || 1;
    for (let i = 0; i < plane.length; i++) {
      const t = (plane[i] - min) / range;
      const [r, g, b] = heatColor(opts.gamma ? Math.pow(t, opts.gamma) : t);
      imgData.data[i * 4] = r; imgData.data[i * 4 + 1] = g; imgData.data[i * 4 + 2] = b; imgData.data[i * 4 + 3] = 255;
    }
    ctx.putImageData(imgData, 0, 0);
  }

  function renderBlockHeatmap(canvas, blockValues, bw, bh, targetW, targetH) {
    canvas.width = targetW; canvas.height = targetH;
    const ctx = canvas.getContext('2d');
    ctx.clearRect(0, 0, targetW, targetH);
    let min = Infinity, max = -Infinity;
    for (let i = 0; i < blockValues.length; i++) { if (blockValues[i] < min) min = blockValues[i]; if (blockValues[i] > max) max = blockValues[i]; }
    const range = max - min || 1;
    const cw = targetW / bw, ch = targetH / bh;
    for (let by = 0; by < bh; by++) for (let bx = 0; bx < bw; bx++) {
      const t = (blockValues[by * bw + bx] - min) / range;
      const [r, g, b] = heatColor(t);
      ctx.fillStyle = `rgb(${r},${g},${b})`;
      ctx.fillRect(bx * cw, by * ch, cw + 0.5, ch + 0.5);
    }
  }

  function drawLineChart(canvas, series, opts) {
    opts = opts || {};
    const ctx = canvas.getContext('2d');
    const W = canvas.width, H = canvas.height;
    ctx.clearRect(0, 0, W, H);
    const pad = { l: 34, r: 10, t: 10, b: 18 };
    const plotW = W - pad.l - pad.r, plotH = H - pad.t - pad.b;
    let allVals = [];
    series.forEach(s => allVals = allVals.concat(s.values));
    let min = opts.min !== undefined ? opts.min : Math.min(...allVals, 0);
    let max = opts.max !== undefined ? opts.max : Math.max(...allVals, 1);
    if (max === min) max = min + 1;
    // gridlines
    ctx.strokeStyle = 'rgba(255,255,255,0.08)'; ctx.lineWidth = 1; ctx.font = '10px monospace';
    ctx.fillStyle = 'rgba(255,255,255,0.4)';
    for (let i = 0; i <= 4; i++) {
      const y = pad.t + plotH * (1 - i / 4);
      ctx.beginPath(); ctx.moveTo(pad.l, y); ctx.lineTo(W - pad.r, y); ctx.stroke();
      const val = min + (max - min) * (i / 4);
      ctx.fillText(val.toFixed(opts.decimals ?? 1), 2, y + 3);
    }
    series.forEach(s => {
      ctx.strokeStyle = s.color || '#00c8ff';
      ctx.lineWidth = 2;
      ctx.beginPath();
      s.values.forEach((v, i) => {
        const x = pad.l + (plotW * i) / (s.values.length - 1 || 1);
        const y = pad.t + plotH * (1 - (v - min) / (max - min));
        if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
      });
      ctx.stroke();
    });
  }

  function drawDonut(canvas, segments) {
    // segments: [{value, color}]
    const ctx = canvas.getContext('2d');
    const W = canvas.width, H = canvas.height;
    ctx.clearRect(0, 0, W, H);
    const total = segments.reduce((a, s) => a + s.value, 0) || 1;
    const cx = W / 2, cy = H / 2, rOuter = Math.min(W, H) / 2 - 4, rInner = rOuter * 0.6;
    let start = -Math.PI / 2;
    segments.forEach(s => {
      const angle = (s.value / total) * Math.PI * 2;
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.arc(cx, cy, rOuter, start, start + angle);
      ctx.closePath();
      ctx.fillStyle = s.color;
      ctx.fill();
      start += angle;
    });
    ctx.globalCompositeOperation = 'destination-out';
    ctx.beginPath(); ctx.arc(cx, cy, rInner, 0, Math.PI * 2); ctx.fill();
    ctx.globalCompositeOperation = 'source-over';
  }

  function drawBar(canvas, values, colors, labels) {
    const ctx = canvas.getContext('2d');
    const W = canvas.width, H = canvas.height;
    ctx.clearRect(0, 0, W, H);
    const max = Math.max(...values, 1);
    const gap = 8, bw = (W - gap * (values.length + 1)) / values.length;
    values.forEach((v, i) => {
      const h = (v / max) * (H - 20);
      const x = gap + i * (bw + gap);
      ctx.fillStyle = colors[i] || '#00c8ff';
      ctx.fillRect(x, H - 16 - h, bw, h);
      ctx.fillStyle = 'rgba(255,255,255,0.6)'; ctx.font = '10px monospace'; ctx.textAlign = 'center';
      ctx.fillText(String(v), x + bw / 2, H - 4);
    });
    ctx.textAlign = 'left';
  }

  TT.viz = { heatColor, renderScalarHeatmap, renderBlockHeatmap, drawLineChart, drawDonut, drawBar };
})(window.TT);
