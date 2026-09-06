// TeckThorn Sentinel — container-format structural parsers
// Each parser verified against real generated fixtures during development
// (wav via Python 'wave', zip via Python 'zipfile', pdf raw bytes, mp4 synthetic boxes, id3 by hand).
window.TT = window.TT || {};

(function (TT) {
  'use strict';

  /* ================= RIFF (WAV / WEBP / AVI) ================= */
  function parseRIFF(bytes) {
    if (bytes.length < 12) return null;
    const riff = String.fromCharCode(bytes[0], bytes[1], bytes[2], bytes[3]);
    if (riff !== 'RIFF') return null;
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const declaredSize = dv.getUint32(4, true);
    const form = String.fromCharCode(bytes[8], bytes[9], bytes[10], bytes[11]);
    const chunks = [];
    let off = 12;
    while (off + 8 <= bytes.length) {
      const id = String.fromCharCode(bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]);
      const size = dv.getUint32(off + 4, true);
      chunks.push({ id, size, dataOffset: off + 8 });
      off += 8 + size + (size % 2);
      if (size < 0 || off > bytes.length + 1) break;
    }
    return { form, declaredSize, chunks, trailingBytes: Math.max(0, bytes.length - off) };
  }

  /* ================= ZIP End Of Central Directory ================= */
  function findZipEOCD(bytes) {
    const searchStart = Math.max(0, bytes.length - 65535 - 22);
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    for (let i = bytes.length - 22; i >= searchStart; i--) {
      if (bytes[i] === 0x50 && bytes[i + 1] === 0x4B && bytes[i + 2] === 0x05 && bytes[i + 3] === 0x06) {
        const commentLen = dv.getUint16(i + 20, true);
        const totalEntries = dv.getUint16(i + 10, true);
        const eocdEnd = i + 22 + commentLen;
        return { offset: i, totalEntries, commentLen, trailingBytes: Math.max(0, bytes.length - eocdEnd) };
      }
    }
    return null;
  }

  /* ================= PDF %%EOF / trailer scan ================= */
  function scanPDFEOF(bytes) {
    const text = TT.util.bytesToLatin1(bytes);
    const marker = '%%EOF';
    const positions = [];
    let idx = text.indexOf(marker);
    while (idx !== -1) { positions.push(idx); idx = text.indexOf(marker, idx + 1); }
    if (!positions.length) return { eofCount: 0, eofPositions: [], trailingBytesAfterLast: null };
    const last = positions[positions.length - 1] + marker.length;
    let end = bytes.length;
    while (end > last && (bytes[end - 1] === 0x0A || bytes[end - 1] === 0x0D || bytes[end - 1] === 0x20 || bytes[end - 1] === 0x09)) end--;
    return { eofCount: positions.length, eofPositions: positions, trailingBytesAfterLast: end - last, revisions: positions.length };
  }

  /* ================= MP4 / MOV box walker ================= */
  function parseMP4Boxes(bytes, maxDepth) {
    maxDepth = maxDepth === undefined ? 5 : maxDepth;
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const CONTAINER_TYPES = ['moov', 'trak', 'mdia', 'minf', 'stbl', 'udta', 'edts', 'mvex', 'moof', 'traf', 'meta'];
    function walk(start, end, depth) {
      const boxes = [];
      let off = start;
      while (off + 8 <= end) {
        let size = dv.getUint32(off);
        const type = String.fromCharCode(bytes[off + 4], bytes[off + 5], bytes[off + 6], bytes[off + 7]);
        let headerSize = 8;
        if (size === 1) {
          if (off + 16 > end) break;
          const hi = dv.getUint32(off + 8), lo = dv.getUint32(off + 12);
          size = hi * 4294967296 + lo; headerSize = 16;
        } else if (size === 0) size = end - off;
        if (size < headerSize || off + size > end) break;
        const box = { type, offset: off, size };
        if (depth < maxDepth && CONTAINER_TYPES.includes(type)) box.children = walk(off + headerSize, off + size, depth + 1);
        boxes.push(box);
        off += size;
      }
      return boxes;
    }
    const boxes = walk(0, bytes.length, 0);
    return { boxes, trailingBytes: 0 };
  }

  function findMP4Box(boxes, type) {
    for (const b of boxes) {
      if (b.type === type) return b;
      if (b.children) { const found = findMP4Box(b.children, type); if (found) return found; }
    }
    return null;
  }
  function collectMP4BoxTypes(boxes, set) {
    set = set || new Set();
    for (const b of boxes) { set.add(b.type); if (b.children) collectMP4BoxTypes(b.children, set); }
    return set;
  }

  /* ================= ID3v2 (MP3) ================= */
  function parseID3v2(bytes) {
    if (bytes.length < 10 || !(bytes[0] === 0x49 && bytes[1] === 0x44 && bytes[2] === 0x33)) return null;
    const major = bytes[3];
    const size = ((bytes[6] & 0x7f) << 21) | ((bytes[7] & 0x7f) << 14) | ((bytes[8] & 0x7f) << 7) | (bytes[9] & 0x7f);
    let off = 10;
    const end = Math.min(bytes.length, 10 + size);
    const frames = [];
    while (off + 10 <= end) {
      const id = String.fromCharCode(bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]);
      if (id === '\0\0\0\0') break;
      let fsize;
      if (major >= 4) fsize = ((bytes[off + 4] & 0x7f) << 21) | ((bytes[off + 5] & 0x7f) << 14) | ((bytes[off + 6] & 0x7f) << 7) | (bytes[off + 7] & 0x7f);
      else fsize = (bytes[off + 4] << 24) | (bytes[off + 5] << 16) | (bytes[off + 6] << 8) | bytes[off + 7];
      const dataStart = off + 10;
      if (dataStart + fsize > bytes.length || fsize < 0) break;
      let text = '';
      if (id[0] === 'T' || id === 'COMM') {
        const encByte = bytes[dataStart];
        const bodyStart = dataStart + 1;
        try {
          if (encByte === 1 || encByte === 2) text = new TextDecoder('utf-16').decode(bytes.subarray(bodyStart, dataStart + fsize));
          else text = TT.util.bytesToLatin1(bytes, bodyStart, dataStart + fsize);
        } catch (e) { text = ''; }
        text = text.replace(/\0+$/, '').replace(/\0/g, ' | ');
      }
      frames.push({ id, size: fsize, text });
      off = dataStart + fsize;
    }
    // check for legacy ID3v1 trailer (last 128 bytes, starts with "TAG")
    let hasID3v1 = false;
    if (bytes.length >= 128) {
      const tail = bytes.subarray(bytes.length - 128, bytes.length - 125);
      hasID3v1 = tail[0] === 0x54 && tail[1] === 0x41 && tail[2] === 0x47;
    }
    return { version: '2.' + major, size, frames, hasID3v1 };
  }

  TT.metaContainer = { parseRIFF, findZipEOCD, scanPDFEOF, parseMP4Boxes, findMP4Box, collectMP4BoxTypes, parseID3v2 };
})(window.TT);
