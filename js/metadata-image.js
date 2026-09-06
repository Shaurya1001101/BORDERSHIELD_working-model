// TeckThorn Sentinel — JPEG/EXIF and PNG metadata parsers
// Parsing logic verified against real generated test fixtures (EXIF Make/Model/Software
// round-trip, PNG tEXt "parameters" chunk round-trip, CRC32 validation) during development.
window.TT = window.TT || {};

(function (TT) {
  'use strict';
  const { crc32 } = TT.util;

  /* ================= PNG ================= */
  function parsePNGChunks(bytes) {
    const sig = [137, 80, 78, 71, 13, 10, 26, 10];
    for (let i = 0; i < 8; i++) if (bytes[i] !== sig[i]) return null;
    const chunks = [];
    let off = 8;
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    while (off + 8 <= bytes.length) {
      const len = dv.getUint32(off);
      const type = String.fromCharCode(bytes[off + 4], bytes[off + 5], bytes[off + 6], bytes[off + 7]);
      const dataOffset = off + 8;
      if (dataOffset + len + 4 > bytes.length) break;
      const storedCrc = dv.getUint32(dataOffset + len);
      const computedCrc = crc32(bytes, off + 4, dataOffset + len);
      chunks.push({ type, length: len, offset: off, dataOffset, crcOk: storedCrc === computedCrc });
      off = dataOffset + len + 4;
      if (type === 'IEND') break;
    }
    return { chunks, endOffset: off, trailingBytes: bytes.length - off, valid: chunks.length > 0 && chunks[0].type === 'IHDR' };
  }

  function readPNGTextChunks(bytes, pngInfo) {
    const out = [];
    for (const c of pngInfo.chunks) {
      if (c.type === 'tEXt') {
        const slice = bytes.subarray(c.dataOffset, c.dataOffset + c.length);
        const nul = slice.indexOf(0);
        if (nul < 0) continue;
        out.push({ type: 'tEXt', key: TT.util.bytesToLatin1(slice, 0, nul), value: TT.util.bytesToLatin1(slice, nul + 1) });
      } else if (c.type === 'iTXt') {
        const slice = bytes.subarray(c.dataOffset, c.dataOffset + c.length);
        let p = slice.indexOf(0);
        if (p < 0) continue;
        const key = TT.util.bytesToLatin1(slice, 0, p);
        p += 1;
        const compFlag = slice[p]; p += 2;
        let nul2 = slice.indexOf(0, p); if (nul2 < 0) continue; p = nul2 + 1;
        nul2 = slice.indexOf(0, p); if (nul2 < 0) continue; p = nul2 + 1;
        let value = '';
        try { value = new TextDecoder('utf-8').decode(slice.subarray(p)); } catch (e) { value = TT.util.bytesToLatin1(slice, p); }
        out.push({ type: 'iTXt', key, value, compressed: !!compFlag });
      } else if (c.type === 'zTXt') {
        const slice = bytes.subarray(c.dataOffset, c.dataOffset + c.length);
        const nul = slice.indexOf(0);
        if (nul < 0) continue;
        out.push({ type: 'zTXt', key: TT.util.bytesToLatin1(slice, 0, nul), value: '(compressed — not decoded)', compressed: true });
      }
    }
    return out;
  }

  /* ================= JPEG / EXIF ================= */
  function parseJPEGSegments(bytes) {
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    if (bytes.length < 4 || dv.getUint16(0) !== 0xFFD8) return null;
    const segments = [];
    let off = 2;
    while (off < bytes.length - 1) {
      if (bytes[off] !== 0xFF) { off++; continue; }
      let marker = bytes[off + 1];
      while (marker === 0xFF && off + 1 < bytes.length) { off++; marker = bytes[off + 1]; }
      if (marker === 0xD8 || marker === 0xD9 || (marker >= 0xD0 && marker <= 0xD7) || marker === 0x01) {
        segments.push({ marker, offset: off, length: 0, dataOffset: off + 2 });
        off += 2; continue;
      }
      if (marker === 0xDA) { segments.push({ marker, offset: off, dataOffset: off + 2 }); break; }
      if (off + 4 > bytes.length) break;
      const len = dv.getUint16(off + 2);
      segments.push({ marker, offset: off, length: len, dataOffset: off + 4 });
      off += 2 + len;
    }
    let eoiOffset = -1;
    for (let i = bytes.length - 2; i >= 2; i--) {
      if (bytes[i] === 0xFF && bytes[i + 1] === 0xD9) { eoiOffset = i; break; }
    }
    return { segments, eoiOffset, trailingAfterEOI: eoiOffset >= 0 ? bytes.length - (eoiOffset + 2) : null };
  }

  const EXIF_TAG_NAMES = {
    0x010F: 'Make', 0x0110: 'Model', 0x0131: 'Software', 0x0132: 'DateTime',
    0x8769: 'ExifIFDPointer', 0x8825: 'GPSInfoIFDPointer', 0x0112: 'Orientation',
    0x9003: 'DateTimeOriginal', 0x9004: 'DateTimeDigitized', 0xA434: 'LensModel',
    0x829A: 'ExposureTime', 0x829D: 'FNumber', 0x8827: 'ISOSpeedRatings',
    0x0129: 'PageName', 0x9286: 'UserComment', 0xA002: 'PixelXDimension', 0xA003: 'PixelYDimension',
    0xA005: 'InteroperabilityIFDPointer', 0x013B: 'Artist', 0x8298: 'Copyright'
  };
  const TYPE_SIZES = { 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8 };

  function parseEXIFFromAPP1(bytes, seg) {
    const start = seg.dataOffset;
    if (start + 6 > bytes.length) return null;
    const header = TT.util.bytesToLatin1(bytes, start, start + 6);
    if (header !== 'Exif\0\0') return null;
    const tiffStart = start + 6;
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const byteOrder = String.fromCharCode(bytes[tiffStart], bytes[tiffStart + 1]);
    const little = byteOrder === 'II';
    const get16 = (o) => dv.getUint16(o, little);
    const get32 = (o) => dv.getUint32(o, little);
    if (get16(tiffStart + 2) !== 42) return null;
    const ifd0Offset = get32(tiffStart + 4);

    function readIFD(offset) {
      if (offset <= 0 || tiffStart + offset + 2 > bytes.length) return { entries: [], nextIFDOffset: 0 };
      const count = get16(tiffStart + offset);
      const entries = [];
      let p = tiffStart + offset + 2;
      for (let i = 0; i < count; i++) {
        if (p + 12 > bytes.length) break;
        const tag = get16(p), type = get16(p + 2), num = get32(p + 4);
        const size = (TYPE_SIZES[type] || 1) * num;
        let valueOffset = p + 8;
        if (size > 4) valueOffset = tiffStart + get32(p + 8);
        let value = null;
        try {
          if (type === 2) value = TT.util.bytesToLatin1(bytes, valueOffset, valueOffset + num).replace(/\0+$/, '');
          else if (type === 3) value = dv.getUint16(valueOffset, little);
          else if (type === 4) value = get32(valueOffset);
          else if (type === 5) { const n = get32(valueOffset), d = get32(valueOffset + 4); value = d !== 0 ? n / d : 0; }
        } catch (e) { value = null; }
        entries.push({ tag, name: EXIF_TAG_NAMES[tag] || ('0x' + tag.toString(16)), type, count: num, value });
        p += 12;
      }
      const nextIFDOffset = p + 4 <= bytes.length ? get32(p) : 0;
      return { entries, nextIFDOffset };
    }

    const ifd0 = readIFD(ifd0Offset);
    const result = { byteOrder, ifd0: ifd0.entries, exif: [], hasGPS: false };
    const exifPtr = ifd0.entries.find(e => e.tag === 0x8769);
    if (exifPtr) result.exif = readIFD(exifPtr.value).entries;
    result.hasGPS = ifd0.entries.some(e => e.tag === 0x8825);
    return result;
  }

  function extractXMP(bytes, segments) {
    const XMP_SIG = 'http://ns.adobe.com/xap/1.0/\0';
    for (const seg of segments) {
      if (seg.marker !== 0xE1 || !seg.length) continue;
      const header = TT.util.bytesToLatin1(bytes, seg.dataOffset, Math.min(bytes.length, seg.dataOffset + XMP_SIG.length));
      if (header === XMP_SIG) {
        const xmpStart = seg.dataOffset + XMP_SIG.length;
        const xmpEnd = seg.dataOffset + seg.length - 2;
        return TT.util.bytesToLatin1(bytes, xmpStart, xmpEnd);
      }
    }
    return null;
  }

  function analyzeJPEG(bytes) {
    const jpegInfo = parseJPEGSegments(bytes);
    if (!jpegInfo) return null;
    const app1s = jpegInfo.segments.filter(s => s.marker === 0xE1);
    let exif = null;
    for (const s of app1s) { const r = parseEXIFFromAPP1(bytes, s); if (r) { exif = r; break; } }
    const xmp = extractXMP(bytes, jpegInfo.segments);
    const app11 = jpegInfo.segments.filter(s => s.marker === 0xEB); // C2PA/JUMBF typically here
    return { jpegInfo, exif, xmp, hasAPP11: app11.length > 0, app11Count: app11.length };
  }

  function analyzePNG(bytes) {
    const pngInfo = parsePNGChunks(bytes);
    if (!pngInfo) return null;
    const texts = readPNGTextChunks(bytes, pngInfo);
    const hasEXIFChunk = pngInfo.chunks.some(c => c.type === 'eXIf');
    const hasC2PAChunk = pngInfo.chunks.some(c => c.type === 'caBX');
    return { pngInfo, texts, hasEXIFChunk, hasC2PAChunk };
  }

  TT.metaImage = { parsePNGChunks, readPNGTextChunks, parseJPEGSegments, parseEXIFFromAPP1, extractXMP, analyzeJPEG, analyzePNG };
})(window.TT);
