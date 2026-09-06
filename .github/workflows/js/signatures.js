// TeckThorn Sentinel — file signature (magic byte) detection + text signature scanning
window.TT = window.TT || {};

(function (TT) {
  'use strict';

  const MAGIC_SIGNATURES = [
    { format: 'JPEG image', ext: ['jpg', 'jpeg'], bytes: [0xFF, 0xD8, 0xFF], kind: 'image' },
    { format: 'PNG image', ext: ['png'], bytes: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A], kind: 'image' },
    { format: 'GIF image', ext: ['gif'], bytes: [0x47, 0x49, 0x46, 0x38], kind: 'image' },
    { format: 'BMP image', ext: ['bmp'], bytes: [0x42, 0x4D], kind: 'image' },
    { format: 'TIFF image (little-endian)', ext: ['tif', 'tiff'], bytes: [0x49, 0x49, 0x2A, 0x00], kind: 'image' },
    { format: 'TIFF image (big-endian)', ext: ['tif', 'tiff'], bytes: [0x4D, 0x4D, 0x00, 0x2A], kind: 'image' },
    { format: 'PDF document', ext: ['pdf'], bytes: [0x25, 0x50, 0x44, 0x46], kind: 'doc' },
    { format: 'ZIP-based container (zip/docx/xlsx/pptx/apk/jar)', ext: ['zip', 'docx', 'xlsx', 'pptx', 'apk', 'jar'], bytes: [0x50, 0x4B, 0x03, 0x04], kind: 'archive' },
    { format: 'ZIP archive (empty)', ext: ['zip'], bytes: [0x50, 0x4B, 0x05, 0x06], kind: 'archive' },
    { format: 'RAR archive', ext: ['rar'], bytes: [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07], kind: 'archive' },
    { format: '7-Zip archive', ext: ['7z'], bytes: [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C], kind: 'archive' },
    { format: 'GZIP archive', ext: ['gz'], bytes: [0x1F, 0x8B], kind: 'archive' },
    { format: 'RIFF container (WAV/WebP/AVI)', ext: ['wav', 'webp', 'avi'], bytes: [0x52, 0x49, 0x46, 0x46], kind: 'riff' },
    { format: 'MP3 audio (ID3 tag)', ext: ['mp3'], bytes: [0x49, 0x44, 0x33], kind: 'audio' },
    { format: 'MP3 audio (frame sync)', ext: ['mp3'], bytes: [0xFF, 0xFB], kind: 'audio' },
    { format: 'FLAC audio', ext: ['flac'], bytes: [0x66, 0x4C, 0x61, 0x43], kind: 'audio' },
    { format: 'OGG container', ext: ['ogg', 'ogv', 'oga'], bytes: [0x4F, 0x67, 0x67, 0x53], kind: 'audio' },
    { format: 'Windows executable (EXE/DLL)', ext: ['exe', 'dll'], bytes: [0x4D, 0x5A], kind: 'executable' },
    { format: 'ELF executable (Linux)', ext: [''], bytes: [0x7F, 0x45, 0x4C, 0x46], kind: 'executable' },
    { format: 'Mach-O executable (32-bit)', ext: [''], bytes: [0xFE, 0xED, 0xFA, 0xCE], kind: 'executable' },
    { format: 'Mach-O executable (64-bit)', ext: [''], bytes: [0xFE, 0xED, 0xFA, 0xCF], kind: 'executable' },
  ];

  function detectFormat(bytes) {
    if (bytes.length > 12 && bytes[4] === 0x66 && bytes[5] === 0x74 && bytes[6] === 0x79 && bytes[7] === 0x70) {
      const brand = String.fromCharCode(bytes[8], bytes[9], bytes[10], bytes[11]).trim();
      return { format: 'MP4/MOV video (ISO base media, brand=' + brand + ')', ext: ['mp4', 'mov', 'm4a', 'm4v'], kind: 'video' };
    }
    if (bytes.length > 3 && bytes[0] === 0x23 && bytes[1] === 0x21) {
      return { format: 'Script (shebang #!)', ext: [''], kind: 'script' };
    }
    for (const sig of MAGIC_SIGNATURES) {
      if (bytes.length < sig.bytes.length) continue;
      let ok = true;
      for (let i = 0; i < sig.bytes.length; i++) if (bytes[i] !== sig.bytes[i]) { ok = false; break; }
      if (ok) {
        // Disambiguate RIFF subtype
        if (sig.format.startsWith('RIFF') && bytes.length >= 12) {
          const sub = String.fromCharCode(bytes[8], bytes[9], bytes[10], bytes[11]);
          if (sub === 'WAVE') return { format: 'WAV audio (RIFF/WAVE)', ext: ['wav'], kind: 'audio' };
          if (sub === 'WEBP') return { format: 'WebP image (RIFF/WEBP)', ext: ['webp'], kind: 'image' };
          if (sub === 'AVI ') return { format: 'AVI video (RIFF/AVI)', ext: ['avi'], kind: 'video' };
        }
        return sig;
      }
    }
    return { format: 'Unknown / unrecognized binary format', ext: [], kind: 'unknown' };
  }

  function extensionMatches(filename, detected) {
    if (!detected || !detected.ext || !detected.ext.length) return null; // unknown, can't judge
    const dot = filename.lastIndexOf('.');
    if (dot < 0) return { hasExt: false, mismatch: false, claimedExt: '' };
    const claimed = filename.slice(dot + 1).toLowerCase();
    if (detected.ext.includes('')) return { hasExt: true, mismatch: false, claimedExt: claimed };
    return { hasExt: true, mismatch: !detected.ext.includes(claimed), claimedExt: claimed };
  }

  // Keywords that, if found as raw bytes/text anywhere in a file, hint at AI generation tools,
  // content-provenance manifests, or common generation-parameter dumps. This is a broad heuristic
  // string scan — not a full parser — and is presented to the user as such.
  const AI_SIGNATURES = [
    'stable diffusion', 'dreambooth', 'midjourney', 'dall-e', 'dalle', 'openai',
    'adobe firefly', 'firefly', 'leonardo.ai', 'novelai', 'comfyui', 'automatic1111',
    'invokeai', 'runwayml', 'runway gen', 'sora', 'pika labs', 'synthesia', 'elevenlabs',
    'resemble.ai', 'murf.ai', 'descript overdub',
    'c2pa', 'contentauth', 'jumbf', 'digitalsourcetype', 'trainedalgorithmicmedia',
    'compositewithtrainedalgorithmicmedia', 'negative prompt:', 'cfg scale', 'sampler:',
    'nightcafe', 'playground ai', 'ideogram', 'flux.1', 'flux-2', 'seedream', 'imagen', 'gemini',
    'bing image creator', 'copilot designer', 'recraft', 'krea', 'wan2.', 'kling ai',
    'luma ai', 'haiper', 'pixverse', 'higgsfield', 'gpt-image'
  ];

  // Backend image-processing-library fingerprints. These are NOT AI-specific by themselves —
  // plenty of ordinary websites resize photos with GD/ImageMagick too — but real camera/phone
  // JPEGs are essentially never encoded by these libraries. Seen combined with an absence of
  // any camera EXIF data, this is a meaningful (if not conclusive) clue that an image passed
  // through a server-side generation/rendering pipeline rather than a camera.
  const PIPELINE_SIGNATURES = [
    'gd-jpeg', 'ijg jpeg', 'imagemagick', 'graphicsmagick', 'libvips', 'ffmpeg',
    'cairo', 'skia', 'wand-py', 'sharp/libvips'
  ];

  function signatureScan(bytes, maxBytes) {
    const cap = Math.min(bytes.length, maxBytes || 12 * 1024 * 1024);
    const text = TT.util.bytesToLatin1(bytes, 0, cap).toLowerCase();
    const found = [];
    for (const sig of AI_SIGNATURES) {
      const idx = text.indexOf(sig);
      if (idx >= 0) {
        const ctxStart = Math.max(0, idx - 24);
        const ctx = text.substring(ctxStart, idx + sig.length + 24).replace(/[\x00-\x1f]/g, ' ');
        found.push({ signature: sig, index: idx, context: ctx.trim(), category: 'ai' });
      }
    }
    return found;
  }

  function pipelineSignatureScan(bytes, maxBytes) {
    const cap = Math.min(bytes.length, maxBytes || 12 * 1024 * 1024);
    const text = TT.util.bytesToLatin1(bytes, 0, cap).toLowerCase();
    const found = [];
    for (const sig of PIPELINE_SIGNATURES) {
      const idx = text.indexOf(sig);
      if (idx >= 0) {
        const ctxStart = Math.max(0, idx - 24);
        const ctx = text.substring(ctxStart, idx + sig.length + 24).replace(/[\x00-\x1f]/g, ' ');
        found.push({ signature: sig, index: idx, context: ctx.trim(), category: 'pipeline' });
      }
    }
    return found;
  }

  TT.signatures = { MAGIC_SIGNATURES, detectFormat, extensionMatches, AI_SIGNATURES, PIPELINE_SIGNATURES, signatureScan, pipelineSignatureScan };
})(window.TT);
