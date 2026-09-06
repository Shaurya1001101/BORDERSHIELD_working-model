// TeckThorn Sentinel — general file anomaly & integrity scanner
// Works on ANY uploaded file (not just media). Severity-graded, explainable findings.
window.TT = window.TT || {};

(function (TT) {
  'use strict';
  const { util, signatures, metaImage, metaContainer } = TT;

  function severityRank(s) { return { info: 0, low: 1, medium: 2, high: 3, critical: 4 }[s] ?? 0; }

  /* ---------------- Entropy sliding-window scan ---------------- */
  function entropyScan(bytes, windowSize) {
    windowSize = windowSize || Math.max(256, Math.floor(bytes.length / 400));
    const values = [];
    for (let i = 0; i < bytes.length; i += windowSize) {
      const end = Math.min(bytes.length, i + windowSize);
      values.push(util.shannonEntropy(bytes, i, end));
    }
    // robust outlier detection via median absolute deviation
    const sorted = values.slice().sort((a, b) => a - b);
    const median = sorted[Math.floor(sorted.length / 2)];
    const absDevs = values.map(v => Math.abs(v - median)).sort((a, b) => a - b);
    const mad = absDevs[Math.floor(absDevs.length / 2)] || 0.01;
    const outliers = [];
    values.forEach((v, i) => {
      const z = (v - median) / (1.4826 * mad || 0.01);
      if (z > 4 && v > 7.2) outliers.push({ index: i, entropy: v, z });
    });
    return { values, windowSize, median, mad, outliers };
  }

  /* ---------------- File structure validators ---------------- */
  function validateStructure(bytes, detected) {
    const findings = [];
    if (!detected) return findings;
    const fmt = detected.format;
    if (fmt.startsWith('PNG')) {
      const info = metaImage.parsePNGChunks(bytes);
      if (info) {
        const badCrc = info.chunks.filter(c => !c.crcOk);
        if (badCrc.length) findings.push({ severity: 'high', title: 'PNG chunk CRC mismatch', detail: `${badCrc.length} chunk(s) failed CRC32 validation (${badCrc.map(c => c.type).join(', ')}). This can indicate corruption or deliberate tampering of chunk data.` });
        if (info.chunks[0] && info.chunks[0].type !== 'IHDR') findings.push({ severity: 'medium', title: 'PNG structure irregular', detail: 'First chunk is not IHDR as required by the PNG spec.' });
        if (info.trailingBytes > 0) findings.push({ severity: 'high', title: 'Data appended after PNG end (IEND)', detail: `${info.trailingBytes} extra byte(s) found after the IEND chunk. Legitimate PNGs end at IEND — trailing data can be a hidden/appended payload.` });
      }
    } else if (fmt === 'JPEG image') {
      const info = metaImage.parseJPEGSegments(bytes);
      if (info) {
        if (info.trailingAfterEOI && info.trailingAfterEOI > 0) findings.push({ severity: 'high', title: 'Data appended after JPEG end (EOI)', detail: `${info.trailingAfterEOI} extra byte(s) found after the End-Of-Image marker (FFD9). This is a common way to hide extra data inside an image file.` });
      }
    } else if (fmt.includes('ZIP-based')) {
      const eocd = metaContainer.findZipEOCD(bytes);
      if (eocd) {
        if (eocd.trailingBytes > 0) findings.push({ severity: 'medium', title: 'Data appended after ZIP end-of-directory', detail: `${eocd.trailingBytes} extra byte(s) found after the ZIP End-Of-Central-Directory record. May be benign (e.g. a code-signing block) or may hide extra content.` });
      } else {
        findings.push({ severity: 'medium', title: 'ZIP End-Of-Central-Directory not found', detail: 'Could not locate a valid ZIP directory footer — the archive may be corrupted or truncated.' });
      }
    } else if (fmt === 'PDF document') {
      const eof = metaContainer.scanPDFEOF(bytes);
      if (eof.eofCount === 0) findings.push({ severity: 'medium', title: 'No %%EOF marker found', detail: 'PDF is missing its expected end-of-file marker — file may be corrupted or truncated.' });
      else {
        if (eof.trailingBytesAfterLast > 8) findings.push({ severity: 'high', title: 'Data appended after final %%EOF', detail: `${eof.trailingBytesAfterLast} byte(s) found after the last %%EOF marker — possible hidden/appended payload.` });
        if (eof.eofCount > 1) findings.push({ severity: 'info', title: `${eof.eofCount} %%EOF markers found (incremental updates)`, detail: 'This PDF has been incrementally saved multiple times. Earlier revisions may still be recoverable from within the file — check revision history if provenance matters.' });
      }
    } else if (fmt.startsWith('WAV')) {
      const info = metaContainer.parseRIFF(bytes);
      if (info) {
        if (info.trailingBytes > 0) findings.push({ severity: 'low', title: 'Extra bytes after RIFF data', detail: `${info.trailingBytes} byte(s) beyond the declared RIFF structure.` });
      }
    } else if (fmt.includes('MP4/MOV')) {
      const info = metaContainer.parseMP4Boxes(bytes);
      const types = metaContainer.collectMP4BoxTypes(info.boxes);
      if (!types.has('moov')) findings.push({ severity: 'medium', title: 'No moov box found', detail: 'Could not find the movie metadata box (moov) — file may be corrupted, truncated, or a raw stream fragment.' });
      if (!types.has('mdat')) findings.push({ severity: 'low', title: 'No mdat box found at top level', detail: 'Media data box (mdat) not found at the top level (may be fragmented/streamed format).' });
    }
    return findings;
  }

  /* ---------------- Extension / magic-byte mismatch & disguised executables ---------------- */
  function checkExtensionAndExecutable(filename, detected) {
    const findings = [];
    const match = signatures.extensionMatches(filename, detected);
    if (match && match.hasExt && match.mismatch) {
      const severity = detected.kind === 'executable' || detected.kind === 'script' ? 'critical' : 'medium';
      findings.push({ severity, title: 'File extension does not match actual file content', detail: `File is named ".${match.claimedExt}" but its content signature identifies it as: ${detected.format}. ${detected.kind === 'executable' || detected.kind === 'script' ? 'This combination (executable/script content masquerading as another file type) is a classic malware-disguise technique.' : 'This can be an innocent rename, but is worth double-checking the source.'}` });
    } else if (detected && (detected.kind === 'executable' || detected.kind === 'script')) {
      findings.push({ severity: 'high', title: 'Executable/script content detected', detail: `Content signature identifies this as: ${detected.format}. Treat with caution if this was not the expected file type.` });
    }
    return findings;
  }

  /* ---------------- LSB chi-square steganalysis (images) ---------------- */
  function lsbChiSquareTest(samples) {
    const freq = new Uint32Array(256);
    for (const s of samples) freq[s]++;
    let chi2 = 0, k = 0;
    for (let pair = 0; pair < 128; pair++) {
      const i0 = pair * 2, i1 = pair * 2 + 1;
      const total = freq[i0] + freq[i1];
      if (total < 4) continue;
      const expected = total / 2;
      chi2 += Math.pow(freq[i0] - expected, 2) / expected;
      k++;
    }
    return { chi2, degreesOfFreedom: k };
  }

  function windowedLSBTest(channelSamples, windows) {
    windows = windows || 10;
    const chunkSize = Math.floor(channelSamples.length / windows);
    const results = [];
    for (let w = 0; w < windows; w++) {
      const chunk = channelSamples.slice(w * chunkSize, (w + 1) * chunkSize);
      if (chunk.length < 500) continue;
      const { chi2, degreesOfFreedom } = lsbChiSquareTest(chunk);
      const p = util.chiSquarePValue(chi2, degreesOfFreedom);
      results.push({ window: w, p, chi2, dof: degreesOfFreedom });
    }
    return results;
  }

  function analyzeLSBSteganography(imgData, sampleCap) {
    sampleCap = sampleCap || 200000;
    const { data } = imgData;
    const totalPixels = data.length / 4;
    const step = Math.max(1, Math.floor(totalPixels / sampleCap));
    const r = [], g = [], b = [];
    for (let p = 0; p < totalPixels; p += step) {
      const i = p * 4;
      r.push(data[i]); g.push(data[i + 1]); b.push(data[i + 2]);
    }
    const windowedR = windowedLSBTest(r, 12);
    const windowedG = windowedLSBTest(g, 12);
    const windowedB = windowedLSBTest(b, 12);
    const maxP = Math.max(
      ...windowedR.map(w => w.p), ...windowedG.map(w => w.p), ...windowedB.map(w => w.p)
    );
    const highPWindows = [...windowedR, ...windowedG, ...windowedB].filter(w => w.p > 0.95).length;
    return { windowedR, windowedG, windowedB, maxP, highPWindows, sampledPixels: r.length };
  }

  /* ---------------- Combine into a graded report ---------------- */
  function combineAnomalyReport(structureFindings, extFindings, entropyResult, lsbResult, signatureMatches) {
    const findings = structureFindings.concat(extFindings);

    if (entropyResult && entropyResult.outliers.length) {
      findings.push({
        severity: entropyResult.outliers.length > 3 ? 'medium' : 'low',
        title: `${entropyResult.outliers.length} high-entropy region(s) detected`,
        detail: `Localized region(s) of the file show entropy far above the file's own median (window size ${entropyResult.windowSize} bytes). This can indicate embedded encrypted or compressed data, or steganographic payloads. Not unusual in already-compressed formats like JPEG/MP4/ZIP.`
      });
    }
    if (lsbResult && lsbResult.highPWindows > 0) {
      findings.push({
        severity: lsbResult.highPWindows >= 3 ? 'medium' : 'low',
        title: `Statistical LSB test flagged ${lsbResult.highPWindows} region(s)`,
        detail: `A chi-square "pairs of values" test on the least-significant bits found region(s) statistically consistent with LSB-embedded data (p > 0.95). This is a classic but imperfect steganalysis heuristic — false positives happen on smooth/flat image regions. Treat as a lead, not proof.`
      });
    }
    if (signatureMatches && signatureMatches.length) {
      findings.push({
        severity: 'info',
        title: `${signatureMatches.length} known keyword(s) found in file bytes`,
        detail: 'See the Metadata & Signatures panel for details.'
      });
    }
    if (!findings.length) {
      findings.push({ severity: 'info', title: 'No anomalies found', detail: 'File structure, entropy distribution, and byte-level signatures all look unremarkable for this format.' });
    }
    findings.sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
    const worst = findings[0].severity;
    return { findings, worstSeverity: worst };
  }

  TT.anomaly = { entropyScan, validateStructure, checkExtensionAndExecutable, lsbChiSquareTest, windowedLSBTest, analyzeLSBSteganography, combineAnomalyReport, severityRank };
})(window.TT);
