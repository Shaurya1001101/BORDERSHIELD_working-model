// TeckThorn Sentinel — "different file measures over the internet"
// Real, currently-active third-party tools (verified during development) that a user can
// cross-check a file against, plus an optional bring-your-own-key live API call.
window.TT = window.TT || {};

(function (TT) {
  'use strict';

  const TOOLS = {
    image: [
      { name: 'Content Credentials Verify', url: 'https://contentcredentials.org/verify', desc: 'Official Coalition for Content Provenance & Authenticity (C2PA) tool. Reads signed manifests that declare AI generation, editing history, and the tool/device used. Runs in your browser.' },
      { name: 'C2PA Viewer', url: 'https://c2paviewer.com/', desc: 'Independent drag-and-drop C2PA manifest viewer with raw manifest inspection.' },
      { name: 'Hive Moderation — AI Detector', url: 'https://hivemoderation.com/ai-generated-content', desc: 'Free single-image AI-generation probability check, no account needed.' },
      { name: 'Illuminarty', url: 'https://illuminarty.ai/', desc: 'Free daily scans with a visual heatmap of which regions look AI-generated, and can name the likely generator.' },
      { name: 'AI or Not', url: 'https://www.aiornot.com/', desc: 'Quick no-signup AI-image check.' },
      { name: 'WasItAI', url: 'https://wasitai.com/', desc: 'Free, no-account AI image detector.' },
      { name: 'FotoForensics', url: 'https://fotoforensics.com/', desc: 'Long-standing free Error Level Analysis tool — a good independent second opinion on the ELA result shown above.' },
      { name: 'Google Images (reverse search)', url: 'https://images.google.com/', desc: 'Drag the image in to find earlier/original copies online.' },
      { name: 'TinEye (reverse search)', url: 'https://tineye.com/', desc: 'Reverse image search focused on finding the earliest known appearance of an image.' },
      { name: 'Yandex Images (reverse search)', url: 'https://yandex.com/images/', desc: 'Often finds matches that Google/TinEye miss, especially for images originating outside the US/EU.' },
    ],
    video: [
      { name: 'Content Credentials Verify', url: 'https://contentcredentials.org/verify', desc: 'Checks for a signed C2PA provenance manifest on the video file.' },
      { name: 'Hive Moderation — Deepfake Detector', url: 'https://hivemoderation.com/ai-generated-content', desc: 'Free deepfake/AI-video probability check.' },
      { name: 'Deepware Scanner', url: 'https://deepware.ai/', desc: 'Free deepfake video scanner.' },
    ],
    audio: [
      { name: 'Hive Moderation — AI Audio Detector', url: 'https://hivemoderation.com/ai-generated-content', desc: 'Free AI-generated speech/voice probability check.' },
    ],
    file: [
      { name: 'VirusTotal (hash lookup)', url: 'https://www.virustotal.com/gui/home/upload', urlWithHash: (h) => `https://www.virustotal.com/gui/file/${h}`, desc: 'Look up this file\u2019s hash against 70+ antivirus engines. If the hash link shows "no results", the file simply hasn\u2019t been scanned before — upload it directly for a fresh check.' },
    ]
  };

  function getToolsFor(kind) {
    if (kind === 'image') return TOOLS.image;
    if (kind === 'video') return TOOLS.video;
    if (kind === 'audio') return TOOLS.audio;
    return TOOLS.file;
  }

  function renderToolsPanel(container, kind, context) {
    container.innerHTML = '';
    const tools = getToolsFor(kind).concat(kind !== 'file' ? [] : []);
    const allTools = kind === 'file' ? TOOLS.file : tools;
    const list = TT.util.el('div', { class: 'tool-grid' });
    allTools.forEach(t => {
      let href = t.url;
      if (t.urlWithHash && context && context.sha256) href = t.urlWithHash(context.sha256);
      const card = TT.util.el('div', { class: 'tool-card' }, [
        TT.util.el('div', { class: 'tool-card-name' }, [t.name]),
        TT.util.el('div', { class: 'tool-card-desc' }, [t.desc]),
        TT.util.el('a', { class: 'tool-card-link', href, target: '_blank', rel: 'noopener noreferrer' }, ['Open ↗'])
      ]);
      list.appendChild(card);
    });
    container.appendChild(list);
    if (kind === 'file' && context && context.sha256) {
      const note = TT.util.el('p', { class: 'muted small mt-8' }, [
        'VirusTotal link above is pre-filled with this file\u2019s SHA-256 hash: ',
        TT.util.el('code', {}, [context.sha256])
      ]);
      container.appendChild(note);
    }
  }

  /* ---------------- Optional: live Sightengine API call (documented public API) ---------------- */
  // https://sightengine.com/docs — models=genai. Requires the user's own free/paid api_user + api_secret.
  // Credentials are kept in memory only for this session and sent directly from the browser to
  // api.sightengine.com — never to any other server. This may be blocked by CORS/network policy
  // in some environments; failures are caught and reported clearly rather than silently retried.
  async function callSightengine(file, kind, apiUser, apiSecret) {
    const endpoints = {
      image: 'https://api.sightengine.com/1.0/check.json',
      video: 'https://api.sightengine.com/1.0/video/check-sync.json',
      audio: 'https://api.sightengine.com/1.0/audio/check.json'
    };
    const fieldNames = { image: 'media', video: 'media', audio: 'audio' };
    const endpoint = endpoints[kind];
    if (!endpoint) throw new Error('Sightengine integration only supports image, video, or audio files.');
    const form = new FormData();
    form.append(fieldNames[kind], file);
    form.append('models', 'genai');
    form.append('api_user', apiUser);
    form.append('api_secret', apiSecret);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 25000);
    try {
      const res = await fetch(endpoint, { method: 'POST', body: form, signal: controller.signal });
      clearTimeout(timeout);
      const json = await res.json();
      if (json.status === 'failure' || json.error) {
        throw new Error((json.error && json.error.message) || 'Sightengine returned an error.');
      }
      return json;
    } catch (err) {
      clearTimeout(timeout);
      if (err.name === 'AbortError') throw new Error('Request to Sightengine timed out after 25s.');
      throw new Error('Could not reach Sightengine from this browser (' + err.message + '). This can happen due to CORS restrictions, an offline connection, or invalid credentials. The local heuristic analysis above still applies, and the link-out tools work independently of this.');
    }
  }

  TT.onlineTools = { TOOLS, getToolsFor, renderToolsPanel, callSightengine };
})(window.TT);
