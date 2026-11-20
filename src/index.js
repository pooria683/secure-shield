import defaults from '../config/default.js';

const safeMethods = new Set(['GET', 'HEAD', 'OPTIONS']);
const methods = new Set([...safeMethods, 'POST', 'PUT', 'PATCH', 'DELETE']);
const sensitiveHeaders = new Set(['host', 'origin', 'content-length', 'content-type', 'transfer-encoding']);
const signatures = [
  /(?:^|[\/\\])\.\.(?:[\/\\]|$)/,
  /(?:<\s*\/?\s*(?:script|iframe|svg)\b|javascript\s*:)/i,
  /\bunion\s+(?:all\s+)?select\b/i,
  /(?:php|file|data|expect|phar):\/\//i,
];

function decode(value) {
  // Inspect one additional encoding layer without treating decoded literal % as malformed.
  const once = decodeURIComponent(value);
  return once.replace(/(?:%[\da-f]{2})+/gi, part => {
    try { return decodeURIComponent(part); } catch { return part; }
  });
}

function configuration(options) {
  for (const key of Object.keys(options)) {
    if (!Object.hasOwn(defaults, key)) throw new TypeError(`Unknown setting: ${key}`);
  }
  const config = { ...defaults, ...options };
  for (const [key, value] of Object.entries(config)) {
    const expected = defaults[key];
    if (Array.isArray(expected)) {
      if (!Array.isArray(value) || value.some(item => typeof item !== 'string')) throw new TypeError(`Invalid ${key}`);
      config[key] = [...value];
    } else if (typeof value !== typeof expected || (typeof expected === 'number' && (!Number.isSafeInteger(value) || value < 1))) {
      throw new TypeError(`Invalid ${key}`);
    }
  }
  for (const origin of config.allowedOrigins) {
    const url = new URL(origin);
    if (!['http:', 'https:'].includes(url.protocol) || url.origin !== origin) throw new TypeError('Expected an exact HTTP(S) origin');
  }
  for (const path of config.loginPaths) {
    if (!/^\/[a-z0-9/_-]*$/i.test(path)) throw new TypeError('Invalid login path');
  }
  return config;
}

/** Node HTTP / Express-style middleware. Install before routing and body parsing. */
export function createShield(options = {}, { log = event => console.warn(JSON.stringify(event)) } = {}) {
  const c = configuration(options);
  const origins = new Set(c.allowedOrigins);
  const loginKey = path => path.toLowerCase().replace(/\/+$/, '') || '/';
  const login = new Set(c.loginPaths.map(loginKey));
  const peers = new Map();
  let window = -1;
  let total = 0;
  let reported = 0;

  return function shield(req, res, next) {
    const minute = Math.floor(process.uptime() / 60);
    if (minute !== window) {
      window = minute;
      total = reported = 0;
      peers.clear();
    }
    const deny = (status, reason) => {
      // Bound log amplification; never record peer data, headers, URLs or bodies.
      if (++reported <= 100) {
        try { log({ time: new Date().toISOString(), action: 'blocked', status, reason }); } catch { /* logging must not bypass enforcement */ }
      }
      res.statusCode = status;
      res.setHeader('Connection', 'close');
      res.setHeader('Cache-Control', 'no-store');
      res.setHeader('Content-Type', 'text/plain; charset=utf-8');
      if (status === 429) res.setHeader('Retry-After', String(Math.ceil(60 - process.uptime() % 60)));
      res.end('Request rejected');
    };
    if (c.securityHeaders) {
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('X-Frame-Options', 'DENY');
      res.setHeader('Referrer-Policy', 'no-referrer');
    }
    if (c.rateLimit && ++total > c.globalPerMinute) return deny(429, 'global-limit');
    let bucket;
    if (c.rateLimit) {
      // Deliberately ignore all client-supplied forwarding headers.
      const peer = req.socket.remoteAddress ?? 'unknown';
      bucket = peers.get(peer);
      if (!bucket) {
        if (peers.size >= c.maxTrackedPeers) return deny(429, 'peer-capacity');
        bucket = { requests: 0, logins: 0 };
        peers.set(peer, bucket);
      }
      if (++bucket.requests > c.requestsPerMinute) return deny(429, 'peer-limit');
    }
    const target = req.url ?? '';
    if (Buffer.byteLength(target) > c.maxTargetBytes) return deny(414, 'target-size');
    if (!methods.has(req.method)) return deny(405, 'method');
    if (!target.startsWith('/') || target.startsWith('//') || /[#\\\s]/.test(target)) return deny(400, 'target-form');
    const separator = target.indexOf('?');
    let path, query;
    try {
      path = decode(separator < 0 ? target : target.slice(0, separator));
      query = separator < 0 ? '' : decode(target.slice(separator + 1).replace(/\+/g, ' '));
    } catch { return deny(400, 'target-encoding'); }
    if (/[\x00-\x1f\x7f]/.test(path + query)) return deny(400, 'target-controls');
    if (bucket && !safeMethods.has(req.method) && login.has(loginKey(path)) && ++bucket.logins > c.loginPerMinute) return deny(429, 'login-limit');
    const seen = new Set();
    for (let i = 0; i < req.rawHeaders.length; i += 2) {
      const name = req.rawHeaders[i].toLowerCase();
      if (!sensitiveHeaders.has(name)) continue;
      if (seen.has(name)) return deny(400, 'duplicate-header');
      seen.add(name);
    }
    if (req.headers['transfer-encoding']) return deny(400, 'streaming-request');
    if (Number(req.headers['content-length']) > c.maxDeclaredBodyBytes) return deny(413, 'body-size');
    const contentType = (req.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
    if (c.blockFileMedia && (contentType.startsWith('multipart/') || contentType === 'application/octet-stream')) return deny(415, 'file-media');
    if (c.csrf && !safeMethods.has(req.method) && !origins.has(req.headers.origin)) return deny(403, 'origin');
    if (c.blockScannerAgents && /\b(?:sqlmap|nikto|masscan|nuclei)\b/i.test(req.headers['user-agent'] ?? '')) return deny(403, 'scanner-agent');
    if (c.inspect && ([path, ...query.split(/[&=]/)].some(value => signatures.some(pattern => pattern.test(value))) || /(?:^|[&?])(?:file|include|template|page)=https?:\/\//i.test(query))) return deny(403, 'target-signature');
    return next();
  };
}
