import { createReadStream } from 'node:fs';
import { realpath, stat } from 'node:fs/promises';
import { extname, resolve } from 'node:path';
import { pipeline } from 'node:stream/promises';

const media = new Map(Object.entries({
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8', '.png': 'image/png', '.jpg': 'image/jpeg',
  '.webp': 'image/webp', '.ico': 'image/x-icon', '.txt': 'text/plain; charset=utf-8',
}));

/** Serve an immutable, trusted, dedicated public directory behind the shield. */
export async function createStaticHandler(directory) {
  const root = await realpath(directory);
  if (!(await stat(root)).isDirectory()) throw new TypeError('Expected a public directory');
  return async function serve(req, res) {
    const finish = status => { res.statusCode = status; res.end(); };
    if (!['GET', 'HEAD'].includes(req.method)) {
      res.setHeader('Allow', 'GET, HEAD');
      return finish(405);
    }
    const path = req.url.split('?')[0];
    // No decoding or aliases: deployment filenames intentionally use a narrow alphabet.
    if (path !== '/' && !/^(?:\/[a-z\d_-][a-z\d_.-]*)+$/i.test(path)) return finish(404);
    const name = path === '/' ? '/index.html' : path;
    const type = media.get(extname(name).toLowerCase());
    if (!type) return finish(404);
    try {
      const file = resolve(root, `.${name}`);
      if (await realpath(file) !== file) return finish(404);
      const info = await stat(file);
      if (!info.isFile()) return finish(404);
      res.setHeader('Content-Type', type);
      res.setHeader('Content-Length', info.size);
      res.setHeader('Content-Security-Policy', "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
      if (req.method === 'HEAD') return res.end();
      await pipeline(createReadStream(file), res);
    } catch (error) {
      if (res.headersSent || res.destroyed) return res.destroy();
      res.removeHeader('Content-Length');
      return finish(['ENOENT', 'ENOTDIR', 'EACCES', 'ELOOP'].includes(error.code) ? 404 : 500);
    }
  };
}
