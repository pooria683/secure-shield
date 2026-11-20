import { createServer } from 'node:http';
import { createShield } from '../src/index.js';

const shield = createShield({ allowedOrigins: [process.env.APP_ORIGIN ?? 'http://localhost:3000'] });
createServer({ maxHeaderSize: 8192, headersTimeout: 10000, requestTimeout: 15000 }, (req, res) => {
  shield(req, res, () => {
    if (req.url !== '/' || !['GET', 'HEAD'].includes(req.method)) {
      res.statusCode = 404;
      return res.end();
    }
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ ok: true }));
  });
}).listen(Number(process.env.PORT ?? 3000), '0.0.0.0');
