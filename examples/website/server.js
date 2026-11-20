import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import { createShield } from '../../src/index.js';
import { createStaticHandler } from '../../src/static.js';

const directory = process.env.SHIELD_PUBLIC_DIR ?? fileURLToPath(new URL('./public/', import.meta.url));
const serve = await createStaticHandler(directory);
const shield = createShield();
const server = createServer({ maxHeaderSize: 8192, headersTimeout: 10000, requestTimeout: 15000, connectionsCheckingInterval: 1000, keepAliveTimeout: 3000 },
  (req, res) => shield(req, res, () => serve(req, res)));
server.maxConnections = 512;
server.setTimeout(15000, socket => socket.destroy());
server.listen(Number(process.env.PORT ?? 3000), process.env.SHIELD_BIND ?? '0.0.0.0');
for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => server.close());
