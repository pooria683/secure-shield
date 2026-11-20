# Secure Shield

A dependency-free HTTP request filter for Node.js applications and a standalone gateway for static websites. It rejects some common suspicious requests before they reach application routes or public files.

## Install and try it

Requires Node.js 22 or newer. Clone or download this repository and run:

```sh
npm ci
npm test
npm start
```

Open `http://localhost:3000` to see the example website. No third-party runtime packages are required.

## Add to an application before building

Copy `src/` and `config/` into your application source, preserving their relative layout. These `.js` files are ES modules; use `"type": "module"` in the containing package or configure your build to treat them as ESM. Include the files in the server build, not in browser bundles.

```js
import { createShield } from './secure-shield/src/index.js';

const shield = createShield({
  allowedOrigins: ['https://app.example.org'],
  loginPaths: ['/login', '/api/session'],
});
app.use(shield); // Express: before routers, URL rewriting, and body parsers
```

With Node HTTP, call `shield(req, res, () => route(req, res))`. Run `npm run example:app` for a minimal working server. Create the middleware once per process, not once per request.

## Deploy alongside a website

Place the project **outside the publicly served directory** and point the gateway at a dedicated public-only folder. If using an existing website folder, keep the gateway code and private files outside the configured public directory. Start the server under an unprivileged account:

```sh
SHIELD_PUBLIC_DIR=/srv/example/public SHIELD_BIND=127.0.0.1 PORT=3000 npm start
```

Put your HTTPS reverse proxy on the same host and route the site's traffic through the gateway. Remove alternate routes that serve the same content without it. Simply uploading these files to static hosting or shared FTP hosting **does not activate protection**; you need a Node.js process and control over HTTP routing. The gateway serves trusted static files only, not PHP, dynamic routes, or a general-purpose reverse proxy. See [deployment guidance](docs/deployment.md).

## Configure

Edit [`config/default.js`](config/default.js) for local defaults, or pass overrides to `createShield`. Invalid or unknown settings fail at startup.

| Setting | Default | Effect |
| --- | --- | --- |
| `inspect` | `true` | Heuristics for traversal, SQL injection, XSS and file inclusion in paths and query strings only. |
| `blockScannerAgents` | `true` | Blocks a small set of self-identifying scanners; user agents aren't proof of identity. |
| `csrf`, `allowedOrigins` | `true`, `[]` | Unsafe methods require an exact configured HTTP(S) `Origin`. An empty list blocks all such requests. |
| `blockFileMedia` | `true` | Rejects multipart and octet-stream requests; not a file scanner or a guarantee that other formats can't carry files. |
| `securityHeaders` | `true` | Adds nosniff, frame denial and no-referrer headers. Set a site-specific CSP separately for apps. |
| `maxTargetBytes`, `maxDeclaredBodyBytes` | `8192`, `65536` | Request-target and declared body-size limits. Transfer-Encoding requests are rejected independently. |
| `rateLimit` | `true` | Enables process-local, fixed-minute counters. |
| `requestsPerMinute`, `globalPerMinute` | `120`, `6000` | Limits per socket peer and per middleware instance, respectively. |
| `loginPaths`, `loginPerMinute` | `['/login']`, `10` | Separate per-peer limit on unsafe methods at configured login paths. Include all route aliases; enforce account-level throttling in the app. |
| `maxTrackedPeers` | `10000` | Caps counter memory; new peers are rejected when full until the next window. |

The filter also rejects malformed targets, unsupported methods, and duplicate framing or security-sensitive headers that reach the middleware. Node may reject malformed HTTP before the middleware sees it.

### Logging and privacy

Blocked and suspicious requests rejected by the filter emit JSON events to stderr with timestamp, action, status, and reason only (at most 100 events per instance per minute). URLs, IP addresses, headers, bodies, cookies and credentials are not logged. Socket peer addresses exist only in rate-limit memory. Supply a synchronous `log(event)` callback as the second argument's `log` property to integrate a collector. Keep logs outside the public directory, restrict access, and set retention and rotation at the collector. Parser/proxy logs are separate: review their redaction settings too.

## Security disclaimer

Secure Shield is an additional layer, **not a guarantee of protection**. Heuristics can miss attacks and block legitimate requests; they do not inspect bodies or validate uploaded files. Origin checks are not authentication. Process-local rate limits do not stop volumetric DDoS and may group users behind NAT or a proxy. Use parameterized SQL, context-aware output escaping, proper CSRF tokens and cookie settings, safe filesystem and upload handling, and application-level authentication and authorization. This project does not replace secure development, updates, backups, firewalls, or professional security auditing. Validate the configuration with your own traffic before production rollout.

Released under the [MIT License](LICENSE).
