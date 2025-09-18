// Import Express.js
const express = require('express');

// Create an Express app
const app = express();

// Middleware to parse JSON bodies
app.use(express.json());

// Trust proxy headers if running behind a reverse proxy (e.g., Heroku, Nginx)
app.set('trust proxy', true);

// Helpers to determine request origin and client IP
const getDomainOrigin = (req) => {
  const origin = req.get('origin');
  if (origin) return origin;

  const referer = req.get('referer');
  if (referer) {
    try {
      return new URL(referer).origin;
    } catch {
      // ignore invalid referer
    }
  }

  const proto = req.get('x-forwarded-proto') || req.protocol;
  const host = req.get('x-forwarded-host') || req.get('host');
  if (host) return `${proto}://${host}`;

  return 'unknown';
};

const getClientIp = (req) =>
  (req.headers['x-forwarded-for']?.split(',')[0]?.trim()) || req.ip;

// Optional: request logger showing domain origin and IP for all requests
app.use((req, _res, next) => {
  const origin = getDomainOrigin(req);
  const ip = getClientIp(req);
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl} from ${origin} (ip: ${ip})`);
  next();
});

// Set port and verify_token
const port = process.env.PORT || 3000;
const verifyToken = process.env.VERIFY_TOKEN;

// Route for GET requests (webhook verification)
app.get('/', (req, res) => {
  const { 'hub.mode': mode, 'hub.challenge': challenge, 'hub.verify_token': token } = req.query;

  const origin = getDomainOrigin(req);
  const ip = getClientIp(req);
  console.log(`Webhook verification attempt from ${origin} (ip: ${ip})`);

  if (mode === 'subscribe' && token === verifyToken) {
    console.log('WEBHOOK VERIFIED');
    res.status(200).send(challenge);
  } else {
    res.status(403).end();
  }
});

// Route for POST requests (webhook events)
app.post('/', (req, res) => {
  const timestamp = new Date().toISOString().replace('T', ' ').slice(0, 19);
  const origin = getDomainOrigin(req);
  const ip = getClientIp(req);

  console.log(`\n\nWebhook received ${timestamp} from ${origin} (ip: ${ip})\n`);
  console.log(JSON.stringify(req.body, null, 2));
  res.status(200).end();
});

// Start the server
app.listen(port, () => {
  console.log(`\nListening on port ${port}\n`);
});
