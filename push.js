// push.js
// Sends push notifications via Firebase Cloud Messaging's HTTP v1 API.
//
// This uses ONLY Node's built-in `crypto` and `https` modules — no
// firebase-admin package required — so it fits the project's
// zero-dependency philosophy.
//
// SETUP REQUIRED:
// google-services.json (already in /config) is the ANDROID CLIENT config —
// it identifies the app to Firebase but cannot authenticate the server.
// To actually send pushes you also need the ADMIN service account key:
//   Firebase Console -> Project Settings -> Service Accounts
//   -> "Generate new private key" -> downloads a JSON file.
// Save that file as: config/service-account.json  (never commit this —
// it grants server-level access to your Firebase project).
//
// Until service-account.json exists, sendPush() safely no-ops and logs
// a one-time warning, so the rest of the app works fine without it.

const fs = require('fs');
const path = require('path');
const https = require('https');
const crypto = require('crypto');

const SERVICE_ACCOUNT_PATH = path.join(__dirname, 'config', 'service-account.json');
const GOOGLE_SERVICES_PATH = path.join(__dirname, 'config', 'google-services.json');

let serviceAccount = null;
let projectId = null;
let warnedMissingServiceAccount = false;

try {
  serviceAccount = JSON.parse(fs.readFileSync(SERVICE_ACCOUNT_PATH, 'utf8'));
} catch (e) {
  // Not present yet — that's fine, see note above.
}

try {
  const googleServices = JSON.parse(fs.readFileSync(GOOGLE_SERVICES_PATH, 'utf8'));
  projectId = googleServices.project_info.project_id;
} catch (e) {
  // No client config found either; pushes simply stay disabled.
}

let cachedToken = null; // { accessToken, expiresAt }

function base64url(input) {
  return Buffer.from(input)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

// Exchange the service account's private key for a short-lived OAuth2
// access token (standard Google "JWT bearer" flow), signed locally with
// Node's crypto — no external auth library needed.
function getAccessToken() {
  return new Promise((resolve, reject) => {
    if (!serviceAccount) return reject(new Error('no service account configured'));

    if (cachedToken && cachedToken.expiresAt > Date.now() + 30_000) {
      return resolve(cachedToken.accessToken);
    }

    const nowSec = Math.floor(Date.now() / 1000);
    const header = { alg: 'RS256', typ: 'JWT' };
    const claimSet = {
      iss: serviceAccount.client_email,
      scope: 'https://www.googleapis.com/auth/firebase.messaging',
      aud: 'https://oauth2.googleapis.com/token',
      iat: nowSec,
      exp: nowSec + 3600,
    };
    const unsigned = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(claimSet))}`;
    const signer = crypto.createSign('RSA-SHA256');
    signer.update(unsigned);
    const signature = signer.sign(serviceAccount.private_key).toString('base64')
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const assertion = `${unsigned}.${signature}`;

    const postData = `grant_type=${encodeURIComponent('urn:ietf:params:oauth:grant-type:jwt-bearer')}&assertion=${assertion}`;

    const req = https.request(
      {
        hostname: 'oauth2.googleapis.com',
        path: '/token',
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': Buffer.byteLength(postData),
        },
      },
      (res) => {
        let data = '';
        res.on('data', (c) => (data += c));
        res.on('end', () => {
          try {
            const parsed = JSON.parse(data);
            if (!parsed.access_token) return reject(new Error(data));
            cachedToken = {
              accessToken: parsed.access_token,
              expiresAt: Date.now() + (parsed.expires_in || 3600) * 1000,
            };
            resolve(parsed.access_token);
          } catch (e) {
            reject(e);
          }
        });
      }
    );
    req.on('error', reject);
    req.write(postData);
    req.end();
  });
}

// Send a data-only push (title/body are NOT included here on purpose —
// since messages are end-to-end encrypted, the server doesn't know the
// plaintext, so it can't put it in a notification preview either. The
// app should show a generic "New message" alert and decrypt once opened.)
async function sendPush(deviceToken, data = {}) {
  if (!serviceAccount || !projectId) {
    if (!warnedMissingServiceAccount) {
      console.warn(
        '[push] Skipping push notification: config/service-account.json not found. ' +
        'Add your Firebase Admin service account key to enable push. See push.js for instructions.'
      );
      warnedMissingServiceAccount = true;
    }
    return { skipped: true };
  }
  if (!deviceToken) return { skipped: true };

  const accessToken = await getAccessToken();

  const message = {
    message: {
      token: deviceToken,
      data: Object.fromEntries(Object.entries(data).map(([k, v]) => [k, String(v)])),
      notification: {
        title: 'SecureChat',
        body: 'You have a new message',
      },
    },
  };

  return new Promise((resolve, reject) => {
    const body = JSON.stringify(message);
    const req = https.request(
      {
        hostname: 'fcm.googleapis.com',
        path: `/v1/projects/${projectId}/messages:send`,
        method: 'POST',
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(body),
        },
      },
      (res) => {
        let data = '';
        res.on('data', (c) => (data += c));
        res.on('end', () => resolve({ status: res.statusCode, body: data }));
      }
    );
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

module.exports = { sendPush };
