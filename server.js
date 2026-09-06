// server.js
// Zero-dependency Node.js backend for an end-to-end-encrypted chat app.
//
// IMPORTANT SECURITY NOTE:
// The server never sees plaintext. It only ever stores/forwards:
//   - RSA PUBLIC keys (safe to share)
//   - AES-GCM ciphertext + IV (unreadable without the private key)
//   - an AES key that has itself been RSA-encrypted for a specific recipient
// If this database were stolen, none of the message/image/story content
// could be read without the individual users' private keys, which never
// leave their browsers.
//
// This is a learning/demo reference implementation, not a security audit.
// For production use, add: authentication, TLS, key-verification ("safety
// numbers"), persistent storage, rate limiting, and forward secrecy.

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { sendPush } = require('./push');

const PORT = process.env.PORT || 3000;
const STORY_TTL_MS = 24 * 60 * 60 * 1000; // stories expire after 24h

// ---- In-memory "database" (swap for real DB in production) ----
const users = new Map();       // username -> { publicKey, lastSeen, online, pushToken, phone }
const phoneIndex = new Map();  // normalized phone -> username (for "find my contacts" matching)
const messages = [];           // { id, from, to, ciphertext, iv, encryptedKey, type, ts, status }
const stories = [];            // { id, from, ciphertext, iv, mediaType, ts }
const sseClients = new Map();  // username -> [res, res, ...]

function normalizePhone(raw) {
  // Keep digits only, so "+1 (555) 123-4567", "555-123-4567", etc. all match.
  return String(raw || '').replace(/\D/g, '');
}

// Matching by the last 10 digits handles the common case where one side
// includes a country code (+1 555-123-4567) and the other doesn't
// (555-123-4567) — a real phone contact book will have both forms.
function phoneMatchKey(raw) {
  const digits = normalizePhone(raw);
  return digits.length > 10 ? digits.slice(-10) : digits;
}

function send(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
  });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk) => {
      data += chunk;
      if (data.length > 25 * 1024 * 1024) req.destroy(); // 25MB cap (images as base64)
    });
    req.on('end', () => {
      try {
        resolve(data ? JSON.parse(data) : {});
      } catch (e) {
        reject(e);
      }
    });
    req.on('error', reject);
  });
}

function broadcastToUser(username, eventName, payload) {
  const clients = sseClients.get(username);
  if (!clients) return;
  const chunk = `event: ${eventName}\ndata: ${JSON.stringify(payload)}\n\n`;
  clients.forEach((res) => res.write(chunk));
}

function broadcastToAll(eventName, payload) {
  const chunk = `event: ${eventName}\ndata: ${JSON.stringify(payload)}\n\n`;
  for (const clients of sseClients.values()) {
    clients.forEach((res) => res.write(chunk));
  }
}

function purgeExpiredStories() {
  const now = Date.now();
  for (let i = stories.length - 1; i >= 0; i--) {
    if (now - stories[i].ts > STORY_TTL_MS) stories.splice(i, 1);
  }
}

const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css' };

function serveStatic(req, res) {
  let filePath = req.url === '/' ? '/index.html' : req.url;
  filePath = path.join(__dirname, 'public', filePath.split('?')[0]);
  if (!filePath.startsWith(path.join(__dirname, 'public'))) {
    res.writeHead(403); return res.end();
  }
  fs.readFile(filePath, (err, data) => {
    if (err) { res.writeHead(404); return res.end('Not found'); }
    const ext = path.extname(filePath);
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
    res.end(data);
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET,POST',
      'Access-Control-Allow-Headers': 'Content-Type',
    });
    return res.end();
  }

  // ---- SSE stream for realtime push (new messages / stories) ----
  if (url.pathname === '/api/stream' && req.method === 'GET') {
    const username = url.searchParams.get('username');
    if (!username) return send(res, 400, { error: 'username required' });

    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
      'Access-Control-Allow-Origin': '*',
    });
    res.write('retry: 2000\n\n');

    if (!sseClients.has(username)) sseClients.set(username, []);
    sseClients.get(username).push(res);

    // Mark online + tell everyone
    const u = users.get(username);
    if (u) u.online = true;
    broadcastToAll('presence', { username, online: true });

    req.on('close', () => {
      const arr = sseClients.get(username) || [];
      const idx = arr.indexOf(res);
      if (idx >= 0) arr.splice(idx, 1);
      if (arr.length === 0) {
        const uu = users.get(username);
        if (uu) { uu.online = false; uu.lastSeen = Date.now(); }
        broadcastToAll('presence', { username, online: false, lastSeen: Date.now() });
      }
    });
    return;
  }

  // ---- Register user + publish their RSA public key ----
  if (url.pathname === '/api/register' && req.method === 'POST') {
    const body = await readBody(req).catch(() => null);
    if (!body || !body.username || !body.publicKey) {
      return send(res, 400, { error: 'username and publicKey required' });
    }
    const existing = users.get(body.username);
    const phone = body.phone ? normalizePhone(body.phone) : (existing ? existing.phone : null);
    users.set(body.username, {
      publicKey: body.publicKey,
      lastSeen: existing ? existing.lastSeen : Date.now(),
      online: existing ? existing.online : false,
      pushToken: existing ? existing.pushToken : null,
      phone,
    });
    if (phone) phoneIndex.set(phoneMatchKey(phone), body.username);
    return send(res, 200, { success: true });
  }

  // ---- Match a list of phone numbers (e.g. from the device's contact
  // book, picked via the Contact Picker API) against registered users ----
  if (url.pathname === '/api/contacts/match' && req.method === 'POST') {
    const body = await readBody(req).catch(() => null);
    if (!body || !Array.isArray(body.phones)) return send(res, 400, { error: 'phones array required' });
    const matches = {};
    for (const raw of body.phones) {
      const key = phoneMatchKey(raw);
      if (key && phoneIndex.has(key)) matches[raw] = phoneIndex.get(key);
    }
    return send(res, 200, { matches });
  }

  // ---- Register/refresh this user's FCM device token for push notifications ----
  if (url.pathname === '/api/push-token' && req.method === 'POST') {
    const body = await readBody(req).catch(() => null);
    if (!body || !body.username || !body.token) return send(res, 400, { error: 'username and token required' });
    const u = users.get(body.username);
    if (!u) return send(res, 404, { error: 'unknown user' });
    u.pushToken = body.token;
    return send(res, 200, { success: true });
  }

  // ---- List all known users (= contacts, for demo simplicity) ----
  if (url.pathname === '/api/users' && req.method === 'GET') {
    const list = [...users.keys()];
    return send(res, 200, { users: list });
  }

  // ---- Presence (online/offline + last seen) for every known user ----
  if (url.pathname === '/api/presence' && req.method === 'GET') {
    const presence = {};
    for (const [name, u] of users.entries()) {
      presence[name] = { online: !!u.online, lastSeen: u.lastSeen };
    }
    return send(res, 200, { presence });
  }

  // ---- Typing indicator ----
  if (url.pathname === '/api/typing' && req.method === 'POST') {
    const body = await readBody(req).catch(() => null);
    if (!body || !body.from || !body.to) return send(res, 400, { error: 'missing fields' });
    broadcastToUser(body.to, 'typing', { from: body.from, isTyping: !!body.isTyping });
    return send(res, 200, { success: true });
  }

  // ---- Fetch a user's public key ----
  if (url.pathname.startsWith('/api/publicKey/') && req.method === 'GET') {
    const uname = decodeURIComponent(url.pathname.split('/').pop());
    const u = users.get(uname);
    if (!u) return send(res, 404, { error: 'unknown user' });
    return send(res, 200, { publicKey: u.publicKey });
  }

  // ---- Send an encrypted message (text or image) ----
  if (url.pathname === '/api/messages' && req.method === 'POST') {
    const body = await readBody(req).catch(() => null);
    if (!body || !body.from || !body.to || !body.ciphertext || !body.iv || !body.encryptedKey) {
      return send(res, 400, { error: 'missing fields' });
    }
    const msg = {
      id: crypto.randomUUID(),
      from: body.from,
      to: body.to,
      ciphertext: body.ciphertext,   // AES-GCM encrypted payload (text or base64 image), base64
      iv: body.iv,                   // base64
      encryptedKey: body.encryptedKey, // AES key, RSA-encrypted for recipient, base64
      type: body.type || 'text',     // 'text' | 'image'
      ts: Date.now(),
      // 'sent' -> 'delivered' (recipient's device received it) -> 'read' (recipient opened the chat)
      status: (users.get(body.to) && users.get(body.to).online) ? 'delivered' : 'sent',
    };
    messages.push(msg);
    broadcastToUser(body.to, 'message', msg);
    broadcastToUser(body.from, 'message', msg); // echo to sender's other tabs
    if (msg.status === 'delivered') {
      broadcastToUser(body.from, 'status', { id: msg.id, status: 'delivered' });
    } else {
      // Recipient has no live connection (app closed/backgrounded) — nudge
      // them with a push notification. Only a generic alert is sent since
      // the server cannot decrypt the message to preview it.
      const recipient = users.get(body.to);
      if (recipient && recipient.pushToken) {
        sendPush(recipient.pushToken, { type: 'message', from: body.from, messageId: msg.id })
          .catch((err) => console.warn('[push] failed to send:', err.message));
      }
    }
    return send(res, 200, { success: true, id: msg.id });
  }

  // ---- Mark all messages from `withUser` to `me` as read ----
  if (url.pathname === '/api/messages/read' && req.method === 'POST') {
    const body = await readBody(req).catch(() => null);
    if (!body || !body.me || !body.withUser) return send(res, 400, { error: 'missing fields' });
    const updatedIds = [];
    for (const m of messages) {
      if (m.from === body.withUser && m.to === body.me && m.status !== 'read') {
        m.status = 'read';
        updatedIds.push(m.id);
      }
    }
    if (updatedIds.length) {
      broadcastToUser(body.withUser, 'status', { ids: updatedIds, status: 'read' });
    }
    return send(res, 200, { success: true, updated: updatedIds.length });
  }

  // ---- Poll message history for a conversation ----
  if (url.pathname === '/api/messages' && req.method === 'GET') {
    const me = url.searchParams.get('me');
    const withUser = url.searchParams.get('withUser');
    const since = Number(url.searchParams.get('since') || 0);
    if (!me || !withUser) return send(res, 400, { error: 'me and withUser required' });
    const convo = messages.filter(
      (m) =>
        m.ts > since &&
        ((m.from === me && m.to === withUser) || (m.from === withUser && m.to === me))
    );
    return send(res, 200, { messages: convo });
  }

  // ---- Post an encrypted story (visible to all contacts for 24h) ----
  if (url.pathname === '/api/stories' && req.method === 'POST') {
    const body = await readBody(req).catch(() => null);
    if (!body || !body.from || !body.ciphertext || !body.iv || !body.encryptedKeys) {
      return send(res, 400, { error: 'missing fields' });
    }
    const story = {
      id: crypto.randomUUID(),
      from: body.from,
      ciphertext: body.ciphertext,
      iv: body.iv,
      // encryptedKeys: { username: rsaEncryptedAesKeyForThatUser, ... }
      encryptedKeys: body.encryptedKeys,
      mediaType: body.mediaType || 'image',
      ts: Date.now(),
    };
    stories.push(story);
    broadcastToAll('story', story);
    return send(res, 200, { success: true, id: story.id });
  }

  // ---- Get active (non-expired) stories ----
  if (url.pathname === '/api/stories' && req.method === 'GET') {
    purgeExpiredStories();
    return send(res, 200, { stories });
  }

  // ---- Static frontend ----
  return serveStatic(req, res);
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`E2E chat server running at http://localhost:${PORT}`);
});
