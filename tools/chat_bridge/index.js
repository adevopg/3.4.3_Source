const express = require('express');
const path = require('path');
const http = require('http');
const { Server } = require('socket.io');
const Redis = require('ioredis');
const jwt = require('jsonwebtoken');
const srp = require('secure-remote-password/server');
const mysql = require('mysql2/promise');
const bodyParser = require('body-parser');
const cors = require('cors');

const JWT_SECRET = process.env.JWT_SECRET || 'devsecret';
const REDIS_URL = process.env.REDIS_URL || 'redis://127.0.0.1:6379';
const LOGIN_DB_CONFIG = {
  host: process.env.DB_HOST || '127.0.0.1',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASS || 'Ladyamy89',
	database: process.env.DB_LOGIN_DB || 'auth'
};

const CHAR_DB_CONFIG = {
  host: process.env.DB_HOST || '127.0.0.1',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASS || process.env.DB_CHAR_PASS || 'Ladyamy89',
  database: process.env.DB_CHAR_DB || 'characters'
};

const app = express();
app.use(cors());
app.use(bodyParser.json());
// Serve the client_example.html and static assets so the web demo runs under http://localhost:3000
app.use(express.static(path.join(__dirname)));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'client_example.html')));

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

// Configure redis with a retry strategy and attach error handlers to avoid unhandled exceptions
const redisOpts = {
  // retryStrategy receives number of attempts and should return delay (ms) or null to stop
  retryStrategy: (times) => Math.min(times * 50, 2000),
  // enable offline queue so commands are queued while reconnecting
  enableOfflineQueue: true,
};

const redisPub = new Redis(REDIS_URL, redisOpts);
const redisSub = new Redis(REDIS_URL, redisOpts);

redisPub.on('error', (err) => console.error('[ioredis][pub] error', err));
redisSub.on('error', (err) => console.error('[ioredis][sub] error', err));

let dbPool;
let charDbPool;
(async () => { dbPool = await mysql.createPool(LOGIN_DB_CONFIG); charDbPool = await mysql.createPool(CHAR_DB_CONFIG); })();

// Simple login: validate account+password using DB (placeholder, implement SRP if needed)
// SRP endpoints: start and finish
// Register: client sends username, salt, verifier (generated client-side)
app.post('/srp/register', async (req, res) => {
  const { username, salt, verifier } = req.body;
  if (!username || !salt || !verifier) return res.status(400).send({ error: 'missing' });
  try {
	// create table if not exists (prototype convenience)
	await dbPool.query('CREATE TABLE IF NOT EXISTS srp_accounts (id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(64) UNIQUE, salt VARCHAR(255), verifier TEXT)');
	await dbPool.query('INSERT INTO srp_accounts (username, salt, verifier) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE salt = VALUES(salt), verifier = VALUES(verifier)', [username, salt, verifier]);
	return res.send({ ok: true });
  } catch (e) { console.error(e); return res.status(500).send({ error: 'err' }); }
});

// Start: returns salt and server ephemeral (B) to client
const serverSessions = new Map(); // username -> serverEphemeral
app.post('/srp/start', async (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).send({ error: 'missing' });
  try {
	const [rows] = await dbPool.query('SELECT id, username, salt, verifier FROM srp_accounts WHERE username = ?', [username]);
	if (!rows || rows.length === 0) return res.status(404).send({ error: 'no_account' });
	const acct = rows[0];
	const server = srp.generateServerChallenge(Buffer.from(acct.verifier, 'hex'));
	serverSessions.set(username, server);
	// server.B is server.challenge
	return res.send({ salt: acct.salt, B: server.public });
  } catch (e) { console.error(e); return res.status(500).send({ error: 'err' }); }
});

// Finish: validate client's proof, respond with server proof and JWT
app.post('/srp/finish', async (req, res) => {
  const { username, A, clientProof } = req.body;
  if (!username || !A || !clientProof) return res.status(400).send({ error: 'missing' });
  try {
	const [rows] = await dbPool.query('SELECT id, username, salt, verifier FROM srp_accounts WHERE username = ?', [username]);
	if (!rows || rows.length === 0) return res.status(404).send({ error: 'no_account' });
	const acct = rows[0];
	const server = serverSessions.get(username);
	if (!server) return res.status(400).send({ error: 'no_session' });
	// verify client's proof and produce server proof
	try {
	  const serverProof = srp.verifyServerProof(Buffer.from(acct.verifier, 'hex'), Buffer.from(A, 'hex'), server, Buffer.from(clientProof, 'hex'));
	  // serverProof is Buffer
	  // on success, issue JWT
	  const token = jwt.sign({ accountId: acct.id, username: acct.username }, JWT_SECRET, { expiresIn: '1h' });
	  serverSessions.delete(username);
	  return res.send({ token, serverProof: serverProof.toString('hex') });
	} catch (err) {
	  return res.status(403).send({ error: 'bad_proof' });
	}
  } catch (e) { console.error(e); return res.status(500).send({ error: 'err' }); }
});

// Backwards compatible plain login (keeps previous endpoint)
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).send({ error: 'missing' });

  try {
	// Try legacy column sha_pass_hash first (some DBs still use it)
	try {
	  const [rows] = await dbPool.query('SELECT id, username FROM account WHERE username = ? AND sha_pass_hash = ?', [username, password]);
	  if (rows && rows.length > 0) {
		const account = rows[0];
		const token = jwt.sign({ accountId: account.id, username: account.username }, JWT_SECRET, { expiresIn: '1h' });
		return res.send({ token });
	  }
	} catch (err) {
	  // handle missing column (modern schemas use SRP/verifier or battlenet mapping)
	  if (err && err.errno === 1054) {
		console.warn('login: sha_pass_hash column missing, trying fallback lookup by username or email');
		// fallthrough to fallback query below
	  } else {
		throw err;
	  }
	}

	// Fallback: try to locate account by username OR email (for battlenet/email mapping)
	const [rows2] = await dbPool.query('SELECT id, username FROM account WHERE username = ? OR email = ?', [username, username]);
	if (!rows2 || rows2.length === 0) return res.status(403).send({ error: 'bad' });

	// NOTE: schema uses SRP6/verifier for authentication. For security, prefer SRP endpoints.
	// As a pragmatic fallback (development), we issue a token if account exists. To require password check
	// in fallback mode, set environment variable DEV_REQUIRE_PASSWORD_CHECK=true and implement custom check.
	if (process.env.DEV_REQUIRE_PASSWORD_CHECK === 'true')
	  return res.status(403).send({ error: 'password_required' });

	const account = rows2[0];
	const token = jwt.sign({ accountId: account.id, username: account.username }, JWT_SECRET, { expiresIn: '1h' });
	return res.send({ token, warning: 'used_fallback_no_password_check' });
  } catch (e) {
	console.error(e);
	return res.status(500).send({ error: 'err' });
  }
});

// List chars
app.get('/chars', async (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).send({ error: 'no auth' });
  const token = auth.split(' ')[1];
  let payload;
  try { payload = jwt.verify(token, JWT_SECRET); } catch (e) { return res.status(401).send({ error: 'bad token' }); }

  try {
	// characters live in the characters DB; use charDbPool
	const [rows] = await charDbPool.query('SELECT guid, name FROM characters WHERE account = ?', [payload.accountId]);
	return res.send({ chars: rows });
  } catch (e) { console.error(e); return res.status(500).send({ error: 'err' }); }
});

io.use(async (socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('no-auth'));
  try {
	const payload = jwt.verify(token, JWT_SECRET);
	socket.data.accountId = payload.accountId;
	socket.data.username = payload.username;
	return next();
  } catch (e) {
	return next(new Error('bad-token'));
  }
});

io.on('connection', (socket) => {
  console.log('ws connected', socket.data.username);

  // subscribe to channels for this account or global
  const inChannel = `chat:in:account:${socket.data.accountId}`;
  const outChannel = `chat:out:account:${socket.data.accountId}`;

  // create a redis subscriber for account-out and allow additional dynamic subscriptions
  const subs = new Map(); // key -> Redis instance
  const createSub = (key) => {
	if (subs.has(key)) return;
	const r = new Redis(REDIS_URL, redisOpts);
	r.on('error', (e) => { console.error('[ioredis][socket-sub] error', e); });
	r.subscribe(key).then(() => {
	  // subscribed
	}).catch((err) => console.error('subscribe failed', err));
	r.on('message', (chan, msg) => {
	  try { const json = JSON.parse(msg); socket.emit('chat', json); } catch (e) {}
	});
	subs.set(key, r);
  };

  // always subscribe to account-specific out channel
  createSub(outChannel);

  // handle client requests to subscribe/unsubscribe to specific out channels
  socket.on('subscribe', (channelKey) => {
	try {
	  if (typeof channelKey !== 'string') return;
	  createSub(channelKey);
	  socket.emit('subscribed', channelKey);
	} catch (e) { console.error('subscribe error', e); }
  });

  socket.on('unsubscribe', (channelKey) => {
	try {
	  const r = subs.get(channelKey);
	  if (r) {
		r.unsubscribe(channelKey).catch(() => {});
		r.disconnect();
		subs.delete(channelKey);
		socket.emit('unsubscribed', channelKey);
	  }
	} catch (e) { console.error('unsubscribe error', e); }
  });

  socket.on('send', async (payload) => {
	// validate and publish to redis in channel for game server
	try {
	  // normalize payload
	  const allowedTypes = new Set(['say','yell','emote','whisper','guild','officer','party','raid','raid_warning','instance','channel']);
	  if (!payload || typeof payload !== 'object') return socket.emit('sent', { ok:false, error: 'invalid_payload' });
	  if (!payload.type || !allowedTypes.has(payload.type)) return socket.emit('sent', { ok:false, error: 'invalid_type' });
	// attach server-side account info
	payload.fromAccount = Number(socket.data.accountId) || 0;
  payload.fromName = String(socket.data.username || '');
  // enforce charGuid: take from payload only (server cannot access client DOM)
  payload.charGuid = String(payload.charGuid || '').trim();
  // sanitize numeric ids - always set to numeric (0 when undefined)
  payload.guildId = Number(payload.guildId || 0) || 0;
	  // ensure message exists and trim/limit length
	  payload.message = String(payload.message || '').trim();
	  if (payload.message.length === 0) return socket.emit('sent', { ok:false, error: 'empty_message' });
	  if (payload.message.length > 1024) payload.message = payload.message.substr(0, 1024);
	  // require target for whisper
	  if (payload.type === 'whisper' && !payload.target) return socket.emit('sent', { ok:false, error: 'missing_target' });

  console.log('[bridge] publish request', JSON.stringify({ from: socket.data.username, type: payload.type, charGuid: payload.charGuid, guildId: payload.guildId }));

  const jsonPayload = JSON.stringify(payload);
  // publish to generic channel
  await redisPub.publish('chat:in', jsonPayload);

  // also publish to type-specific or target-specific channels to allow selective subscriptions
  try {
	switch (payload.type) {
	  case 'say':
		await redisPub.publish('chat:in:say', jsonPayload);
		break;
	  case 'yell':
		await redisPub.publish('chat:in:yell', jsonPayload);
		break;
	  case 'emote':
		await redisPub.publish('chat:in:emote', jsonPayload);
		break;
	  case 'whisper':
		// if we have a target GUID, publish to whisper specific channel
		if (payload.targetGuid) {
		  await redisPub.publish(`chat:in:whisper:${payload.targetGuid}`, jsonPayload);
		} else if (payload.target) {
		  // publish to a name-based whisper channel (less reliable)
		  await redisPub.publish(`chat:in:whisper:name:${payload.target}`, jsonPayload);
		} else {
		  await redisPub.publish('chat:in:whisper', jsonPayload);
		}
		break;
	  case 'guild':
	  case 'officer':
		if (payload.guildId && payload.guildId > 0) {
		  await redisPub.publish(`chat:in:${payload.type}:${payload.guildId}`, jsonPayload);
		} else {
		  await redisPub.publish(`chat:in:${payload.type}`, jsonPayload);
		}
		break;
	  case 'channel':
		if (payload.channel) {
		  // channel names may contain spaces - normalize
		  const chanKey = String(payload.channel).replace(/\s+/g, '_');
		  await redisPub.publish(`chat:in:channel:${chanKey}`, jsonPayload);
		} else {
		  await redisPub.publish('chat:in:channel', jsonPayload);
		}
		break;
	  case 'party':
	  case 'raid':
	  case 'raid_warning':
	  case 'instance':
		if (payload.groupId) {
		  await redisPub.publish(`chat:in:${payload.type}:${payload.groupId}`, jsonPayload);
		} else {
		  await redisPub.publish(`chat:in:${payload.type}`, jsonPayload);
		}
		break;
	  default:
		// nothing extra
		break;
	}
  } catch (err) {
	console.error('[bridge] extra publish failed', err);
  }
	  // ack to client
	  socket.emit('sent', { ok: true, type: payload.type });

		// also broadcast the message to connected web clients so they can see/send replies
		try {
		  const echoed = { channel: 'chat:in', payload };
		  io.emit('chat', echoed);
		} catch (e) { /* best-effort */ }
	} catch (err) {
	  console.error('[bridge] publish failed', err);
	  socket.emit('sent', { ok: false, error: err.message });
	}
  });

	socket.on('disconnect', () => {
	try {
	  for (const [k, r] of subs.entries()) {
		try { r.disconnect(); } catch (e) {}
	  }
	  subs.clear();
	} catch (e) { }
  });
});

// Subscribe to global out channel and re-publish to ws if needed (with error handling)
redisSub.subscribe('chat:out').catch((e) => console.error('[ioredis] failed subscribe chat:out', e));
// also subscribe to all chat-in/out patterns so the bridge forwards any chat events
redisSub.psubscribe('chat:in*').catch((e) => console.error('[ioredis] failed psubscribe chat:in*', e));
redisSub.psubscribe('chat:out*').catch((e) => console.error('[ioredis] failed psubscribe chat:out*', e));

redisSub.on('message', (chan, msg) => {
  try { const json = JSON.parse(msg); io.emit('chat', { channel: chan, payload: json }); } catch (e) {}
});

redisSub.on('pmessage', (pattern, chan, msg) => {
  try { const json = JSON.parse(msg); io.emit('chat', { channel: chan, payload: json }); } catch (e) {}
});

redisSub.on('connect', () => console.log('[ioredis] connected to', REDIS_URL));
redisSub.on('close', () => console.warn('[ioredis] connection closed'));

server.listen(3000, () => console.log('chat bridge listening on 3000'));

// Allow connected websockets to request the bridge to publish to any channel (used for replying)
io.on('connection', (socket) => {
  socket.on('publishToChannel', async (channel, payload) => {
	try {
	  if (typeof channel !== 'string') return socket.emit('publishResult', { ok: false, error: 'invalid_channel' });
	  const json = typeof payload === 'string' ? payload : JSON.stringify(payload);
	  await redisPub.publish(channel, json);
	  socket.emit('publishResult', { ok: true, channel });
	} catch (e) {
	  console.error('[bridge] publishToChannel failed', e);
	  socket.emit('publishResult', { ok: false, error: e.message });
	}
  });
});
