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
app.use(express.static(path.join(__dirname)));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'client_example.html')));

const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*' }
});

const redisOpts = {
  retryStrategy: (times) => Math.min(times * 50, 2000),
  enableOfflineQueue: true
};

const redisPub = new Redis(REDIS_URL, redisOpts);
const redisSub = new Redis(REDIS_URL, redisOpts);

redisPub.on('error', (err) => console.error('[ioredis][pub] error', err));
redisSub.on('error', (err) => console.error('[ioredis][sub] error', err));
redisSub.on('connect', () => console.log('[ioredis] connected to', REDIS_URL));
redisSub.on('close', () => console.warn('[ioredis] connection closed'));

let dbPool;
let charDbPool;

async function initDb() {
  dbPool = await mysql.createPool(LOGIN_DB_CONFIG);
  charDbPool = await mysql.createPool(CHAR_DB_CONFIG);
  console.log('[mysql] pools ready');
}

function getBearerToken(req) {
  const auth = req.headers.authorization;
  if (!auth) return null;
  const parts = auth.split(' ');
  if (parts.length !== 2) return null;
  if (parts[0] !== 'Bearer') return null;
  return parts[1];
}

function verifyHttpToken(req, res) {
  const token = getBearerToken(req);
  if (!token) {
    res.status(401).send({ error: 'no auth' });
    return null;
  }

  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (e) {
    res.status(401).send({ error: 'bad token' });
    return null;
  }
}

async function getMyCharacters(accountId) {
  const [rows] = await charDbPool.query(
    'SELECT guid, name, account, online FROM characters WHERE account = ? ORDER BY name ASC',
    [accountId]
  );
  return rows;
}

async function getOnlineCharacters() {
  const [rows] = await charDbPool.query(
    'SELECT guid, name, account, online FROM characters WHERE online = 1 ORDER BY name ASC'
  );
  return rows;
}

// -----------------------------
// SRP
// -----------------------------

app.post('/srp/register', async (req, res) => {
  const { username, salt, verifier } = req.body;
  if (!username || !salt || !verifier) {
    return res.status(400).send({ error: 'missing' });
  }

  try {
    await dbPool.query(`
      CREATE TABLE IF NOT EXISTS srp_accounts (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(64) UNIQUE,
        salt VARCHAR(255),
        verifier TEXT
      )
    `);

    await dbPool.query(
      `INSERT INTO srp_accounts (username, salt, verifier)
       VALUES (?, ?, ?)
       ON DUPLICATE KEY UPDATE
         salt = VALUES(salt),
         verifier = VALUES(verifier)`,
      [username, salt, verifier]
    );

    return res.send({ ok: true });
  } catch (e) {
    console.error('[srp/register]', e);
    return res.status(500).send({ error: 'err' });
  }
});

const serverSessions = new Map();

app.post('/srp/start', async (req, res) => {
  const { username } = req.body;
  if (!username) {
    return res.status(400).send({ error: 'missing' });
  }

  try {
    const [rows] = await dbPool.query(
      'SELECT id, username, salt, verifier FROM srp_accounts WHERE username = ?',
      [username]
    );

    if (!rows || rows.length === 0) {
      return res.status(404).send({ error: 'no_account' });
    }

    const acct = rows[0];
    const serverChallenge = srp.generateServerChallenge(Buffer.from(acct.verifier, 'hex'));
    serverSessions.set(username, serverChallenge);

    return res.send({
      salt: acct.salt,
      B: serverChallenge.public.toString('hex')
    });
  } catch (e) {
    console.error('[srp/start]', e);
    return res.status(500).send({ error: 'err' });
  }
});

app.post('/srp/finish', async (req, res) => {
  const { username, A, clientProof } = req.body;
  if (!username || !A || !clientProof) {
    return res.status(400).send({ error: 'missing' });
  }

  try {
    const [rows] = await dbPool.query(
      'SELECT id, username, salt, verifier FROM srp_accounts WHERE username = ?',
      [username]
    );

    if (!rows || rows.length === 0) {
      return res.status(404).send({ error: 'no_account' });
    }

    const acct = rows[0];
    const serverChallenge = serverSessions.get(username);

    if (!serverChallenge) {
      return res.status(400).send({ error: 'no_session' });
    }

    try {
      const serverProof = srp.verifyServerProof(
        Buffer.from(acct.verifier, 'hex'),
        Buffer.from(A, 'hex'),
        serverChallenge,
        Buffer.from(clientProof, 'hex')
      );

      const token = jwt.sign(
        { accountId: acct.id, username: acct.username },
        JWT_SECRET,
        { expiresIn: '1h' }
      );

      serverSessions.delete(username);

      return res.send({
        token,
        serverProof: serverProof.toString('hex')
      });
    } catch (err) {
      return res.status(403).send({ error: 'bad_proof' });
    }
  } catch (e) {
    console.error('[srp/finish]', e);
    return res.status(500).send({ error: 'err' });
  }
});

// -----------------------------
// Login clásico
// -----------------------------

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).send({ error: 'missing' });
  }

  try {
    try {
      const [rows] = await dbPool.query(
        'SELECT id, username FROM account WHERE username = ? AND sha_pass_hash = ?',
        [username, password]
      );

      if (rows && rows.length > 0) {
        const account = rows[0];
        console.log('[login] matched by password:', account);

        const token = jwt.sign(
          { accountId: account.id, username: account.username },
          JWT_SECRET,
          { expiresIn: '1h' }
        );

        return res.send({ token, debugAccountId: account.id });
      }
    } catch (err) {
      if (err && err.errno === 1054) {
        console.warn('[login] sha_pass_hash missing, fallback by username/email');
      } else {
        throw err;
      }
    }

    const [rows2] = await dbPool.query(
      'SELECT id, username, email FROM account WHERE username = ? OR email = ?',
      [username, username]
    );

    if (!rows2 || rows2.length === 0) {
      return res.status(403).send({ error: 'bad' });
    }

    const account = rows2[0];
    console.log('[login] matched fallback:', account);

    if (process.env.DEV_REQUIRE_PASSWORD_CHECK === 'true') {
      return res.status(403).send({ error: 'password_required' });
    }

    const token = jwt.sign(
      { accountId: account.id, username: account.username },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    return res.send({
      token,
      warning: 'used_fallback_no_password_check',
      debugAccountId: account.id
    });
  } catch (e) {
    console.error('[login]', e);
    return res.status(500).send({ error: 'err' });
  }
});

// -----------------------------
// Characters API
// -----------------------------

app.get('/chars', async (req, res) => {
  const payload = verifyHttpToken(req, res);
  if (!payload) return;

  try {
    console.log('[chars] JWT payload=', payload);

    const rows = await getMyCharacters(payload.accountId);

    console.log('[chars] SQL accountId=', payload.accountId);
    console.log('[chars] rows=', rows);

    return res.send({
      chars: rows,
      debugAccountId: payload.accountId
    });
  } catch (e) {
    console.error('[chars]', e);
    return res.status(500).send({ error: 'err' });
  }
});

app.get('/online-chars', async (req, res) => {
  const payload = verifyHttpToken(req, res);
  if (!payload) return;

  try {
    const rows = await getOnlineCharacters();
    return res.send({ chars: rows });
  } catch (e) {
    console.error('[online-chars]', e);
    return res.status(500).send({ error: 'err' });
  }
});

app.get('/debug/chars-db', async (req, res) => {
  try {
    const [rows] = await charDbPool.query('SELECT DATABASE() AS db');
    const [count] = await charDbPool.query('SELECT COUNT(*) AS total FROM characters');

    return res.send({
      database: rows[0].db,
      totalCharacters: count[0].total
    });
  } catch (e) {
    console.error('[debug/chars-db]', e);
    return res.status(500).send({ error: 'err' });
  }
});

// -----------------------------
// Socket auth
// -----------------------------

io.use((socket, next) => {
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

// -----------------------------
// Socket connection
// -----------------------------

io.on('connection', (socket) => {
  console.log('[ws] connected', socket.data.username);

  const outChannel = `chat:out:account:${socket.data.accountId}`;
  const subs = new Map();

  const createSub = (key) => {
    if (!key || typeof key !== 'string') return;
    if (subs.has(key)) return;

    const r = new Redis(REDIS_URL, redisOpts);

    r.on('error', (e) => {
      console.error('[ioredis][socket-sub] error', e);
    });

    r.on('message', (chan, msg) => {
      try {
        const json = JSON.parse(msg);
        socket.emit('chat', { channel: chan, payload: json });
      } catch (e) {
        console.error('[socket-sub][message]', e);
      }
    });

    r.subscribe(key)
      .then(() => {
        console.log('[ws] subscribed', socket.data.username, key);
      })
      .catch((err) => {
        console.error('[ws] subscribe failed', err);
      });

    subs.set(key, r);
  };

  createSub(outChannel);

  socket.on('subscribe', (channelKey) => {
    try {
      if (typeof channelKey !== 'string') return;
      createSub(channelKey);
      socket.emit('subscribed', channelKey);
    } catch (e) {
      console.error('[subscribe]', e);
    }
  });

  socket.on('unsubscribe', (channelKey) => {
    try {
      const r = subs.get(channelKey);
      if (!r) return;

      r.unsubscribe(channelKey).catch(() => {});
      r.disconnect();
      subs.delete(channelKey);
      socket.emit('unsubscribed', channelKey);
    } catch (e) {
      console.error('[unsubscribe]', e);
    }
  });

  socket.on('send', async (payload) => {
    try {
      const allowedTypes = new Set([
        'say',
        'yell',
        'emote',
        'whisper',
        'guild',
        'officer',
        'party',
        'raid',
        'raid_warning',
        'instance',
        'channel'
      ]);

      if (!payload || typeof payload !== 'object') {
        return socket.emit('sent', { ok: false, error: 'invalid_payload' });
      }

      if (!payload.type || !allowedTypes.has(payload.type)) {
        return socket.emit('sent', { ok: false, error: 'invalid_type' });
      }

      payload.fromAccount = Number(socket.data.accountId) || 0;
      payload.fromName = String(socket.data.username || '');
      payload.charGuid = String(payload.charGuid || '').trim();
      payload.charName = String(payload.charName || '').trim();
      payload.guildId = Number(payload.guildId || 0) || 0;
      payload.groupId = Number(payload.groupId || 0) || 0;
      payload.target = String(payload.target || '').trim();
      payload.targetGuid = String(payload.targetGuid || '').trim();
      payload.channel = String(payload.channel || '').trim();
      payload.message = String(payload.message || '').trim();

      if (!payload.charGuid && !payload.charName) {
        return socket.emit('sent', { ok: false, error: 'missing_character_identity' });
      }

      if (!payload.message.length) {
        return socket.emit('sent', { ok: false, error: 'empty_message' });
      }

      if (payload.message.length > 1024) {
        payload.message = payload.message.substring(0, 1024);
      }

      if (payload.type === 'whisper' && !payload.target) {
        return socket.emit('sent', { ok: false, error: 'missing_target' });
      }

      console.log('[bridge] publish request', JSON.stringify({
        from: socket.data.username,
        type: payload.type,
        charGuid: payload.charGuid,
        charName: payload.charName,
        guildId: payload.guildId,
        groupId: payload.groupId,
        target: payload.target || null
      }));

      const jsonPayload = JSON.stringify(payload);

      await redisPub.publish('chat:in', jsonPayload);

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
          if (payload.targetGuid) {
            await redisPub.publish(`chat:in:whisper:${payload.targetGuid}`, jsonPayload);
          } else if (payload.target) {
            await redisPub.publish(`chat:in:whisper:name:${payload.target}`, jsonPayload);
          } else {
            await redisPub.publish('chat:in:whisper', jsonPayload);
          }
          break;

        case 'guild':
        case 'officer':
          if (payload.guildId > 0) {
            await redisPub.publish(`chat:in:${payload.type}:${payload.guildId}`, jsonPayload);
          } else {
            await redisPub.publish(`chat:in:${payload.type}`, jsonPayload);
          }
          break;

        case 'channel':
          if (payload.channel) {
            const chanKey = payload.channel.replace(/\s+/g, '_');
            await redisPub.publish(`chat:in:channel:${chanKey}`, jsonPayload);
          } else {
            await redisPub.publish('chat:in:channel', jsonPayload);
          }
          break;

        case 'party':
        case 'raid':
        case 'raid_warning':
        case 'instance':
          if (payload.groupId > 0) {
            await redisPub.publish(`chat:in:${payload.type}:${payload.groupId}`, jsonPayload);
          } else {
            await redisPub.publish(`chat:in:${payload.type}`, jsonPayload);
          }
          break;

        default:
          break;
      }

      socket.emit('sent', {
        ok: true,
        type: payload.type
      });
    } catch (err) {
      console.error('[bridge] publish failed', err);
      socket.emit('sent', { ok: false, error: err.message });
    }
  });

  socket.on('publishToChannel', async (channel, payload) => {
    try {
      if (typeof channel !== 'string' || !channel.trim()) {
        return socket.emit('publishResult', { ok: false, error: 'invalid_channel' });
      }

      const json = typeof payload === 'string' ? payload : JSON.stringify(payload);
      await redisPub.publish(channel, json);

      socket.emit('publishResult', {
        ok: true,
        channel
      });
    } catch (e) {
      console.error('[bridge] publishToChannel failed', e);
      socket.emit('publishResult', { ok: false, error: e.message });
    }
  });

  socket.on('disconnect', () => {
    try {
      for (const [, r] of subs.entries()) {
        try {
          r.disconnect();
        } catch (e) {}
      }
      subs.clear();
    } catch (e) {}
  });
});

// -----------------------------
// Global redis subscriptions
// -----------------------------

redisSub.subscribe('chat:out')
  .catch((e) => console.error('[ioredis] failed subscribe chat:out', e));

redisSub.psubscribe('chat:in*')
  .catch((e) => console.error('[ioredis] failed psubscribe chat:in*', e));

redisSub.psubscribe('chat:out*')
  .catch((e) => console.error('[ioredis] failed psubscribe chat:out*', e));

redisSub.on('message', (chan, msg) => {
  try {
    const json = JSON.parse(msg);
    io.emit('chat', { channel: chan, payload: json });
  } catch (e) {
    console.error('[redisSub][message]', e);
  }
});

redisSub.on('pmessage', (pattern, chan, msg) => {
  try {
    const json = JSON.parse(msg);
    io.emit('chat', { channel: chan, payload: json });
  } catch (e) {
    console.error('[redisSub][pmessage]', e);
  }
});

// -----------------------------
// Start
// -----------------------------

async function start() {
  try {
    await initDb();
    server.listen(3000, () => {
      console.log('chat bridge listening on 3000');
    });
  } catch (e) {
    console.error('[startup] fatal', e);
    process.exit(1);
  }
}

start();
