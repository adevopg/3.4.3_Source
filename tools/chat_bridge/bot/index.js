// bot.js
require('dotenv').config();
const { Client, GatewayIntentBits, Partials, Events } = require('discord.js');
const express = require('express');
const path = require('path');
const http = require('http'); // por si quieres mantener HTTP
const Redis = require('ioredis');
const jwt = require('jsonwebtoken');
const srp = require('secure-remote-password/server');
const mysql = require('mysql2/promise');
const bodyParser = require('body-parser');
const cors = require('cors');

// --------- Config ----------
const JWT_SECRET = process.env.JWT_SECRET || 'devsecret';
const REDIS_URL = process.env.REDIS_URL || 'redis://127.0.0.1:6379';
const DISCORD_TOKEN = process.env.DISCORD_TOKEN || 'MTUxNTcyNjM5ODcxMzc2MTk5NA.G0Nhxo.C68WetfeYh0gyAXbpnPtOHJWWiqe5KmztJL1LY';
const DEFAULT_CHANNEL_ID = process.env.DEFAULT_CHANNEL_ID || ''; // canal puente por defecto
const GUILD_ID = process.env.GUILD_ID || '';

const LOGIN_DB_CONFIG = {
  host: process.env.DB_HOST || '127.0.0.1',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASS || 'Ladyamy89',
  database: process.env.DB_LOGIN_DB || 'auth'
};

const CHAR_DB_CONFIG = {
  host: process.env.DB_HOST || '127.0.0.1',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_CHAR_PASS || process.env.DB_PASS || 'Ladyamy89',
  database: process.env.DB_CHAR_DB || 'characters'
};

// Mapeos Discord -> WoW y viceversa
// Ajusta según tus canales y necesidades
const CHANNEL_MAP = {
  // Discord channel ID => { type: 'channel'|'guild'|'say'|'yell'|..., wowKey: 'Trade' o guildId/groupId, etc. }
  // Ejemplos:
  // '123456789012345678': { type: 'channel', wowKey: 'Trade' },
  // '234567890123456789': { type: 'guild', guildId: 1 },
};

const USERNAME_PREFIX = '[DC]'; // prefijo para mensajes salientes desde Discord hacia WoW

// --------- Express opcional (SRP/Login/Chars) ----------
const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname)));

let dbPool, charDbPool;

async function initDb() {
  dbPool = await mysql.createPool(LOGIN_DB_CONFIG);
  charDbPool = await mysql.createPool(CHAR_DB_CONFIG);
  console.log('[mysql] pools ready');
}

function getBearerToken(req) {
  const auth = req.headers.authorization;
  if (!auth) return null;
  const [scheme, token] = auth.split(' ');
  if (scheme !== 'Bearer' || !token) return null;
  return token;
}

function verifyHttpToken(req, res) {
  const token = getBearerToken(req);
  if (!token) {
    res.status(401).send({ error: 'no auth' });
    return null;
  }
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
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

// SRP endpoints (opcional)
app.post('/srp/register', async (req, res) => {
  const { username, salt, verifier } = req.body;
  if (!username || !salt || !verifier) return res.status(400).send({ error: 'missing' });
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
       ON DUPLICATE KEY UPDATE salt=VALUES(salt), verifier=VALUES(verifier)`,
      [username, salt, verifier]
    );
    res.send({ ok: true });
  } catch (e) {
    console.error('[srp/register]', e);
    res.status(500).send({ error: 'err' });
  }
});

const serverSessions = new Map();

app.post('/srp/start', async (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).send({ error: 'missing' });
  try {
    const [rows] = await dbPool.query(
      'SELECT id, username, salt, verifier FROM srp_accounts WHERE username = ?',
      [username]
    );
    if (!rows.length) return res.status(404).send({ error: 'no_account' });
    const acct = rows[0];
    const serverChallenge = srp.generateServerChallenge(Buffer.from(acct.verifier, 'hex'));
    serverSessions.set(username, serverChallenge);
    res.send({ salt: acct.salt, B: serverChallenge.public.toString('hex') });
  } catch (e) {
    console.error('[srp/start]', e);
    res.status(500).send({ error: 'err' });
  }
});

app.post('/srp/finish', async (req, res) => {
  const { username, A, clientProof } = req.body;
  if (!username || !A || !clientProof) return res.status(400).send({ error: 'missing' });
  try {
    const [rows] = await dbPool.query(
      'SELECT id, username, salt, verifier FROM srp_accounts WHERE username = ?',
      [username]
    );
    if (!rows.length) return res.status(404).send({ error: 'no_account' });
    const acct = rows[0];
    const serverChallenge = serverSessions.get(username);
    if (!serverChallenge) return res.status(400).send({ error: 'no_session' });
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
      res.send({ token, serverProof: serverProof.toString('hex') });
    } catch {
      res.status(403).send({ error: 'bad_proof' });
    }
  } catch (e) {
    console.error('[srp/finish]', e);
    res.status(500).send({ error: 'err' });
  }
});

// Login clásico (idéntico salvo claves)
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).send({ error: 'missing' });
  try {
    try {
      const [rows] = await dbPool.query(
        'SELECT id, username FROM account WHERE username = ? AND sha_pass_hash = ?',
        [username, password]
      );
      if (rows && rows.length > 0) {
        const account = rows[0];
        const token = jwt.sign(
          { accountId: account.id, username: account.username },
          JWT_SECRET,
          { expiresIn: '1h' }
        );
        return res.send({ token, debugAccountId: account.id });
      }
    } catch (err) {
      if (!(err && err.errno === 1054)) throw err;
    }
    const [rows2] = await dbPool.query(
      'SELECT id, username, email FROM account WHERE username = ? OR email = ?',
      [username, username]
    );
    if (!rows2 || !rows2.length) return res.status(403).send({ error: 'bad' });
    const account = rows2[0];
    if (process.env.DEV_REQUIRE_PASSWORD_CHECK === 'true') {
      return res.status(403).send({ error: 'password_required' });
    }
    const token = jwt.sign(
      { accountId: account.id, username: account.username },
      JWT_SECRET,
      { expiresIn: '1h' }
    );
    res.send({ token, warning: 'used_fallback_no_password_check', debugAccountId: account.id });
  } catch (e) {
    console.error('[login]', e);
    res.status(500).send({ error: 'err' });
  }
});

// Characters API
app.get('/chars', async (req, res) => {
  const payload = verifyHttpToken(req, res);
  if (!payload) return;
  try {
    const rows = await getMyCharacters(payload.accountId);
    res.send({ chars: rows, debugAccountId: payload.accountId });
  } catch (e) {
    console.error('[chars]', e);
    res.status(500).send({ error: 'err' });
  }
});

app.get('/online-chars', async (req, res) => {
  const payload = verifyHttpToken(req, res);
  if (!payload) return;
  try {
    const rows = await getOnlineCharacters();
    res.send({ chars: rows });
  } catch (e) {
    console.error('[online-chars]', e);
    res.status(500).send({ error: 'err' });
  }
});

// Debug
app.get('/debug/chars-db', async (req, res) => {
  try {
    const [rows] = await charDbPool.query('SELECT DATABASE() AS db');
    const [count] = await charDbPool.query('SELECT COUNT(*) AS total FROM characters');
    res.send({ database: rows[0].db, totalCharacters: count[0].total });
  } catch (e) {
    console.error('[debug/chars-db]', e);
    res.status(500).send({ error: 'err' });
  }
});

// --------- Redis ----------
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

// --------- Discord Client ----------
const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.DirectMessages,
    GatewayIntentBits.MessageContent
  ],
  partials: [Partials.Channel]
});

// Publicar hacia WoW (Redis) desde Discord
async function publishToWoWFromDiscord(discordMsg, mapping) {
  // Construye el payload siguiendo tu esquema actual
  const content = discordMsg.content?.trim() || '';
  if (!content) return;

  const payload = {
    type: mapping.type,       // 'channel', 'guild', 'say', etc.
    fromAccount: 0,           // si deseas enlazar cuentas, mapéalo
    fromName: `${USERNAME_PREFIX}${discordMsg.author.username}`,
    charGuid: '',             // opcional si asocias personajes
    charName: '',             // idem
    guildId: mapping.guildId || 0,
    groupId: mapping.groupId || 0,
    target: '',               // para whispers desde comandos
    targetGuid: '',
    channel: mapping.wowKey || '',
    message: content.slice(0, 1024)
  };

  const json = JSON.stringify(payload);

  // Publicación genérica
  await redisPub.publish('chat:in', json);

  // Específicos por tipo (igual que tu switch)
  switch (payload.type) {
    case 'say':
      await redisPub.publish('chat:in:say', json);
      break;
    case 'yell':
      await redisPub.publish('chat:in:yell', json);
      break;
    case 'emote':
      await redisPub.publish('chat:in:emote', json);
      break;
    case 'whisper':
      if (payload.targetGuid) {
        await redisPub.publish(`chat:in:whisper:${payload.targetGuid}`, json);
      } else if (payload.target) {
        await redisPub.publish(`chat:in:whisper:name:${payload.target}`, json);
      } else {
        await redisPub.publish('chat:in:whisper', json);
      }
      break;
    case 'guild':
    case 'officer':
      if (payload.guildId > 0) {
        await redisPub.publish(`chat:in:${payload.type}:${payload.guildId}`, json);
      } else {
        await redisPub.publish(`chat:in:${payload.type}`, json);
      }
      break;
    case 'channel':
      if (payload.channel) {
        const chanKey = payload.channel.replace(/\s+/g, '_');
        await redisPub.publish(`chat:in:channel:${chanKey}`, json);
      } else {
        await redisPub.publish('chat:in:channel', json);
      }
      break;
    case 'party':
    case 'raid':
    case 'raid_warning':
    case 'instance':
      if (payload.groupId > 0) {
        await redisPub.publish(`chat:in:${payload.type}:${payload.groupId}`, json);
      } else {
        await redisPub.publish(`chat:in:${payload.type}`, json);
      }
      break;
  }
}

// Reenviar WoW -> Discord
async function relayWoWToDiscord(chan, msgObj) {
  try {
    const payload = typeof msgObj === 'string' ? JSON.parse(msgObj) : msgObj;
    const text = payload?.message || '';
    const from = payload?.fromName || payload?.charName || 'WoW';
    const type = payload?.type || 'channel';

    // Elige canal de Discord según tipo/canal/guild
    let discordChannelId = DEFAULT_CHANNEL_ID;

    // Si mapeas por channel name
    if (type === 'channel' && payload.channel) {
      // busca un mapeo inverso
      const found = Object.entries(CHANNEL_MAP).find(
        ([, m]) => m.type === 'channel' && (m.wowKey || '').toLowerCase() === payload.channel.toLowerCase().replace(/\s+/g, '_')
      );
      if (found) discordChannelId = found[0];
    }

    // Si mapeas por guildId
    if ((type === 'guild' || type === 'officer') && payload.guildId) {
      const found = Object.entries(CHANNEL_MAP).find(
        ([, m]) => (m.type === type) && Number(m.guildId) === Number(payload.guildId)
      );
      if (found) discordChannelId = found[0];
    }

    if (!discordChannelId) return;

    const channel = await client.channels.fetch(discordChannelId).catch(() => null);
    if (!channel || !channel.isTextBased()) return;

    const prefix = type.toUpperCase();
    const name = from.replace(/`/g, "'");
    const body = text || JSON.stringify(payload);

    await channel.send(`[${prefix}] ${name}: ${body}`);
  } catch (e) {
    console.error('[relayWoWToDiscord]', e);
  }
}

// Suscripciones Redis globales (WoW -> Discord)
async function subscribeRedis() {
  await redisSub.psubscribe('chat:out*');
  redisSub.on('pmessage', (pattern, chan, msg) => {
    relayWoWToDiscord(chan, msg);
  });
}

// Eventos Discord
client.once(Events.ClientReady, async () => {
  console.log(`[discord] Logged in as ${client.user.tag}`);
  await subscribeRedis();
});

client.on(Events.MessageCreate, async (message) => {
  try {
    if (message.author.bot) return;

    // DM -> podría ser whisper
    if (message.channel?.isDMBased?.()) {
      const mapping = { type: 'whisper', wowKey: '' };
      // Podrías parsear "/w <name> <mensaje>"
      // Por simplicidad lo tratamos como "say" privado, pero publicamos a whisper genérico
      await publishToWoWFromDiscord(message, mapping);
      return;
    }

    // Canal de servidor
    const chId = message.channelId;
    const mapping = CHANNEL_MAP[chId] || { type: 'channel', wowKey: 'General' };

    // Comandos simples para enrutar:
    // !say texto, !yell texto, !emote texto, !w <name> texto, !guild texto, !chan <name> texto
    const c = message.content.trim();
    if (c.startsWith('!')) {
      const [cmd, ...rest] = c.slice(1).split(/\s+/);
      const restText = rest.join(' ');
      switch (cmd.toLowerCase()) {
        case 'say':
          await publishToWoWFromDiscord(
            { ...message, content: restText },
            { type: 'say' }
          );
          return;
        case 'yell':
          await publishToWoWFromDiscord(
            { ...message, content: restText },
            { type: 'yell' }
          );
          return;
        case 'emote':
          await publishToWoWFromDiscord(
            { ...message, content: restText },
            { type: 'emote' }
          );
          return;
        case 'w': // !w objetivo mensaje
          if (rest.length < 2) {
            await message.reply('Uso: !w <nombre> <mensaje>');
            return;
          }
          const target = rest[0];
          const msgText = rest.slice(1).join(' ');
          await publishToWoWFromDiscord(
            { ...message, content: msgText },
            { type: 'whisper' }
          );
          // Publica con target name específico
          const payload = {
            type: 'whisper',
            fromAccount: 0,
            fromName: `${USERNAME_PREFIX}${message.author.username}`,
            charGuid: '',
            charName: '',
            guildId: 0,
            groupId: 0,
            target: target,
            targetGuid: '',
            channel: '',
            message: msgText.slice(0, 1024)
          };
          const json = JSON.stringify(payload);
          await redisPub.publish('chat:in', json);
          await redisPub.publish(`chat:in:whisper:name:${target}`, json);
          return;
        case 'guild':
          await publishToWoWFromDiscord(
            { ...message, content: restText },
            { type: 'guild', guildId: (CHANNEL_MAP[chId]?.guildId || 0) }
          );
          return;
        case 'chan':
          if (rest.length < 2) {
            await message.reply('Uso: !chan <nombre_canal> <mensaje>');
            return;
          }
          const wowChan = rest[0].replace(/\s+/g, '_');
          const chanMsg = rest.slice(1).join(' ');
          await publishToWoWFromDiscord(
            { ...message, content: chanMsg },
            { type: 'channel', wowKey: wowChan }
          );
          return;
      }
      // Si no coincide comando, cae al mapping del canal
    }

    // Sin comando: usa el mapeo del canal
    await publishToWoWFromDiscord(message, mapping);
  } catch (e) {
    console.error('[MessageCreate]', e);
  }
});

// --------- Start ----------
async function start() {
  try {
    if (!DISCORD_TOKEN) {
      console.error('Falta DISCORD_TOKEN');
      process.exit(1);
    }
    await initDb();

    // Arranca HTTP si quieres exponer APIs
    const server = http.createServer(app);
    const PORT = process.env.PORT || 3000;
    server.listen(PORT, () => console.log(`API listening on ${PORT}`));

    await client.login(DISCORD_TOKEN);
  } catch (e) {
    console.error('[startup] fatal', e);
    process.exit(1);
  }
}

start();
