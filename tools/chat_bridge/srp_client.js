// Example Node.js SRP client using secure-remote-password
const axios = require('axios');
const srpClient = require('secure-remote-password/client');

const BRIDGE = process.env.BRIDGE_URL || 'http://localhost:3000';

async function register(username, password) {
  const salt = srpClient.generateSalt().toString('hex');
  const privateKey = srpClient.derivePrivateKey(Buffer.from(salt, 'hex'), username, password);
  const verifier = srpClient.deriveVerifier(privateKey).toString('hex');
  const r = await axios.post(`${BRIDGE}/srp/register`, { username, salt, verifier });
  console.log('register', r.data);
}

async function authenticate(username, password) {
  // start: get salt and B
  const start = await axios.post(`${BRIDGE}/srp/start`, { username });
  if (!start.data || !start.data.salt || !start.data.B) { console.error('start failed', start.data); return; }
  const salt = Buffer.from(start.data.salt, 'hex');
  const B = Buffer.from(start.data.B, 'hex');

  const a = srpClient.generateEphemeral();
  const A = a.public;
  const privateKey = srpClient.derivePrivateKey(salt, username, password);
  const clientSession = srpClient.deriveSession(a.secret, A, B, username, privateKey);
  // clientSession.proof is Buffer
  const finish = await axios.post(`${BRIDGE}/srp/finish`, { username, A: A.toString('hex'), clientProof: clientSession.proof.toString('hex') });
  console.log('finish', finish.data);
  return finish.data.token;
}

(async () =>{
  const user = process.argv[2] || 'testuser';
  const pass = process.argv[3] || 'testpass';
  await register(user, pass);
  const token = await authenticate(user, pass);
  console.log('token', token);
})();
