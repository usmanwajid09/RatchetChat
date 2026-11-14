/**
 * RatchetChat Integration Test Suite - End-to-End Relay Server & API
 */

const assert = require('assert');
const http = require('http');
const { app, server } = require('../server/index.js');
const primitives = require('../client/js/crypto/primitives.js');
const x3dh = require('../client/js/crypto/x3dh.js');

function postJson(port, path, body, token = null) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(body);
    const headers = {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(payload),
    };
    if (token) headers['Authorization'] = `Bearer ${token}`;

    const req = http.request(
      {
        hostname: 'localhost',
        port,
        path,
        method: 'POST',
        headers,
      },
      (res) => {
        let data = '';
        res.on('data', (c) => (data += c));
        res.on('end', () => {
          try {
            resolve({ status: res.statusCode, data: JSON.parse(data) });
          } catch (e) {
            resolve({ status: res.statusCode, raw: data });
          }
        });
      }
    );
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

function getJson(port, path, token = null) {
  return new Promise((resolve, reject) => {
    const headers = {};
    if (token) headers['Authorization'] = `Bearer ${token}`;

    const req = http.request(
      {
        hostname: 'localhost',
        port,
        path,
        method: 'GET',
        headers,
      },
      (res) => {
        let data = '';
        res.on('data', (c) => (data += c));
        res.on('end', () => {
          try {
            resolve({ status: res.statusCode, data: JSON.parse(data) });
          } catch (e) {
            resolve({ status: res.statusCode, raw: data });
          }
        });
      }
    );
    req.on('error', reject);
    req.end();
  });
}

async function runEndToEndIntegration() {
  console.log('[TEST] Running End-to-End Integration Test Suite...');

  // Get active server port
  const address = server.address();
  const port = address ? address.port : 3001;

  // 1. Health check
  const healthRes = await getJson(port, '/api/health');
  assert.strictEqual(healthRes.status, 200);
  assert.strictEqual(healthRes.data.status, 'ONLINE');

  // 2. Register Alice & Bob (using unique test timestamp for test idempotency)
  const userA = 'alice_' + Date.now();
  const userB = 'bob_' + Date.now();

  const aliceReg = await postJson(port, '/api/auth/register', { username: userA, password: 'password123' });
  assert.strictEqual(aliceReg.status, 201);
  const aliceToken = aliceReg.data.token;

  const bobReg = await postJson(port, '/api/auth/register', { username: userB, password: 'password123' });
  assert.strictEqual(bobReg.status, 201);
  const bobToken = bobReg.data.token;

  // 3. Bob publishes Prekey Bundle
  const bobKeys = x3dh.generatePrekeyBundle(5);
  const pubRes = await postJson(port, '/api/prekeys/publish', bobKeys.publicBundle, bobToken);
  assert.strictEqual(pubRes.status, 200);

  // 4. Alice fetches Bob's prekey bundle
  const fetchRes = await getJson(port, `/api/prekeys/${userB}`, aliceToken);
  assert.strictEqual(fetchRes.status, 200);
  assert.ok(fetchRes.data.bundle.signedPrekeyHex);
  assert.strictEqual(fetchRes.data.bundle.oneTimePrekeys.length, 1);

  // 5. Check Bob's remaining OPK count (should be 4 because 1 was consumed)
  const countRes = await getJson(port, `/api/prekeys/count/${userB}`, aliceToken);
  assert.strictEqual(countRes.data.count, 4);

  // 6. Alice sends encrypted message via offline queue
  const sendRes = await postJson(
    port,
    '/api/messages/send',
    {
      recipient: userB,
      payload: {
        header: { dhRatchetPubHex: 'aa'.repeat(32), n: 0, pn: 0 },
        ivHex: 'bb'.repeat(12),
        ciphertextHex: 'cc'.repeat(32),
      },
    },
    aliceToken
  );
  assert.strictEqual(sendRes.status, 201);

  // 7. Bob retrieves queued messages
  const pendingRes = await getJson(port, '/api/messages/pending', bobToken);
  assert.strictEqual(pendingRes.status, 200);
  assert.strictEqual(pendingRes.data.count, 1);
  assert.strictEqual(pendingRes.data.messages[0].sender, userA);

  // 8. Packet Inspector verification
  const inspectRes = await getJson(port, '/api/admin/relay-inspector');
  assert.strictEqual(inspectRes.status, 200);
  assert.ok(inspectRes.data.packets.length > 0);

  console.log('[PASS] End-to-End Integration Suite: 8/8 assertions passed.');
  server.close();
}

if (server.listening) {
  runEndToEndIntegration().catch((err) => {
    console.error('[FAIL] End-to-End Integration failed:', err);
    process.exit(1);
  });
} else {
  server.once('listening', () => {
    runEndToEndIntegration().catch((err) => {
      console.error('[FAIL] End-to-End Integration failed:', err);
      process.exit(1);
    });
  });
}
