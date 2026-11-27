import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  MemoryReplayStore,
  parseStandardWebhookSignatures,
  parseStripeSignature,
  signGitHub,
  signSlack,
  signStandardWebhooks,
  signStripe,
  verifyWebhook,
} from '../src/index.mjs';
import { FIXED_NOW, FIXED_SECONDS, expectCode, rotationSecrets } from './helpers.mjs';

function flipHexSignature(signature) {
  return signature.replace(/(v[01]=)([0-9a-f])/, (whole, prefix, digit) => prefix + (digit === '0' ? 'f' : '0'));
}

function flipBase64Token(signature) {
  return signature.replace(/v1,(.)/, (whole, digit) => 'v1,' + (digit === 'A' ? 'B' : 'A'));
}

function bodyFor(index) {
  return `{"delivery":${index},"nested":{"ok":true},"text":"payload-${index}"}`;
}

for (let index = 0; index < 50; index += 1) {
  test(`github valid matrix ${index}`, () => {
    const body = bodyFor(index);
    const secret = `github-secret-${index}`;
    const signature = signGitHub(body, secret);
    const result = verifyWebhook('github', body, {
      'x-hub-signature-256': signature,
      'x-github-delivery': `delivery-${index}`,
    }, { secret });
    assert.equal(result.valid, true);
    assert.equal(result.provider, 'github');
    assert.equal(result.secretIndex, 0);
    assert.equal(result.deliveryId, `delivery-${index}`);
  });
}

for (let index = 0; index < 20; index += 1) {
  test(`github wrong secret matrix ${index}`, () => {
    const body = bodyFor(index);
    const signature = signGitHub(body, `right-${index}`);
    expectCode(() => verifyWebhook('github', body, { 'x-hub-signature-256': signature }, { secret: `wrong-${index}` }), 'SIGNATURE_MISMATCH');
  });
}

for (let index = 0; index < 10; index += 1) {
  test(`github malformed signature matrix ${index}`, () => {
    const body = bodyFor(index);
    const bad = index % 2 === 0 ? `sha1=${signGitHub(body, 's').slice(7)}` : 'sha256=not-hex';
    expectCode(() => verifyWebhook('github', body, { 'x-hub-signature-256': bad }, { secret: 's' }), index % 2 === 0 ? 'INVALID_SIGNATURE' : 'INVALID_SIGNATURE');
  });
}

for (let index = 0; index < 10; index += 1) {
  test(`github header shape matrix ${index}`, () => {
    const body = bodyFor(index);
    const signature = signGitHub(body, 's');
    if (index % 2 === 0) {
      expectCode(() => verifyWebhook('github', body, {}, { secret: 's' }), 'MISSING_HEADER');
    } else {
      expectCode(() => verifyWebhook('github', body, new Map([['x-hub-signature-256', [signature, signature]]]), { secret: 's' }), 'INVALID_HEADER');
    }
  });
}

const stripeAges = [0, 1, 30, 60, 300];
for (let index = 0; index < 10; index += 1) {
  for (const age of stripeAges) {
    test(`stripe valid age ${age} body ${index}`, () => {
      const timestamp = FIXED_SECONDS - age;
      const body = bodyFor(index);
      const secret = `stripe-secret-${index}`;
      const header = signStripe(body, secret, timestamp);
      const result = verifyWebhook('stripe', body, { 'Stripe-Signature': header }, {
        secret,
        now: FIXED_NOW,
      });
      assert.equal(result.valid, true);
      assert.equal(result.timestamp, timestamp * 1000);
    });
  }
}

const stripeBadTimes = [301, 600, 3600];
for (const age of stripeBadTimes) {
  test(`stripe stale age ${age} is rejected`, () => {
    const timestamp = FIXED_SECONDS - age;
    const body = 'stripe-stale';
    const header = signStripe(body, 'stripe-secret', timestamp);
    expectCode(() => verifyWebhook('stripe', body, { 'stripe-signature': header }, { secret: 'stripe-secret', now: FIXED_NOW }), 'TIMESTAMP_OUT_OF_TOLERANCE');
  });
}

for (const future of [61, 120, 3600]) {
  test(`stripe future skew ${future} is rejected`, () => {
    const timestamp = FIXED_SECONDS + future;
    const body = 'stripe-future';
    const header = signStripe(body, 'stripe-secret', timestamp);
    expectCode(() => verifyWebhook('stripe', body, { 'stripe-signature': header }, { secret: 'stripe-secret', now: FIXED_NOW }), 'TIMESTAMP_OUT_OF_TOLERANCE');
  });
}

test('stripe exact replay boundary is accepted', () => {
  const timestamp = FIXED_SECONDS - 300;
  const body = 'stripe-boundary-old';
  const header = signStripe(body, 'stripe-secret', timestamp);
  assert.equal(verifyWebhook('stripe', body, { 'stripe-signature': header }, { secret: 'stripe-secret', now: FIXED_NOW }).valid, true);
});

test('stripe exact future skew boundary is accepted', () => {
  const timestamp = FIXED_SECONDS + 60;
  const body = 'stripe-boundary-future';
  const header = signStripe(body, 'stripe-secret', timestamp);
  assert.equal(verifyWebhook('stripe', body, { 'stripe-signature': header }, { secret: 'stripe-secret', now: FIXED_NOW }).valid, true);
});

for (let index = 0; index < 20; index += 1) {
  test(`stripe malformed or mismatched matrix ${index}`, () => {
    const body = bodyFor(index);
    const secret = `stripe-${index}`;
    const good = signStripe(body, secret, FIXED_SECONDS);
    let header = good;
    let code = 'SIGNATURE_MISMATCH';
    if (index % 6 === 0) { header = `t=${FIXED_SECONDS}`; code = 'INVALID_SIGNATURE'; }
    if (index % 6 === 1) { header = `v1=abcd`; code = 'TIMESTAMP_MISSING'; }
    if (index % 6 === 2) { header = `t=${FIXED_SECONDS},t=${FIXED_SECONDS},v1=abcd`; code = 'INVALID_HEADER'; }
    if (index % 6 === 3) { header = flipHexSignature(good); }
    if (index % 6 === 4) { header = signStripe(`${body}x`, secret, FIXED_SECONDS); }
    if (index % 6 === 5) { header = signStripe(body, `wrong-${index}`, FIXED_SECONDS); }
    expectCode(() => verifyWebhook('stripe', body, { 'stripe-signature': header }, { secret, now: FIXED_NOW }), code);
  });
}

test('stripe accepts a correct second v1 signature during rotation overlap', () => {
  const body = 'multi-v1';
  const first = signStripe(body, 'wrong-secret', FIXED_SECONDS).match(/v1=([0-9a-f]+)/)[1];
  const second = signStripe(body, 'right-secret', FIXED_SECONDS).match(/v1=([0-9a-f]+)/)[1];
  const result = verifyWebhook('stripe', body, { 'stripe-signature': `t=${FIXED_SECONDS},v1=${first},v1=${second}` }, { secret: 'right-secret', now: FIXED_NOW });
  assert.equal(result.valid, true);
});

test('parseStripeSignature returns timestamp and signatures', () => {
  const parsed = parseStripeSignature('t=123,v1=abc,v1=def');
  assert.equal(parsed.timestamp, '123');
  assert.deepEqual(parsed.signatures, ['abc', 'def']);
});

for (let index = 0; index < 40; index += 1) {
  test(`slack valid matrix ${index}`, () => {
    const body = bodyFor(index);
    const secret = `slack-secret-${index}`;
    const timestamp = FIXED_SECONDS - (index % 200);
    const signature = signSlack(body, secret, timestamp);
    const result = verifyWebhook('slack', body, {
      'x-slack-signature': signature,
      'x-slack-request-timestamp': String(timestamp),
    }, { secret, now: FIXED_NOW });
    assert.equal(result.valid, true);
    assert.equal(result.timestamp, timestamp * 1000);
  });
}

for (let index = 0; index < 30; index += 1) {
  test(`slack invalid matrix ${index}`, () => {
    const body = bodyFor(index);
    const secret = `slack-${index}`;
    const timestamp = FIXED_SECONDS;
    const good = signSlack(body, secret, timestamp);
    const headers = {
      'x-slack-signature': good,
      'x-slack-request-timestamp': String(timestamp),
    };
    let code = 'SIGNATURE_MISMATCH';
    if (index % 6 === 0) { headers['x-slack-signature'] = flipHexSignature(good); }
    if (index % 6 === 1) { headers['x-slack-signature'] = signSlack(`${body}x`, secret, timestamp); }
    if (index % 6 === 2) { headers['x-slack-signature'] = signSlack(body, `wrong-${index}`, timestamp); }
    if (index % 6 === 3) { headers['x-slack-request-timestamp'] = String(timestamp - 301); headers['x-slack-signature'] = signSlack(body, secret, timestamp - 301); code = 'TIMESTAMP_OUT_OF_TOLERANCE'; }
    if (index % 6 === 4) { headers['x-slack-request-timestamp'] = '01'; code = 'TIMESTAMP_INVALID'; }
    if (index % 6 === 5) { delete headers['x-slack-request-timestamp']; code = 'MISSING_HEADER'; }
    expectCode(() => verifyWebhook('slack', body, headers, { secret, now: FIXED_NOW }), code);
  });
}

for (let index = 0; index < 40; index += 1) {
  test(`standard webhooks valid matrix ${index}`, () => {
    const body = bodyFor(index);
    const secret = `standard-secret-${index}`;
    const timestamp = FIXED_SECONDS - (index % 200);
    const headers = signStandardWebhooks(body, secret, `msg-${index}`, timestamp);
    const result = verifyWebhook('standard-webhooks', body, headers, { secret, now: FIXED_NOW });
    assert.equal(result.valid, true);
    assert.equal(result.deliveryId, `msg-${index}`);
    assert.equal(result.timestamp, timestamp * 1000);
  });
}

for (let index = 0; index < 30; index += 1) {
  test(`standard webhooks invalid matrix ${index}`, () => {
    const body = bodyFor(index);
    const secret = `standard-${index}`;
    const headers = { ...signStandardWebhooks(body, secret, `bad-${index}`, FIXED_SECONDS) };
    let code = 'SIGNATURE_MISMATCH';
    if (index % 6 === 0) headers['webhook-signature'] = flipBase64Token(headers['webhook-signature']);
    if (index % 6 === 1) headers['webhook-signature'] = signStandardWebhooks(`${body}x`, secret, `bad-${index}`, FIXED_SECONDS)['webhook-signature'];
    if (index % 6 === 2) headers['webhook-signature'] = signStandardWebhooks(body, `wrong-${index}`, `bad-${index}`, FIXED_SECONDS)['webhook-signature'];
    if (index % 6 === 3) { headers['webhook-timestamp'] = String(FIXED_SECONDS - 301); Object.assign(headers, signStandardWebhooks(body, secret, `bad-${index}`, FIXED_SECONDS - 301)); code = 'TIMESTAMP_OUT_OF_TOLERANCE'; }
    if (index % 6 === 4) { delete headers['webhook-id']; code = 'MISSING_HEADER'; }
    if (index % 6 === 5) { headers['webhook-signature'] = 'v2,AAAA'; code = 'INVALID_SIGNATURE'; }
    expectCode(() => verifyWebhook('standard-webhooks', body, headers, { secret, now: FIXED_NOW }), code);
  });
}

test('standard webhooks parser accepts multiple v1 tokens', () => {
  const parsed = parseStandardWebhookSignatures('v1,AAAA v2,ignore v1,BBBB');
  assert.deepEqual(parsed, ['AAAA', 'BBBB']);
});

for (let index = 0; index < 5; index += 1) {
  test(`github replay rejected ${index}`, () => {
    const body = bodyFor(index);
    const secret = `replay-github-${index}`;
    const headers = { 'x-hub-signature-256': signGitHub(body, secret), 'x-github-delivery': `repeat-${index}` };
    const replayStore = new MemoryReplayStore({ now: () => FIXED_NOW });
    assert.equal(verifyWebhook('github', body, headers, { secret, replayStore }).replayProtected, true);
    expectCode(() => verifyWebhook('github', body, headers, { secret, replayStore }), 'REPLAYED_DELIVERY');
  });

  test(`stripe replay rejected ${index}`, () => {
    const body = bodyFor(index);
    const secret = `replay-stripe-${index}`;
    const headers = { 'stripe-signature': signStripe(body, secret, FIXED_SECONDS) };
    const replayStore = new MemoryReplayStore({ now: () => FIXED_NOW });
    verifyWebhook('stripe', body, headers, { secret, now: FIXED_NOW, replayStore });
    expectCode(() => verifyWebhook('stripe', body, headers, { secret, now: FIXED_NOW, replayStore }), 'REPLAYED_DELIVERY');
  });

  test(`slack replay rejected ${index}`, () => {
    const body = bodyFor(index);
    const secret = `replay-slack-${index}`;
    const headers = { 'x-slack-signature': signSlack(body, secret, FIXED_SECONDS), 'x-slack-request-timestamp': String(FIXED_SECONDS) };
    const replayStore = new MemoryReplayStore({ now: () => FIXED_NOW });
    verifyWebhook('slack', body, headers, { secret, now: FIXED_NOW, replayStore });
    expectCode(() => verifyWebhook('slack', body, headers, { secret, now: FIXED_NOW, replayStore }), 'REPLAYED_DELIVERY');
  });

  test(`standard replay rejected ${index}`, () => {
    const body = bodyFor(index);
    const secret = `replay-standard-${index}`;
    const headers = signStandardWebhooks(body, secret, `repeat-${index}`, FIXED_SECONDS);
    const replayStore = new MemoryReplayStore({ now: () => FIXED_NOW });
    verifyWebhook('standard-webhooks', body, headers, { secret, now: FIXED_NOW, replayStore });
    expectCode(() => verifyWebhook('standard-webhooks', body, headers, { secret, now: FIXED_NOW, replayStore }), 'REPLAYED_DELIVERY');
  });
}

for (let index = 0; index < 10; index += 1) {
  test(`provider key rotation index ${index}`, () => {
    const secrets = rotationSecrets(10);
    const body = bodyFor(index);
    const signature = signGitHub(body, secrets[index]);
    const result = verifyWebhook('github', body, { 'x-hub-signature-256': signature }, { secrets });
    assert.equal(result.secretIndex, index);
  });
}

test('standard webhooks accepts a real whsec base64 secret', () => {
  const rawSecret = 'standard-webhooks-key-material';
  const secret = `whsec_${Buffer.from(rawSecret).toString('base64')}`;
  const body = 'whsec-body';
  const headers = signStandardWebhooks(body, rawSecret, 'whsec-message', FIXED_SECONDS);
  const result = verifyWebhook('standard-webhooks', body, headers, { secret, now: FIXED_NOW });
  assert.equal(result.valid, true);
});

test('standard webhooks rejects a malformed whsec secret', () => {
  const body = 'whsec-body';
  const headers = signStandardWebhooks(body, 'raw-secret', 'whsec-message', FIXED_SECONDS);
  expectCode(() => verifyWebhook('standard-webhooks', body, headers, { secret: 'whsec_!!', now: FIXED_NOW }), 'INVALID_SECRET');
});

test('standard webhooks whsec rotation matches the correct key', () => {
  const oldSecret = `whsec_${Buffer.from('old-standard-key').toString('base64')}`;
  const newSecret = `whsec_${Buffer.from('new-standard-key').toString('base64')}`;
  const body = 'rotation-standard-body';
  const headers = signStandardWebhooks(body, oldSecret, 'rotation-message', FIXED_SECONDS);
  const result = verifyWebhook('standard-webhooks', body, headers, { secrets: [newSecret, oldSecret], now: FIXED_NOW });
  assert.equal(result.secretIndex, 1);
});

test('standard webhooks whsec signer and verifier use the decoded key', () => {
  const secret = `whsec_${Buffer.from('decoded-key').toString('base64')}`;
  const body = 'decoded-key-body';
  const headers = signStandardWebhooks(body, 'decoded-key', 'decoded-message', FIXED_SECONDS);
  assert.equal(verifyWebhook('standard-webhooks', body, headers, { secret, now: FIXED_NOW }).valid, true);
  const wrong = signStandardWebhooks(body, 'not-the-key-material', 'decoded-message', FIXED_SECONDS);
  expectCode(() => verifyWebhook('standard-webhooks', body, wrong, { secret, now: FIXED_NOW }), 'SIGNATURE_MISMATCH');
});
