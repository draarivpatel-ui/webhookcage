import { signSlack, verifyWebhook } from '../src/index.mjs';

const oldSecret = 'old-example-secret';
const newSecret = 'new-example-secret';
const body = 'event=example';
const timestamp = 1700000000;
const signature = signSlack(body, oldSecret, timestamp);
const result = verifyWebhook('slack', body, {
  'x-slack-signature': signature,
  'x-slack-request-timestamp': String(timestamp),
}, {
  secrets: [newSecret, oldSecret],
  now: timestamp * 1000,
});

console.log('matched rotation key', result.secretIndex);
