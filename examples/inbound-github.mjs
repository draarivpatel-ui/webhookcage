import { signGitHub, verifyWebhook } from '../src/index.mjs';

const secret = 'example-shared-secret';
const body = '{"action":"opened"}';
const signature = signGitHub(body, secret);
const result = verifyWebhook('github', body, {
  'x-hub-signature-256': signature,
  'x-github-delivery': 'example-delivery-1',
}, { secret });

console.log('github valid', result.valid, 'key', result.secretIndex);
