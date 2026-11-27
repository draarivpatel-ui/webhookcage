// Provider dispatch and replay recording.
import { WebhookCageError } from './errors.mjs';
import { providerSigners, providerVerifiers } from './providers.mjs';
import { recordDelivery } from './replay.mjs';

function own(source, key) {
  return source && typeof source === 'object' && Object.hasOwn(source, key) ? source[key] : undefined;
}

function providerName(provider) {
  if (typeof provider !== 'string') throw new WebhookCageError('INVALID_ARGUMENT', 'provider must be a string');
  const name = provider.trim().toLowerCase();
  if (!Object.hasOwn(providerVerifiers, name)) throw new WebhookCageError('UNKNOWN_PROVIDER', `unknown webhook provider ${provider}`, { provider });
  return name;
}

export function listProviders() {
  return Object.freeze(Object.keys(providerVerifiers).sort());
}

export function verifyWebhook(provider, body, headers, options) {
  const name = providerName(provider);
  const opts = options && typeof options === 'object' ? options : {};
  const result = providerVerifiers[name](body, headers, opts);
  const store = own(opts, 'replayStore');
  const requireReplay = own(opts, 'requireReplay') === true;
  if (requireReplay && result.replayKey === null) {
    throw new WebhookCageError('INVALID_HEADER', 'provider did not supply a delivery identifier for replay protection');
  }
  let replayProtected = false;
  if (store !== undefined && result.replayKey !== null) {
    recordDelivery(store, result.replayKey);
    replayProtected = true;
  }
  return Object.freeze({ ...result, replayProtected });
}

export function signWebhook(provider, body, secret, options) {
  const name = providerName(provider);
  const signer = providerSigners[name];
  if (name === 'stripe' || name === 'slack') return signer(body, secret, own(options, 'timestamp'));
  if (name === 'standard-webhooks') return signer(body, secret, own(options, 'messageId'), own(options, 'timestamp'));
  return signer(body, secret);
}

export function createVerifier(provider, defaultOptions) {
  const name = providerName(provider);
  const defaults = defaultOptions && typeof defaultOptions === 'object' ? Object.freeze({ ...defaultOptions }) : Object.freeze({});
  return Object.freeze({
    provider: name,
    verify(body, headers, options) {
      const merged = { ...defaults };
      if (options && typeof options === 'object') {
        for (const key of Object.keys(options)) merged[key] = options[key];
      }
      return verifyWebhook(name, body, headers, merged);
    },
  });
}
