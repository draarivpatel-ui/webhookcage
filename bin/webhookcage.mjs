#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { signWebhook, validateDeliveryUrl, verifyWebhook, WebhookCageError } from '../src/index.mjs';

function usage() {
  return [
    'usage:',
    '  webhookcage sign <provider> (--secret VALUE | --secret-env NAME) [--body TEXT | --body-file PATH] [--timestamp SECONDS] [--message-id ID]',
    '  webhookcage verify <provider> (--secret VALUE | --secret-env NAME) [--body TEXT | --body-file PATH] --header "Name: value" [--header ...] [--timestamp-now-ms MS]',
    '  webhookcage check-url <url> [--allow-http] [--allow-any-port]',
    '  webhookcage --version',
  ].join('\n');
}

function parse(argv) {
  const out = { headers: [] };
  const positional = [];
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (!arg.startsWith('--')) {
      positional.push(arg);
      continue;
    }
    const key = arg.slice(2);
    if (key === 'allow-http' || key === 'allow-any-port') {
      out[key] = true;
      continue;
    }
    index += 1;
    if (index >= argv.length) throw new Error(`missing value for --${key}`);
    if (key === 'header') out.headers.push(argv[index]);
    else out[key] = argv[index];
  }
  out.positional = positional;
  return out;
}

function readBody(args) {
  if (args.body !== undefined && args['body-file'] !== undefined) throw new Error('pass either --body or --body-file, not both');
  if (args['body-file'] !== undefined) return readFileSync(args['body-file']);
  return args.body === undefined ? '' : args.body;
}

function readSecret(args) {
  if (args.secret !== undefined && args['secret-env'] !== undefined) throw new Error('pass either --secret or --secret-env, not both');
  if (args['secret-env'] !== undefined) {
    const value = process.env[args['secret-env']];
    if (value === undefined) throw new Error(`environment variable ${args['secret-env']} is not set`);
    return value;
  }
  if (args.secret === undefined) throw new Error('a secret is required');
  return args.secret;
}

function parseHeader(line) {
  const colon = line.indexOf(':');
  if (colon < 1) throw new Error('headers must use the form Name: value');
  return [line.slice(0, colon).trim(), line.slice(colon + 1).trimStart()];
}

function emit(value) {
  process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
}

function main(argv) {
  if (argv.length === 1 && argv[0] === '--version') {
    process.stdout.write('webhookcage 1.0.0\n');
    return 0;
  }
  if (argv.length === 0) {
    process.stderr.write(`${usage()}\n`);
    return 2;
  }
  const args = parse(argv.slice(1));
  const command = argv[0];
  if (command === 'sign' || command === 'verify') {
    const provider = args.positional[0];
    if (!provider) throw new Error(`missing provider\n${usage()}`);
    const body = readBody(args);
    const secret = readSecret(args);
    if (command === 'sign') {
      const signed = signWebhook(provider, body, secret, {
        timestamp: args.timestamp === undefined ? undefined : Number(args.timestamp),
        messageId: args['message-id'],
      });
      emit({ ok: true, signature: signed });
      return 0;
    }
    const headers = {};
    for (const line of args.headers) {
      const [name, value] = parseHeader(line);
      headers[name] = value;
    }
    const result = verifyWebhook(provider, body, headers, {
      secret,
      now: args['timestamp-now-ms'] === undefined ? undefined : Number(args['timestamp-now-ms']),
    });
    emit({ ok: true, provider: result.provider, secretIndex: result.secretIndex, timestamp: result.timestamp });
    return 0;
  }
  if (command === 'check-url') {
    const url = args.positional[0];
    if (!url) throw new Error(`missing URL\n${usage()}`);
    const options = {};
    if (args['allow-http']) options.allowedSchemes = ['https:', 'http:'];
    if (args['allow-any-port']) options.allowedPorts = 'any';
    const result = validateDeliveryUrl(url, options);
    emit(result.ok ? { ok: true, normalized: result.normalized, hostname: result.hostname, port: result.port } : result);
    return result.ok ? 0 : 1;
  }
  throw new Error(`unknown command ${command}\n${usage()}`);
}

try {
  process.exitCode = main(process.argv.slice(2));
} catch (error) {
  if (error instanceof WebhookCageError) {
    emit({ ok: false, code: error.code, message: error.reason });
    process.exitCode = 1;
  } else {
    process.stderr.write(`${error && error.message ? error.message : String(error)}\n`);
    process.exitCode = 2;
  }
}
