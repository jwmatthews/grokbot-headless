import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  accountScope,
  base64url,
  cursorChecksum,
  extractAsar,
  hasCredentialShape,
  isTestedClientVersion,
  jwtPayload,
  syncMachinePolicy,
  tokenExpiresSoon,
  validatedServiceUrl,
} from '../grok-bot-headless.mjs';

test('service URLs require HTTPS, drop trailing slashes, and reject embedded credentials', () => {
  assert.equal(validatedServiceUrl('https://api.example.test///', 'backend'), 'https://api.example.test');
  assert.throws(
    () => validatedServiceUrl('http://api.example.test', 'backend'),
    /backend URL must use HTTPS/,
  );
  assert.throws(
    () => validatedServiceUrl('https://user:secret@api.example.test', 'backend'),
    /backend URL cannot contain credentials/,
  );
});

test('plain HTTP is allowed for loopback hosts only with the explicit opt-in', () => {
  assert.throws(() => validatedServiceUrl('http://127.0.0.1:8080', 'backend'), /must use HTTPS/);
  process.env.GROK_BOT_ALLOW_INSECURE_LOCALHOST = '1';
  try {
    assert.equal(validatedServiceUrl('http://localhost:8080/', 'backend'), 'http://localhost:8080');
    assert.equal(validatedServiceUrl('http://127.0.0.1:8080', 'backend'), 'http://127.0.0.1:8080');
    assert.equal(validatedServiceUrl('http://[::1]:8080', 'backend'), 'http://[::1]:8080');
    assert.throws(() => validatedServiceUrl('http://api.example.test', 'backend'), /must use HTTPS/);
  } finally {
    delete process.env.GROK_BOT_ALLOW_INSECURE_LOCALHOST;
  }
});

test('access tokens expire soon inside the refresh margin or without an exp claim', () => {
  const token = (payload) => `header.${base64url(JSON.stringify(payload))}.signature`;
  const nowSeconds = Math.floor(Date.now() / 1000);
  assert.equal(tokenExpiresSoon(token({ exp: nowSeconds + 3600 })), false);
  assert.equal(tokenExpiresSoon(token({ exp: nowSeconds + 60 })), true);
  assert.equal(tokenExpiresSoon(token({ exp: nowSeconds - 60 })), true);
  assert.equal(tokenExpiresSoon(token({})), true);
  assert.equal(tokenExpiresSoon('not-a-jwt'), true);
});

test('base64url uses URL-safe encoding without padding', () => {
  assert.equal(base64url(Buffer.from([251, 255, 239])), '-__v');
});

test('cursorChecksum matches the Grok Bot byte transform', () => {
  assert.equal(cursorChecksum('machine-123', 1_788_370_000_000), '7D9BXRjPmachine-123');
});

test('compatibility metadata identifies tested client versions', () => {
  assert.equal(isTestedClientVersion('0.30.0'), true);
  assert.equal(isTestedClientVersion('99.0.0'), false);
});

test('credential validation requires both non-empty tokens', () => {
  assert.equal(hasCredentialShape({ accessToken: 'access', refreshToken: 'refresh' }), true);
  assert.equal(hasCredentialShape({ accessToken: 'access' }), false);
  assert.equal(hasCredentialShape({ accessToken: '', refreshToken: 'refresh' }), false);
  assert.equal(hasCredentialShape(null), false);
});

test('JWT payload and account scope use the token subject', () => {
  const payload = base64url(JSON.stringify({ sub: 'user-123', email: 'person@example.test' }));
  const token = `header.${payload}.signature`;
  assert.deepEqual(jwtPayload(token), { sub: 'user-123', email: 'person@example.test' });
  assert.equal(accountScope(token), 'fcdec6df4d44dbc637c7c5b58efface52a7f8a88535423430255be0bb89bedd8');
});

test('machine policy registers the machine before updating its backend permission', async () => {
  const calls = [];
  const identity = { machineId: 'machine-123', label: 'build-host' };
  const credentials = { accessToken: 'access', refreshToken: 'refresh' };
  const connect = async (service, method, request, receivedCredentials, machineId) => {
    calls.push({ service, method, request, receivedCredentials, machineId });
    return method === 'UpdateSandMachineLocalToolPermission'
      ? { machine: { machineId, label: identity.label, localToolPermission: 'always' } }
      : {};
  };

  const machine = await syncMachinePolicy('always', identity, credentials, connect);

  assert.equal(machine.localToolPermission, 'always');
  assert.deepEqual(calls.map(({ method }) => method), [
    'RegisterSandMachine',
    'UpdateSandMachineLocalToolPermission',
  ]);
  assert.deepEqual(calls[0].request, { label: 'build-host', localToolPermission: 'always' });
  assert.deepEqual(calls[1].request, { machineId: 'machine-123', localToolPermission: 'always' });
  assert.ok(calls.every(({ service }) => service === 'aiserver.v1.DashboardService'));
});

test('machine policy rejects a backend permission ceiling', async () => {
  const connect = async (_service, method) => (
    method === 'UpdateSandMachineLocalToolPermission'
      ? { machine: { machineId: 'machine-123', localToolPermission: 'ask' } }
      : {}
  );
  await assert.rejects(
    syncMachinePolicy(
      'always',
      { machineId: 'machine-123', label: 'build-host' },
      { accessToken: 'access', refreshToken: 'refresh' },
      connect,
    ),
    /backend limited the machine policy to ask/,
  );
});

// Builds an archive the same way @electron/asar does: a size pickle, an index pickle, then file data.
function buildAsar(asarPath, files) {
  const index = { files: {} };
  const chunks = [];
  let offset = 0;
  for (const [archivePath, file] of Object.entries(files)) {
    const segments = archivePath.split('/');
    let directory = index;
    for (const segment of segments.slice(0, -1)) {
      directory = directory.files[segment] ??= { files: {} };
    }
    const content = Buffer.from(file.content);
    const entry = { size: content.length };
    if (file.executable) entry.executable = true;
    if (file.unpacked) {
      entry.unpacked = true;
      const unpackedPath = join(`${asarPath}.unpacked`, archivePath);
      mkdirSync(dirname(unpackedPath), { recursive: true });
      writeFileSync(unpackedPath, content);
    } else {
      entry.offset = String(offset);
      chunks.push(content);
      offset += content.length;
    }
    directory.files[segments.at(-1)] = entry;
  }
  const json = Buffer.from(JSON.stringify(index));
  const padded = Math.ceil(json.length / 4) * 4;
  const header = Buffer.alloc(16 + padded);
  header.writeUInt32LE(4, 0);
  header.writeUInt32LE(8 + padded, 4);
  header.writeUInt32LE(4 + padded, 8);
  header.writeUInt32LE(json.length, 12);
  json.copy(header, 16);
  writeFileSync(asarPath, Buffer.concat([header, ...chunks]));
}

test('extractAsar copies selected archive paths, unpacked files, and executable bits', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'grok-bot-headless-asar-'));
  try {
    const asarPath = join(directory, 'app.asar');
    buildAsar(asarPath, {
      'package.json': { content: '{"version":"1.2.3"}' },
      'dist/local-exec-daemon/main.cjs': { content: 'module.exports = "daemon";' },
      'dist/local-exec-daemon/messages-worker.cjs': { content: 'worker', executable: true },
      'dist/deps/tree-sitter/build/Release/binding.node': { content: 'native', unpacked: true },
      'dist/renderer/index.html': { content: '<html>' },
    });
    const destination = join(directory, 'runtime');
    await extractAsar(asarPath, destination, ['package.json', 'dist/local-exec-daemon', 'dist/deps']);
    const read = (path) => readFileSync(join(destination, path), 'utf8');
    assert.equal(read('package.json'), '{"version":"1.2.3"}');
    assert.equal(read('dist/local-exec-daemon/main.cjs'), 'module.exports = "daemon";');
    assert.equal(read('dist/local-exec-daemon/messages-worker.cjs'), 'worker');
    assert.equal(read('dist/deps/tree-sitter/build/Release/binding.node'), 'native');
    assert.equal(statSync(join(destination, 'dist/local-exec-daemon/messages-worker.cjs')).mode & 0o777, 0o755);
    assert.equal(statSync(join(destination, 'dist/local-exec-daemon/main.cjs')).mode & 0o777, 0o644);
    assert.throws(() => statSync(join(destination, 'dist/renderer')), /ENOENT/, 'unselected paths stay in the archive');
    await assert.rejects(extractAsar(asarPath, destination, ['dist/missing']), /has no dist\/missing/);
    await assert.rejects(extractAsar(join(destination, 'package.json'), destination, ['package.json']), /Not an asar archive/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('the CLI runs when its path contains a symlink', () => {
  const directory = mkdtempSync(join(tmpdir(), 'grok-bot-headless-'));
  try {
    const link = join(directory, 'grok-bot-headless.mjs');
    symlinkSync(fileURLToPath(new URL('../grok-bot-headless.mjs', import.meta.url)), link);
    const output = execFileSync(process.execPath, [link, 'help'], { encoding: 'utf8' });
    assert.match(output, /^Usage: grok-bot-headless/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
