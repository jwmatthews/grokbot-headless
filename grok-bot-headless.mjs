#!/usr/bin/env node
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { execFileSync, fork } from 'node:child_process';
import { realpathSync } from 'node:fs';
import { access, chmod, copyFile, mkdir, open, readFile, rename, rm, stat, writeFile } from 'node:fs/promises';
import { homedir, hostname } from 'node:os';
import { dirname, join } from 'node:path';
import { pathToFileURL } from 'node:url';

// --- Configuration -----------------------------------------------------------

const CLI_NAME = 'grok-bot-headless';
const SERVICE_UNIT = 'grok-bot-headless.service';
const API_URL = validatedServiceUrl(
  process.env.SAND_BACKEND_URL || process.env.CURSOR_API_BASE_URL || 'https://api2.cursor.sh',
  'backend',
);
const WEBSITE_URL = validatedServiceUrl(
  process.env.SAND_CURSOR_WEBSITE_URL || process.env.CURSOR_WEBSITE_URL || 'https://cursor.com',
  'website',
);
const AUTH_CLIENT_ID = process.env.SAND_AUTH_CLIENT_ID || 'KbZUR41cY7W6zRSdpSUJ7I7mLYBKOCmB';
const CONFIG_DIR = process.env.GROK_BOT_HEADLESS_CONFIG_DIR || join(homedir(), '.config', 'grok-bot-headless');
const DATA_ROOT = process.env.SAND_DATA_ROOT || join(homedir(), '.local', 'share', 'grok-bot-headless');
const CREDENTIALS_PATH = join(CONFIG_DIR, 'credentials.json');
const MACHINE_PATH = join(CONFIG_DIR, 'machine.json');
const DAEMON_CREDENTIAL_PATH = join(DATA_ROOT, 'local-exec-daemon-credential.json');
const HEARTBEAT_PATH = join(DATA_ROOT, 'local-exec-supervisor.json');
const DISCOVERY_PATH = join(DATA_ROOT, 'local-exec-daemon.json');
const SETTINGS_PATH = join(DATA_ROOT, 'settings.json');
const APP_ASAR = process.env.GROK_BOT_APP_ASAR || '/opt/Grok Bot/resources/app.asar';
const DAEMON_SCRIPT_OVERRIDE = process.env.GROK_BOT_DAEMON_SCRIPT || null;
const PACKAGE_JSON_OVERRIDE = process.env.GROK_BOT_PACKAGE_JSON || null;
const RUNTIME_DIR = process.env.GROK_BOT_RUNTIME_DIR || join(homedir(), '.local', 'lib', 'grok-bot-headless', 'runtime');
const RUNTIME_SOURCE_PATH = join(RUNTIME_DIR, '.source.json');
// The daemon resolves its dependencies from ../deps, so both directories must stay siblings.
const RUNTIME_ARCHIVE_PATHS = Object.freeze(['package.json', 'dist/local-exec-daemon', 'dist/deps']);
const DAEMON_ARCHIVE_PATH = 'dist/local-exec-daemon/main.cjs';
const TESTED_CLIENT_VERSIONS = Object.freeze(['0.30.0']);
const POLICIES = Object.freeze(['always', 'ask', 'never']);
const TOKEN_REFRESH_MARGIN_MS = 5 * 60 * 1000;
const DESCRIPTOR_REFRESH_MS = 60 * 1000;
const HEARTBEAT_MS = 20 * 1000;
const DAEMON_RESTART_MS = 5 * 1000;
const DAEMON_STOP_GRACE_MS = 5 * 1000;
const LOGIN_POLL_ATTEMPTS = 150;
const LOGIN_POLL_MAX_MS = 10 * 1000;
const SUBPROCESS_TIMEOUT_MS = 20 * 1000;

function validatedServiceUrl(value, label) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`Invalid ${label} URL`);
  }
  if (parsed.username || parsed.password) {
    throw new Error(`${label} URL cannot contain credentials`);
  }
  const insecureLocalAllowed = process.env.GROK_BOT_ALLOW_INSECURE_LOCALHOST === '1'
    && parsed.protocol === 'http:'
    && ['localhost', '127.0.0.1', '[::1]'].includes(parsed.hostname);
  if (parsed.protocol !== 'https:' && !insecureLocalAllowed) {
    throw new Error(`${label} URL must use HTTPS`);
  }
  return parsed.href.replace(/\/+$/, '');
}

// --- Pure helpers ------------------------------------------------------------

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const formatJson = (value) => `${JSON.stringify(value, null, 2)}\n`;
const printJson = (value) => process.stdout.write(formatJson(value));
const base64url = (value) => Buffer.from(value).toString('base64url');

function describeError(error) {
  const messages = [];
  for (let current = error; current; current = current.cause) {
    messages.push(current.message || String(current));
  }
  return messages.join(': ');
}

function jwtPayload(token) {
  try {
    return JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
  } catch {
    return {};
  }
}

function accountScope(accessToken) {
  const payload = jwtPayload(accessToken);
  return createHash('sha256').update(payload.sub || accessToken).digest('hex');
}

function tokenExpiresSoon(accessToken) {
  const exp = Number(jwtPayload(accessToken).exp || 0) * 1000;
  return exp === 0 || exp - Date.now() < TOKEN_REFRESH_MARGIN_MS;
}

function cursorChecksum(machineId, nowMs = Date.now()) {
  // Keep JavaScript's 32-bit shift behavior. The official client and server use this exact transform.
  const epoch = Math.floor(nowMs / 1_000_000);
  const bytes = Buffer.from([
    (epoch >> 40) & 255,
    (epoch >> 32) & 255,
    (epoch >> 24) & 255,
    (epoch >> 16) & 255,
    (epoch >> 8) & 255,
    epoch & 255,
  ]);
  let previous = 165;
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = ((bytes[index] ^ previous) + index) & 255;
    previous = bytes[index];
  }
  return `${bytes.toString('base64url')}${machineId}`;
}

function isTestedClientVersion(version) {
  return TESTED_CLIENT_VERSIONS.includes(version);
}

function hasCredentialShape(credentials) {
  return typeof credentials?.accessToken === 'string'
    && credentials.accessToken.length > 0
    && typeof credentials?.refreshToken === 'string'
    && credentials.refreshToken.length > 0;
}

function oauthTokens(body) {
  return {
    accessToken: body.accessToken || body.access_token,
    refreshToken: body.refreshToken || body.refresh_token,
  };
}

function processAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

// --- Local files -------------------------------------------------------------

async function atomicJson(path, value) {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.${process.pid}.tmp`;
  await writeFile(temporary, formatJson(value), { mode: 0o600 });
  await chmod(temporary, 0o600);
  await rename(temporary, path);
}

async function readJson(path) {
  try {
    return JSON.parse(await readFile(path, 'utf8'));
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw new Error(`Cannot read ${path}`, { cause: error });
  }
}

async function machineIdentity() {
  const current = await readJson(MACHINE_PATH);
  if (typeof current?.machineId === 'string' && current.machineId.length > 0) return current;
  const created = { machineId: randomUUID(), label: hostname() };
  await atomicJson(MACHINE_PATH, created);
  return created;
}

async function saveCredentials(credentials) {
  const saved = { ...credentials, savedAtMs: Date.now() };
  await atomicJson(CREDENTIALS_PATH, saved);
  return saved;
}

async function loadCredentials() {
  const credentials = await readJson(CREDENTIALS_PATH);
  if (!hasCredentialShape(credentials)) {
    throw new Error(`No valid account credentials. Run: ${CLI_NAME} login`);
  }
  return refresh(credentials);
}

const heartbeat = () => atomicJson(HEARTBEAT_PATH, { pid: process.pid, at: Date.now() });

// --- Application archive -----------------------------------------------------
// Node cannot read files inside app.asar, and current Grok Bot builds disable the
// Electron RunAsNode fuse. The controller therefore copies the daemon and its
// dependencies out of the archive and runs them with the controller's own Node.

async function readAsarIndex(asarPath) {
  const handle = await open(asarPath, 'r');
  try {
    // Layout: u32 pickle size (4), u32 index pickle size, u32 payload size, u32 JSON length, JSON (padded to 4).
    const sizes = Buffer.alloc(16);
    await handle.read(sizes, 0, 16, 0);
    const indexPickleSize = sizes.readUInt32LE(4);
    const jsonLength = sizes.readUInt32LE(12);
    if (sizes.readUInt32LE(0) !== 4 || jsonLength === 0 || jsonLength > indexPickleSize) {
      throw new Error(`Not an asar archive: ${asarPath}`);
    }
    const json = Buffer.alloc(jsonLength);
    await handle.read(json, 0, jsonLength, 16);
    return { index: JSON.parse(json.toString('utf8')), dataOffset: 8 + indexPickleSize };
  } finally {
    await handle.close();
  }
}

function asarEntry(index, archivePath) {
  let entry = index;
  for (const segment of archivePath.split('/')) {
    entry = entry?.files?.[segment];
    if (!entry) throw new Error(`The application archive has no ${archivePath}`);
  }
  return entry;
}

async function extractAsar(asarPath, destination, archivePaths) {
  const { index, dataOffset } = await readAsarIndex(asarPath);
  const handle = await open(asarPath, 'r');
  const extractEntry = async (entry, archivePath) => {
    const target = join(destination, archivePath);
    if (entry.files) {
      await mkdir(target, { recursive: true, mode: 0o755 });
      for (const name of Object.keys(entry.files)) await extractEntry(entry.files[name], `${archivePath}/${name}`);
      return;
    }
    if (entry.link !== undefined) throw new Error(`Symbolic links in the application archive are not supported: ${archivePath}`);
    await mkdir(dirname(target), { recursive: true, mode: 0o755 });
    if (entry.unpacked) {
      await copyFile(join(`${asarPath}.unpacked`, archivePath), target);
    } else {
      const data = Buffer.alloc(entry.size);
      await handle.read(data, 0, entry.size, dataOffset + Number(entry.offset));
      await writeFile(target, data);
    }
    await chmod(target, entry.executable ? 0o755 : 0o644);
  };
  try {
    for (const archivePath of archivePaths) await extractEntry(asarEntry(index, archivePath), archivePath);
  } finally {
    await handle.close();
  }
}

async function readAsarJson(asarPath, archivePath) {
  const { index, dataOffset } = await readAsarIndex(asarPath);
  const entry = asarEntry(index, archivePath);
  const handle = await open(asarPath, 'r');
  try {
    const data = Buffer.alloc(entry.size);
    await handle.read(data, 0, entry.size, dataOffset + Number(entry.offset));
    return JSON.parse(data.toString('utf8'));
  } finally {
    await handle.close();
  }
}

async function archiveFingerprint() {
  const info = await stat(APP_ASAR).catch((error) => {
    throw new Error(`Cannot access the Grok Bot application archive: ${APP_ASAR}`, { cause: error });
  });
  return { asar: APP_ASAR, size: info.size, mtimeMs: info.mtimeMs };
}

async function ensureRuntime() {
  const source = await archiveFingerprint();
  const current = await readJson(RUNTIME_SOURCE_PATH).catch(() => null);
  if (current && current.asar === source.asar && current.size === source.size && current.mtimeMs === source.mtimeMs) {
    return;
  }
  const staging = `${RUNTIME_DIR}.${process.pid}.tmp`;
  await rm(staging, { recursive: true, force: true });
  try {
    await extractAsar(APP_ASAR, staging, RUNTIME_ARCHIVE_PATHS);
    await writeFile(join(staging, '.source.json'), formatJson({ ...source, extractedAtMs: Date.now() }));
    await rm(RUNTIME_DIR, { recursive: true, force: true });
    await mkdir(dirname(RUNTIME_DIR), { recursive: true, mode: 0o755 });
    await rename(staging, RUNTIME_DIR);
  } finally {
    await rm(staging, { recursive: true, force: true });
  }
}

// --- Official daemon ---------------------------------------------------------

let runtimeCache;
async function loadRuntime() {
  if (runtimeCache) return runtimeCache;
  let daemonScript;
  let packageJson;
  if (DAEMON_SCRIPT_OVERRIDE) {
    daemonScript = DAEMON_SCRIPT_OVERRIDE;
    await access(daemonScript).catch((error) => {
      throw new Error(`Cannot access the Grok Bot daemon script: ${daemonScript}`, { cause: error });
    });
    packageJson = PACKAGE_JSON_OVERRIDE ? await readJson(PACKAGE_JSON_OVERRIDE) : null;
  } else {
    await ensureRuntime();
    daemonScript = join(RUNTIME_DIR, DAEMON_ARCHIVE_PATH);
    packageJson = await readJson(PACKAGE_JSON_OVERRIDE || join(RUNTIME_DIR, 'package.json'));
  }
  const version = typeof packageJson?.version === 'string' && packageJson.version.length > 0 ? packageJson.version : null;
  runtimeCache = { daemonScript, version };
  return runtimeCache;
}

function clientVersion() {
  return process.env.SAND_CLIENT_APP_VERSION || runtimeCache?.version || TESTED_CLIENT_VERSIONS.at(-1);
}

async function installedVersion() {
  if (process.env.SAND_CLIENT_APP_VERSION) return process.env.SAND_CLIENT_APP_VERSION;
  if (DAEMON_SCRIPT_OVERRIDE) return (await loadRuntime()).version;
  return (await readAsarJson(APP_ASAR, 'package.json')).version;
}

// Loads the daemon entry point and its native modules in a child Node, the same way `run` does.
const DAEMON_PROBE = `
const fs = require('node:fs');
const path = require('node:path');
const script = process.argv[1];
require.resolve(script);
const deps = path.join(path.dirname(script), '..', 'deps');
if (fs.existsSync(deps)) {
  process.env.NODE_PATH = deps;
  require('node:module').Module._initPaths();
  require('tree-sitter');
  require('tree-sitter-bash');
}
`;

function probeDaemonEntry(daemonScript) {
  try {
    execFileSync(process.execPath, ['-e', DAEMON_PROBE, daemonScript], {
      encoding: 'utf8',
      stdio: ['ignore', 'ignore', 'pipe'],
      timeout: SUBPROCESS_TIMEOUT_MS,
    });
  } catch (error) {
    const detail = String(error.stderr || '').trim().split('\n').filter(Boolean).pop() || error.message;
    throw new Error(`The daemon entry point does not load in Node ${process.version}: ${detail}`);
  }
}

function spawnDaemon(daemonScript, machineId) {
  const child = fork(daemonScript, [], {
    env: {
      ...process.env,
      SAND_PACKAGED: '1',
      SAND_DATA_ROOT: DATA_ROOT,
      SAND_CLIENT_APP_VERSION: clientVersion(),
    },
    stdio: ['ignore', 'inherit', 'inherit', 'ipc'],
  });
  child.once('spawn', () => {
    child.send({ type: 'sand-local-exec-file-key', key: null, computerId: machineId });
  });
  return child;
}

async function terminate(child) {
  const exited = child.exitCode !== null || child.signalCode !== null
    ? Promise.resolve()
    : new Promise((resolve) => child.once('exit', resolve));
  const exitedWithin = (ms) => Promise.race([exited.then(() => true), sleep(ms).then(() => false)]);
  if (child.connected) child.disconnect();
  child.kill('SIGTERM');
  if (!(await exitedWithin(DAEMON_STOP_GRACE_MS))) {
    child.kill('SIGKILL');
    await exitedWithin(1000);
  }
}

// --- Backend protocol --------------------------------------------------------

function authHeaders(machineId, credentials) {
  const teamId = credentials.selectedTeamId;
  return {
    authorization: `Bearer ${credentials.accessToken}`,
    ...(teamId == null || teamId === '' ? {} : { 'x-cursor-team-id': String(teamId) }),
    'x-cursor-checksum': cursorChecksum(machineId),
    'x-cursor-client-type': 'sand',
    'x-cursor-client-version': clientVersion(),
    'x-sand-box-namespace': 'prod',
    'x-ghost-mode': 'true',
    'x-request-id': randomUUID(),
  };
}

async function responseJson(response, action) {
  const text = await response.text();
  let body;
  try {
    body = text.length > 0 ? JSON.parse(text) : {};
  } catch {
    throw new Error(`${action} returned HTTP ${response.status} with invalid JSON`);
  }
  if (!response.ok) {
    throw new Error(`${action} returned HTTP ${response.status}: ${body.message || body.error || text || 'unknown error'}`);
  }
  return body;
}

async function postJson(path, body, action, headers = {}) {
  const response = await fetch(`${API_URL}${path}`, {
    method: 'POST',
    headers: { ...headers, 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  return responseJson(response, action);
}

function connectUnary(service, method, request, credentials, machineId) {
  const headers = { ...authHeaders(machineId, credentials), 'connect-protocol-version': '1' };
  return postJson(`/${service}/${method}`, request, method, headers);
}

async function refresh(credentials) {
  if (!tokenExpiresSoon(credentials.accessToken)) return credentials;
  const body = await postJson('/oauth/token', {
    client_id: AUTH_CLIENT_ID,
    grant_type: 'refresh_token',
    refresh_token: credentials.refreshToken,
  }, 'OAuth refresh');
  if (body.shouldLogout) throw new Error('OAuth refresh requires a new sign-in');
  const tokens = oauthTokens(body);
  return saveCredentials({
    ...credentials,
    accessToken: tokens.accessToken || credentials.accessToken,
    refreshToken: tokens.refreshToken || credentials.refreshToken,
  });
}

async function mintDescriptor(identity, credentials) {
  const { machineId } = identity;
  const [daemon, computer] = await Promise.all([
    postJson('/sand-box/local-exec-daemon-credential', {}, 'Local daemon credential mint', authHeaders(machineId, credentials)),
    connectUnary('aiserver.v1.GrokBotService', 'IssueGrokBotUserComputerCredential', { machineId }, credentials, machineId),
  ]);
  if (!daemon.credential) throw new Error('Daemon credential mint returned no credential');
  if (!computer.credential) throw new Error('User-computer credential mint returned no credential');
  const descriptor = {
    credential: daemon.credential,
    backendUrl: API_URL,
    ...(typeof daemon.expiresAtMs === 'number' ? { expiresAtMs: daemon.expiresAtMs } : {}),
    userComputer: {
      credential: computer.credential,
      machineId,
      expiresAtMs: Number(computer.expiresAtMs),
      accountScope: accountScope(credentials.accessToken),
      serverAuthoritative: computer.serverAuthoritative === true,
    },
  };
  await atomicJson(DAEMON_CREDENTIAL_PATH, descriptor);
  return descriptor;
}

async function syncMachinePolicy(value, identity, credentials, connect = connectUnary) {
  await connect(
    'aiserver.v1.DashboardService',
    'RegisterSandMachine',
    { label: identity.label, localToolPermission: value },
    credentials,
    identity.machineId,
  );
  const response = await connect(
    'aiserver.v1.DashboardService',
    'UpdateSandMachineLocalToolPermission',
    { machineId: identity.machineId, localToolPermission: value },
    credentials,
    identity.machineId,
  );
  if (response.machine?.machineId !== identity.machineId) {
    throw new Error('Machine permission update returned an invalid machine');
  }
  if (response.machine.localToolPermission !== value) {
    throw new Error(`The backend limited the machine policy to ${response.machine.localToolPermission || 'ask'}`);
  }
  return response.machine;
}

// --- Commands ----------------------------------------------------------------

async function login() {
  const verifier = base64url(randomBytes(32));
  const challenge = base64url(createHash('sha256').update(verifier).digest());
  const uuid = randomUUID();
  const loginUrl = new URL('/loginDeepControl', WEBSITE_URL);
  loginUrl.search = new URLSearchParams({
    challenge,
    uuid,
    mode: 'login',
    redirectTarget: 'sand',
    supportsSelectedTeamLogin: 'true',
  });
  process.stdout.write(`Open this URL in any browser and complete sign-in:\n\n${loginUrl}\n\nWaiting for authorization...\n`);

  const pollUrl = new URL(`${API_URL}/auth/poll`);
  pollUrl.search = new URLSearchParams({ uuid, verifier });
  let delay = 1000;
  for (let attempt = 0; attempt < LOGIN_POLL_ATTEMPTS; attempt += 1) {
    const response = await fetch(pollUrl);
    if (response.status !== 404) {
      const body = await responseJson(response, 'OAuth poll');
      const tokens = oauthTokens(body);
      if (!tokens.accessToken || !tokens.refreshToken) {
        throw new Error('OAuth response did not contain access and refresh tokens');
      }
      await saveCredentials({
        ...tokens,
        ...(body.selectedTeamId == null ? {} : { selectedTeamId: body.selectedTeamId }),
      });
      process.stdout.write(`Account authorized for ${hostname()}.\n`);
      return;
    }
    await sleep(delay);
    delay = Math.min(Math.floor(delay * 1.2), LOGIN_POLL_MAX_MS);
  }
  throw new Error('OAuth sign-in timed out');
}

async function localCompatibility() {
  const runtime = await loadRuntime();
  probeDaemonEntry(runtime.daemonScript);
  const version = await installedVersion();
  if (!version) throw new Error('Cannot read the installed Grok Bot version');
  return {
    compatible: true,
    installedVersion: version,
    testedVersion: isTestedClientVersion(version),
    daemonEntryPoint: 'verified',
    daemonScript: runtime.daemonScript,
    nodeVersion: process.version,
  };
}

async function check(localOnly) {
  const report = await localCompatibility();
  if (!localOnly) await mintDescriptor(await machineIdentity(), await loadCredentials());
  printJson({ ...report, authentication: localOnly ? 'skipped' : 'verified' });
}

async function run() {
  const runtime = await loadRuntime();
  await mkdir(DATA_ROOT, { recursive: true, mode: 0o700 });
  const identity = await machineIdentity();
  let stopping = false;
  let daemon;

  const renewCredentials = async () => mintDescriptor(identity, await loadCredentials());

  const startDaemon = () => {
    const child = spawnDaemon(runtime.daemonScript, identity.machineId);
    child.on('exit', (code, signal) => {
      if (stopping) return;
      console.error(`local-exec daemon exited (${signal || code}); restarting in ${DAEMON_RESTART_MS / 1000} seconds`);
      setTimeout(() => {
        if (!stopping) daemon = startDaemon();
      }, DAEMON_RESTART_MS).unref();
    });
    return child;
  };

  const repeat = async (intervalMs, label, work) => {
    while (!stopping) {
      await sleep(intervalMs);
      if (stopping) return;
      await work().catch((error) => console.error(`${label}: ${describeError(error)}`));
    }
  };

  const stop = async (signal) => {
    if (stopping) return;
    stopping = true;
    await terminate(daemon);
    await rm(HEARTBEAT_PATH, { force: true });
    process.exit(signal === 'SIGINT' ? 130 : 0);
  };

  await renewCredentials();
  await heartbeat();
  daemon = startDaemon();
  void repeat(HEARTBEAT_MS, 'heartbeat', heartbeat);
  void repeat(DESCRIPTOR_REFRESH_MS, 'credential refresh', renewCredentials);
  process.on('SIGINT', () => void stop('SIGINT'));
  process.on('SIGTERM', () => void stop('SIGTERM'));
  process.stdout.write(`Native Grok Bot node started: ${identity.label} (${identity.machineId})\n`);
}

async function status() {
  const [identity, discovery, descriptor, settings] = await Promise.all(
    [MACHINE_PATH, DISCOVERY_PATH, DAEMON_CREDENTIAL_PATH, SETTINGS_PATH].map((path) => readJson(path)),
  );
  printJson({
    label: identity?.label || hostname(),
    machineId: identity?.machineId || null,
    daemonPid: discovery?.pid || null,
    daemonAlive: discovery?.pid ? processAlive(discovery.pid) : false,
    localToolPermission: settings?.localToolPermission || 'ask',
    credentialExpiresAtMs: descriptor?.userComputer?.expiresAtMs || descriptor?.expiresAtMs || null,
    dataRoot: DATA_ROOT,
  });
}

async function policy(value) {
  if (!POLICIES.includes(value)) {
    throw new Error(`Policy must be one of: ${POLICIES.join(', ')}`);
  }
  // The version header is informational here, so a missing application does not block the policy call.
  await loadRuntime().catch(() => null);
  const identity = await machineIdentity();
  const credentials = await loadCredentials();
  await syncMachinePolicy(value, identity, credentials);
  const current = await readJson(SETTINGS_PATH);
  await atomicJson(SETTINGS_PATH, {
    ...(current && typeof current === 'object' ? current : {}),
    version: 1,
    localToolPermission: value,
  });
  process.stdout.write(`Local and backend execution policy set to ${value}. Restart the service to apply it locally.\n`);
}

async function logout() {
  try {
    execFileSync('systemctl', ['--user', 'stop', SERVICE_UNIT], { stdio: 'ignore', timeout: SUBPROCESS_TIMEOUT_MS });
  } catch {
    // A direct run or an unavailable user service is handled by the process check below.
  }
  const discovery = await readJson(DISCOVERY_PATH);
  if (discovery?.pid && processAlive(discovery.pid)) {
    throw new Error('The local execution daemon is still active. Stop it before logout');
  }
  await Promise.all(
    [CREDENTIALS_PATH, DAEMON_CREDENTIAL_PATH, DISCOVERY_PATH, HEARTBEAT_PATH].map((path) => rm(path, { force: true })),
  );
  process.stdout.write('Local service stopped and credentials removed.\n');
}

// --- Entry point -------------------------------------------------------------

async function main(command, option) {
  switch (command) {
    case 'login': return login();
    case 'run': return run();
    case 'status': return status();
    case 'check':
      if (option !== undefined && option !== '--local') throw new Error(`Usage: ${CLI_NAME} check [--local]`);
      return check(option === '--local');
    case 'policy': return policy(option);
    case 'logout': return logout();
    default:
      process.stdout.write(`Usage: ${CLI_NAME} <login|run|status|check|policy|logout>\n`);
      process.exitCode = command === 'help' ? 0 : 2;
      return undefined;
  }
}

function isMainModule() {
  if (!process.argv[1]) return false;
  try {
    // import.meta.url is the real path; argv[1] can be a symlink (for example a symlinked $HOME).
    return import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href;
  } catch {
    return false;
  }
}

if (isMainModule()) {
  main(process.argv[2] || 'help', process.argv[3]).catch((error) => {
    console.error(`${CLI_NAME}: ${describeError(error)}`);
    process.exitCode = 1;
  });
}

export {
  accountScope,
  base64url,
  cursorChecksum,
  extractAsar,
  hasCredentialShape,
  isTestedClientVersion,
  jwtPayload,
  tokenExpiresSoon,
  syncMachinePolicy,
  validatedServiceUrl,
};
