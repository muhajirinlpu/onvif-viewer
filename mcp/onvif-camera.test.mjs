import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { requestSnapshot } from './onvif-camera.mjs';

const serverPath = fileURLToPath(new URL('./onvif-camera.mjs', import.meta.url));

async function startMcpServer() {
  const child = spawn(process.execPath, [serverPath], { stdio: ['pipe', 'pipe', 'pipe'] });
  const lines = [];
  child.stdout.setEncoding('utf8');
  child.stdout.on('data', (chunk) => lines.push(...chunk.split('\n').filter(Boolean)));
  child.stdin.write(`${JSON.stringify({
    jsonrpc: '2.0', id: 1, method: 'initialize',
    params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'test', version: '1' } },
  })}\n`);
  await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('MCP server did not initialize')), 5_000);
    const poll = setInterval(() => {
      if (lines.length > 0) {
        clearTimeout(timeout);
        clearInterval(poll);
        resolve();
      }
    }, 10);
    child.once('error', reject);
  });
  return { child, lines };
}

test('MCP executable starts and advertises get_current_picture', async (t) => {
  const { child, lines } = await startMcpServer();
  t.after(async () => {
    child.kill('SIGTERM');
    await once(child, 'exit');
  });

  child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized', params: {} })}\n`);
  child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} })}\n`);
  await new Promise((resolve) => setTimeout(resolve, 100));
  assert.match(lines.join('\n'), /get_current_picture/);
});

test('requestSnapshot fetches the active stream then returns JPEG bytes', async () => {
  const calls = [];
  const fetchImpl = async (url) => {
    calls.push(url);
    if (url === 'http://viewer/api/stream/list') {
      return new Response(JSON.stringify([{ id: 'stream_7', status: 'running' }]), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }
    if (url === 'http://viewer/api/stream/snapshot?id=stream_7') {
      return new Response(new Uint8Array([0xff, 0xd8, 0xff, 0xd9]), {
        status: 200,
        headers: { 'content-type': 'image/jpeg' },
      });
    }
    return new Response('not found', { status: 404 });
  };

  const snapshot = await requestSnapshot({ baseURL: 'http://viewer', fetchImpl });
  assert.equal(snapshot.streamID, 'stream_7');
  assert.equal(snapshot.mimeType, 'image/jpeg');
  assert.deepEqual([...snapshot.bytes], [0xff, 0xd8, 0xff, 0xd9]);
  assert.deepEqual(calls, ['http://viewer/api/stream/list', 'http://viewer/api/stream/snapshot?id=stream_7']);
});

test('requestSnapshot uses ONVIF_VIEWER_URL when no base URL is supplied', async () => {
  const oldBaseURL = process.env.ONVIF_VIEWER_URL;
  process.env.ONVIF_VIEWER_URL = 'http://configured';
  const calls = [];
  const fetchImpl = async (url) => {
    calls.push(url);
    if (url === 'http://configured/api/stream/list') {
      return new Response(JSON.stringify([{ id: 'stream_3', status: 'running' }]), { status: 200 });
    }
    return new Response(new Uint8Array([0xff, 0xd8]), { status: 200, headers: { 'content-type': 'image/jpeg' } });
  };
  await requestSnapshot({ fetchImpl });
  if (oldBaseURL === undefined) delete process.env.ONVIF_VIEWER_URL;
  else process.env.ONVIF_VIEWER_URL = oldBaseURL;
  assert.deepEqual(calls, ['http://configured/api/stream/list', 'http://configured/api/stream/snapshot?id=stream_3']);
});

test('requestSnapshot refuses a non-running selected stream', async () => {
  const fetchImpl = async () => new Response(JSON.stringify([{ id: 'old', status: 'failed' }]), {
    status: 200, headers: { 'content-type': 'application/json' },
  });
  await assert.rejects(requestSnapshot({ baseURL: 'http://viewer', streamID: 'old', fetchImpl }), /not active/);
});
