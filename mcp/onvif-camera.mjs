import { fileURLToPath } from 'node:url';

const DEFAULT_BASE_URL = 'http://127.0.0.1:7878';

function viewerBaseURL() {
  return process.env.ONVIF_VIEWER_URL || DEFAULT_BASE_URL;
}

function normalizedBaseURL(baseURL) {
  return (baseURL || viewerBaseURL()).replace(/\/+$/, '');
}

async function checkedFetch(fetchImpl, url) {
  const response = await fetchImpl(url, { signal: AbortSignal.timeout(20_000) });
  if (!response.ok) {
    const body = await response.text().catch(() => '');
    throw new Error(`ONVIF Viewer returned HTTP ${response.status}${body ? `: ${body}` : ''}`);
  }
  return response;
}

// requestSnapshot captures the newest available JPEG from a running HLS stream.
export async function requestSnapshot({ baseURL, streamID, fetchImpl = fetch } = {}) {
  const root = normalizedBaseURL(baseURL);
  const streamsResponse = await checkedFetch(fetchImpl, `${root}/api/stream/list`);
  const streams = await streamsResponse.json();
  if (!Array.isArray(streams)) {
    throw new Error('ONVIF Viewer returned an invalid stream list');
  }

  const selected = streamID
    ? streams.find((stream) => stream.id === streamID)
    : streams.find((stream) => stream.status === 'running');
  if (!selected) {
    throw new Error(streamID ? `stream ${streamID} was not found` : 'no running camera stream is available');
  }
  if (selected.status !== 'running') {
    throw new Error(`stream ${selected.id} is not active (status: ${selected.status})`);
  }

  const snapshotResponse = await checkedFetch(
    fetchImpl,
    `${root}/api/stream/snapshot?id=${encodeURIComponent(selected.id)}`,
  );
  const mimeType = snapshotResponse.headers.get('content-type')?.split(';')[0] || 'image/jpeg';
  if (mimeType !== 'image/jpeg') {
    throw new Error(`expected JPEG snapshot, received ${mimeType}`);
  }
  const bytes = new Uint8Array(await snapshotResponse.arrayBuffer());
  if (bytes.byteLength === 0) {
    throw new Error('ONVIF Viewer returned an empty snapshot');
  }

  return { streamID: selected.id, mimeType, bytes };
}

export async function startServer() {
  const { McpServer } = await import('@modelcontextprotocol/sdk/server/mcp.js');
  const { StdioServerTransport } = await import('@modelcontextprotocol/sdk/server/stdio.js');
  const { z } = await import('zod');

  const server = new McpServer({ name: 'onvif-camera', version: '0.1.0' });
  server.registerTool(
    'get_current_picture',
    {
      title: 'Get current camera picture',
      description: 'Captures the newest JPEG from the ONVIF Viewer active camera stream. Use the returned image to answer visual questions or send it to the user.',
      inputSchema: {
        stream_id: z.string().min(1).optional().describe('Optional active stream ID. Defaults to the first running stream.'),
      },
    },
    async ({ stream_id: streamID }) => {
      try {
        const snapshot = await requestSnapshot({ streamID });
        return {
          content: [
            { type: 'text', text: `Current picture captured from ${snapshot.streamID}.` },
            { type: 'image', data: Buffer.from(snapshot.bytes).toString('base64'), mimeType: snapshot.mimeType },
          ],
        };
      } catch (error) {
        return {
          content: [{ type: 'text', text: `Unable to capture camera picture: ${error.message}` }],
          isError: true,
        };
      }
    },
  );

  await server.connect(new StdioServerTransport());
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  startServer().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}

export { DEFAULT_BASE_URL };
