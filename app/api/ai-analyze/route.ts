import { NextResponse } from 'next/server';
import { analyzeLocally } from '@/lib/ai/fallback';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const MAX_BODY_BYTES = 512 * 1024;
const UPSTREAM_TIMEOUT_MS = 3_000;

interface AiRequestBody {
  content: string;
  context?: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function parseBody(value: unknown): AiRequestBody | null {
  if (!isRecord(value) || typeof value.content !== 'string' || value.content.trim().length === 0) {
    return null;
  }

  return {
    content: value.content,
    context: typeof value.context === 'string' ? value.context.slice(0, 8_000) : undefined,
  };
}

function buildUpstreamUrl(baseUrl: string): string {
  const normalized = baseUrl.replace(/\/+$/, '');
  return /\/chat\/completions$/i.test(normalized)
    ? normalized
    : `${normalized}/chat/completions`;
}

function upstreamHeaders(apiKey: string): HeadersInit {
  return {
    authorization: `Bearer ${apiKey}`,
    'content-type': 'application/json',
    accept: 'text/event-stream',
  };
}

export async function POST(request: Request): Promise<Response> {
  let body: AiRequestBody | null = null;

  try {
    const rawBody = await request.text();
    if (Buffer.byteLength(rawBody, 'utf8') > MAX_BODY_BYTES) {
      return NextResponse.json({ error: 'Payload Too Large.' }, { status: 413 });
    }
    body = parseBody(JSON.parse(rawBody) as unknown);
  } catch {
    return NextResponse.json({ error: 'Bad Request: invalid JSON body.' }, { status: 400 });
  }

  if (!body) {
    return NextResponse.json(
      { error: 'Bad Request: "content" must be a non-empty string.' },
      { status: 400 }
    );
  }

  const apiKey = process.env.AI_API_KEY?.trim();
  const baseUrl = process.env.AI_BASE_URL?.trim();
  const model = process.env.AI_MODEL?.trim();

  // Offline-first behavior is intentional: no configured provider means no
  // network attempt and an immediate deterministic result.
  if (!apiKey || !baseUrl || !model) {
    return NextResponse.json(
      { success: true, provider: 'offline', analysis: analyzeLocally(body.content) },
      { headers: { 'cache-control': 'no-store', 'x-aegis-analysis-mode': 'offline' } }
    );
  }

  const prompt = [
    'Analyze this source for credential exposure and security risk.',
    'Do not repeat, quote, or transform any secret-like token in your response.',
    'Return concise Markdown with: verdict, key risks, and remediation steps.',
    body.context ? `Additional context: ${body.context}` : '',
    'Source follows:',
    body.content,
  ].filter(Boolean).join('\n\n');

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);

  try {
    const upstream = await fetch(buildUpstreamUrl(baseUrl), {
      method: 'POST',
      headers: upstreamHeaders(apiKey),
      body: JSON.stringify({
        model,
        stream: true,
        temperature: 0,
        messages: [
          {
            role: 'system',
            content: 'You are Aegis, a security reviewer. Never disclose secrets found in input.',
          },
          { role: 'user', content: prompt },
        ],
      }),
      signal: controller.signal,
    });

    if (!upstream.ok || !upstream.body) {
      return NextResponse.json(
        { success: true, provider: 'offline', analysis: analyzeLocally(body.content) },
        { headers: { 'cache-control': 'no-store', 'x-aegis-analysis-mode': 'offline' } }
      );
    }

    const wantsStream = request.headers.get('accept')?.includes('text/event-stream') ?? false;
    if (wantsStream) {
      return new Response(upstream.body, {
        status: 200,
        headers: {
          'cache-control': 'no-store',
          'content-type': upstream.headers.get('content-type') ?? 'text/event-stream',
          'x-aegis-analysis-mode': 'upstream',
        },
      });
    }

    // Non-streaming callers receive the upstream stream buffered server-side;
    // the credential remains confined to this route in either mode.
    const text = await upstream.text();
    return NextResponse.json(
      { success: true, provider: 'upstream', analysis: text },
      { headers: { 'cache-control': 'no-store', 'x-aegis-analysis-mode': 'upstream' } }
    );
  } catch {
    return NextResponse.json(
      { success: true, provider: 'offline', analysis: analyzeLocally(body.content) },
      { headers: { 'cache-control': 'no-store', 'x-aegis-analysis-mode': 'offline' } }
    );
  } finally {
    clearTimeout(timeoutId);
  }
}
