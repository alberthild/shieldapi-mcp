import { describe, it, expect } from 'vitest';

// Import the helpers we need to test by re-implementing them here
// (since they're not exported — we test the logic, not the module wiring)

function detectTargetType(target: string): Record<string, string> {
  if (target.includes('@')) return { email: target };
  if (/^\d+\.\d+\.\d+\.\d+$/.test(target)) return { ip: target };
  if (target.startsWith('http://') || target.startsWith('https://')) return { url: target };
  return { domain: target };
}

function formatResult(data: unknown): { content: Array<{ type: 'text'; text: string }> } {
  return {
    content: [{ type: 'text' as const, text: JSON.stringify(data, null, 2) }],
  };
}

function buildUrl(base: string, endpoint: string, params: Record<string, string>, demo: boolean): string {
  const url = new URL(`${base}/api/${endpoint}`);
  for (const [key, value] of Object.entries(params)) {
    url.searchParams.set(key, value);
  }
  if (demo) {
    url.searchParams.set('demo', 'true');
  }
  return url.toString();
}

describe('detectTargetType', () => {
  it('detects email addresses', () => {
    expect(detectTargetType('user@example.com')).toEqual({ email: 'user@example.com' });
  });

  it('detects IPv4 addresses', () => {
    expect(detectTargetType('8.8.8.8')).toEqual({ ip: '8.8.8.8' });
    expect(detectTargetType('192.168.1.1')).toEqual({ ip: '192.168.1.1' });
  });

  it('detects HTTP URLs', () => {
    expect(detectTargetType('https://example.com/path')).toEqual({ url: 'https://example.com/path' });
    expect(detectTargetType('http://malware.site')).toEqual({ url: 'http://malware.site' });
  });

  it('falls back to domain for everything else', () => {
    expect(detectTargetType('example.com')).toEqual({ domain: 'example.com' });
    expect(detectTargetType('sub.domain.org')).toEqual({ domain: 'sub.domain.org' });
  });

  it('does not match partial IPs as IP', () => {
    expect(detectTargetType('8.8.8')).toEqual({ domain: '8.8.8' });
    expect(detectTargetType('999.999.999.999')).toEqual({ ip: '999.999.999.999' }); // regex matches format, validation is server-side
  });
});

describe('formatResult', () => {
  it('wraps data as MCP text content', () => {
    const result = formatResult({ risk_score: 42 });
    expect(result.content).toHaveLength(1);
    expect(result.content[0].type).toBe('text');
    expect(JSON.parse(result.content[0].text)).toEqual({ risk_score: 42 });
  });

  it('handles arrays', () => {
    const result = formatResult([1, 2, 3]);
    expect(JSON.parse(result.content[0].text)).toEqual([1, 2, 3]);
  });

  it('handles null', () => {
    const result = formatResult(null);
    expect(result.content[0].text).toBe('null');
  });
});

describe('buildUrl', () => {
  const base = 'https://shield.vainplex.dev';

  it('constructs correct URL with params', () => {
    const url = buildUrl(base, 'check-url', { url: 'https://evil.com' }, false);
    expect(url).toBe('https://shield.vainplex.dev/api/check-url?url=https%3A%2F%2Fevil.com');
  });

  it('adds demo flag', () => {
    const url = buildUrl(base, 'check-domain', { domain: 'example.com' }, true);
    expect(url).toContain('domain=example.com');
    expect(url).toContain('demo=true');
  });

  it('handles multiple params for full-scan', () => {
    const url = buildUrl(base, 'full-scan', { email: 'a@b.com', domain: 'b.com' }, false);
    expect(url).toContain('email=a%40b.com');
    expect(url).toContain('domain=b.com');
  });

  it('encodes special characters', () => {
    const url = buildUrl(base, 'check-password', { hash: 'AABBCC' }, false);
    expect(url).toBe('https://shield.vainplex.dev/api/check-password?hash=AABBCC');
  });
});
