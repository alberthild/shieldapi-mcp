#!/usr/bin/env node
/**
 * ShieldAPI MCP Server
 *
 * Exposes ShieldAPI security intelligence as native MCP tools.
 * Handles x402 USDC micropayments automatically, with demo fallback.
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

const {
  SHIELDAPI_URL = 'https://shield.vainplex.dev',
  SHIELDAPI_WALLET_PRIVATE_KEY,
} = process.env;

const demoMode = !SHIELDAPI_WALLET_PRIVATE_KEY;

// --- Tool definitions (single source of truth) ---

interface ToolDef {
  description: string;
  param: string;
  paramDesc: string;
  endpoint: string;
}

const TOOLS: Record<string, ToolDef> = {
  check_url: {
    description: 'Check a URL for malware, phishing, and other threats. Uses URLhaus + heuristic analysis.',
    param: 'url',
    paramDesc: 'The URL to check (e.g. https://example.com)',
    endpoint: 'check-url',
  },
  check_password: {
    description: 'Check if a password hash (SHA-1) has been exposed in known data breaches via HIBP.',
    param: 'hash',
    paramDesc: 'SHA-1 hash of the password (40 hex chars)',
    endpoint: 'check-password',
  },
  check_password_range: {
    description: 'Look up a SHA-1 hash prefix in the HIBP k-Anonymity database.',
    param: 'prefix',
    paramDesc: 'First 5 characters of the SHA-1 password hash',
    endpoint: 'check-password-range',
  },
  check_domain: {
    description: 'Check domain reputation: DNS records, blacklists (Spamhaus, SpamCop, SORBS), SPF/DMARC, SSL.',
    param: 'domain',
    paramDesc: 'Domain name to check (e.g. example.com)',
    endpoint: 'check-domain',
  },
  check_ip: {
    description: 'Check IP reputation: blacklists, Tor exit node detection, reverse DNS.',
    param: 'ip',
    paramDesc: 'IPv4 address to check (e.g. 8.8.8.8)',
    endpoint: 'check-ip',
  },
  check_email: {
    description: 'Check if an email address has been exposed in known data breaches via HIBP.',
    param: 'email',
    paramDesc: 'Email address to check',
    endpoint: 'check-email',
  },
};

// --- x402 payment setup (lazy, only if wallet configured) ---

let paymentFetch: typeof fetch = fetch;

async function initPaymentFetch(): Promise<void> {
  if (demoMode) return;

  const { wrapFetchWithPayment, x402Client } = await import('@x402/fetch');
  const { ExactEvmScheme, toClientEvmSigner } = await import('@x402/evm');
  const { createWalletClient, http, publicActions } = await import('viem');
  const { privateKeyToAccount } = await import('viem/accounts');
  const { base } = await import('viem/chains');

  const account = privateKeyToAccount(SHIELDAPI_WALLET_PRIVATE_KEY as `0x${string}`);
  const walletClient = createWalletClient({
    account,
    chain: base,
    transport: http(),
  }).extend(publicActions);

  // Type assertion needed: viem walletClient.extend(publicActions) is structurally compatible
  // but TypeScript can't prove it due to complex generic types in viem + @x402/evm
  const signer = toClientEvmSigner(walletClient as unknown as Parameters<typeof toClientEvmSigner>[0]);
  const client = new x402Client().register(
    `eip155:${base.id}`,
    new ExactEvmScheme(signer)
  );

  paymentFetch = wrapFetchWithPayment(fetch, client);
}

// --- API caller ---

async function callShieldApi(endpoint: string, params: Record<string, string>): Promise<unknown> {
  const url = new URL(`${SHIELDAPI_URL}/api/${endpoint}`);
  for (const [key, value] of Object.entries(params)) {
    url.searchParams.set(key, value);
  }
  if (demoMode) {
    url.searchParams.set('demo', 'true');
  }

  const response = await paymentFetch(url.toString());
  if (!response.ok) {
    const body = await response.text();
    throw new Error(`ShieldAPI ${endpoint} failed (${response.status}): ${body.substring(0, 200)}`);
  }
  return response.json();
}

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

// --- MCP Server ---

const server = new McpServer({
  name: 'ShieldAPI',
  version: '1.0.2',
});

// Register standard tools from config
for (const [name, def] of Object.entries(TOOLS)) {
  server.tool(
    name,
    def.description,
    { [def.param]: z.string().describe(def.paramDesc) },
    async (params) => formatResult(await callShieldApi(def.endpoint, params as Record<string, string>))
  );
}

// full_scan is special — single 'target' param mapped to the correct server param
server.tool(
  'full_scan',
  'Run all security checks on a target (URL, domain, IP, or email). Most comprehensive scan.',
  { target: z.string().describe('Target to scan — URL, domain, IP address, or email') },
  async ({ target }) => formatResult(await callShieldApi('full-scan', detectTargetType(target)))
);

// --- Start ---

async function main(): Promise<void> {
  await initPaymentFetch();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error(`ShieldAPI MCP server running (${demoMode ? 'DEMO mode' : 'PAID mode'})`);
}

main().catch((err) => {
  console.error('Fatal:', err);
  process.exit(1);
});
