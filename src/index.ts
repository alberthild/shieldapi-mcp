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
  version: '1.0.0',
});

// Tools

server.tool(
  'check_url',
  'Check a URL for malware, phishing, and other threats. Uses URLhaus + heuristic analysis.',
  { url: z.string().describe('The URL to check (e.g. https://example.com)') },
  async ({ url }) => formatResult(await callShieldApi('check-url', { url }))
);

server.tool(
  'check_password',
  'Check if a password hash (SHA-1) has been exposed in known data breaches via HIBP.',
  { hash: z.string().describe('SHA-1 hash of the password (40 hex chars)') },
  async ({ hash }) => formatResult(await callShieldApi('check-password', { hash }))
);

server.tool(
  'check_password_range',
  'Look up a SHA-1 hash prefix in the HIBP k-Anonymity database.',
  { prefix: z.string().describe('First 5 characters of the SHA-1 password hash') },
  async ({ prefix }) => formatResult(await callShieldApi('check-password-range', { prefix }))
);

server.tool(
  'check_domain',
  'Check domain reputation: DNS records, blacklists (Spamhaus, SpamCop, SORBS), SPF/DMARC, SSL.',
  { domain: z.string().describe('Domain name to check (e.g. example.com)') },
  async ({ domain }) => formatResult(await callShieldApi('check-domain', { domain }))
);

server.tool(
  'check_ip',
  'Check IP reputation: blacklists, Tor exit node detection, reverse DNS.',
  { ip: z.string().describe('IPv4 address to check (e.g. 8.8.8.8)') },
  async ({ ip }) => formatResult(await callShieldApi('check-ip', { ip }))
);

server.tool(
  'check_email',
  'Check if an email address has been exposed in known data breaches via HIBP.',
  { email: z.string().describe('Email address to check') },
  async ({ email }) => formatResult(await callShieldApi('check-email', { email }))
);

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
