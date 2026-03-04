#!/usr/bin/env node
/**
 * ShieldAPI MCP Server (v2.0.0 — Phase 2)
 *
 * Exposes ShieldAPI security intelligence as native MCP tools.
 * Handles x402 USDC micropayments automatically, with demo fallback.
 *
 * Phase 2 adds: scan_skill, check_prompt
 */
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
const { SHIELDAPI_URL = 'https://shield.vainplex.dev', SHIELDAPI_WALLET_PRIVATE_KEY, } = process.env;
const demoMode = !SHIELDAPI_WALLET_PRIVATE_KEY;
const TOOLS = {
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
let paymentFetch = fetch;
async function initPaymentFetch() {
    if (demoMode)
        return;
    const { wrapFetchWithPayment, x402Client } = await import('@x402/fetch');
    const { ExactEvmScheme, toClientEvmSigner } = await import('@x402/evm');
    const { createWalletClient, http, publicActions } = await import('viem');
    const { privateKeyToAccount } = await import('viem/accounts');
    const { base } = await import('viem/chains');
    const account = privateKeyToAccount(SHIELDAPI_WALLET_PRIVATE_KEY);
    const walletClient = createWalletClient({
        account,
        chain: base,
        transport: http(),
    }).extend(publicActions);
    const signer = toClientEvmSigner(walletClient);
    const client = new x402Client().register(`eip155:${base.id}`, new ExactEvmScheme(signer));
    paymentFetch = wrapFetchWithPayment(fetch, client);
}
// --- API callers ---
async function callShieldApi(endpoint, params) {
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
async function callShieldApiPost(endpoint, body) {
    const url = new URL(`${SHIELDAPI_URL}/api/${endpoint}`);
    if (demoMode) {
        url.searchParams.set('demo', 'true');
    }
    const response = await paymentFetch(url.toString(), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
    });
    if (!response.ok) {
        const body = await response.text();
        throw new Error(`ShieldAPI ${endpoint} failed (${response.status}): ${body.substring(0, 200)}`);
    }
    return response.json();
}
function detectTargetType(target) {
    if (target.includes('@'))
        return { email: target };
    if (/^\d+\.\d+\.\d+\.\d+$/.test(target))
        return { ip: target };
    if (target.startsWith('http://') || target.startsWith('https://'))
        return { url: target };
    return { domain: target };
}
function formatResult(data) {
    return {
        content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
    };
}
// --- MCP Server ---
const server = new McpServer({
    name: 'shieldapi-mcp',
    title: 'ShieldAPI — Security Intelligence for AI Agents',
    version: '2.1.0',
    description: '9 security tools for AI agents: breach checks, domain/IP/URL reputation, prompt injection detection, skill supply chain scanning. Pay-per-request via x402 USDC micropayments. Demo mode available.',
    websiteUrl: 'https://shield.vainplex.dev',
    icons: [{ src: 'https://shield.vainplex.dev/icon.svg', mimeType: 'image/svg+xml' }],
});
// Annotations for read-only lookup tools
const readOnlyAnnotations = {
    title: '', // will be set per-tool
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: true,
};
const TOOL_TITLES = {
    check_url: 'Check URL Safety',
    check_password: 'Check Password Breach',
    check_password_range: 'Password Range Lookup',
    check_domain: 'Check Domain Reputation',
    check_ip: 'Check IP Reputation',
    check_email: 'Check Email Breach',
};
// Register standard GET tools from config
for (const [name, def] of Object.entries(TOOLS)) {
    server.tool(name, def.description, { [def.param]: z.string().describe(def.paramDesc) }, { ...readOnlyAnnotations, title: TOOL_TITLES[name] || name }, async (params) => formatResult(await callShieldApi(def.endpoint, params)));
}
// full_scan — single 'target' param mapped to the correct server param
server.tool('full_scan', 'Run all security checks on a target (URL, domain, IP, or email). Most comprehensive scan.', { target: z.string().describe('Target to scan — URL, domain, IP address, or email') }, { title: 'Full Security Scan', readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true }, async ({ target }) => formatResult(await callShieldApi('full-scan', detectTargetType(target))));
// ================================================================
// Phase 2 Tools (POST endpoints)
// ================================================================
// scan_skill — AI skill supply chain security scanner
server.tool('scan_skill', 'Scan an AI agent skill/plugin for security issues across 8 risk categories (Snyk ToxicSkills taxonomy). Checks for prompt injection, malicious code, suspicious downloads, credential handling, secret detection, third-party content, unverifiable dependencies, and financial access patterns. Static analysis only — no code execution. Returns risk score (0-100), severity-ranked findings with file locations, and human-readable summary.', {
    skill: z.string().optional().describe('Raw SKILL.md content or skill name from ClawHub'),
    files: z.array(z.object({
        name: z.string().describe('Filename including extension'),
        content: z.string().describe('File content as string'),
    })).optional().describe('Additional code files to analyze (max 20 files)'),
}, { title: 'Scan AI Skill/Plugin', readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }, async (params) => {
    const body = {};
    if (params.skill)
        body.skill = params.skill;
    if (params.files)
        body.files = params.files;
    return formatResult(await callShieldApiPost('scan-skill', body));
});
// check_prompt — Prompt injection detection
server.tool('check_prompt', 'Detect prompt injection in text. Analyzes across 4 categories (direct injection, encoding tricks, exfiltration, indirect injection) with 200+ detection patterns. Designed for real-time inline usage before processing untrusted user input. Returns boolean verdict, confidence score (0-1), matched patterns with evidence, and decoded content if encoding obfuscation was detected. Response time <100ms p95.', {
    prompt: z.string().describe('The text to analyze for prompt injection'),
    context: z.enum(['user-input', 'skill-prompt', 'system-prompt']).optional()
        .describe('Context hint for sensitivity: user-input (default), skill-prompt (higher tolerance), system-prompt (highest sensitivity)'),
}, { title: 'Detect Prompt Injection', readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }, async (params) => {
    const body = { prompt: params.prompt };
    if (params.context)
        body.context = params.context;
    return formatResult(await callShieldApiPost('check-prompt', body));
});
// --- Start ---
async function main() {
    await initPaymentFetch();
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error(`ShieldAPI MCP server v2.0.0 running (${demoMode ? 'DEMO mode' : 'PAID mode'})`);
}
main().catch((err) => {
    console.error('Fatal:', err);
    process.exit(1);
});
