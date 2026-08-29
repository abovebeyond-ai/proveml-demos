/**
 * The model layer of the demos: one function, two providers.
 *
 *   anthropic  Claude through the official SDK. Credentials resolve the way
 *              the SDK does (ANTHROPIC_API_KEY, or an `ant auth login`
 *              profile); as a convenience a key in
 *              ~/.config/proveml/anthropic-key is exported into the process.
 *   together   DeepSeek V4 Pro (or any Together model) through their
 *              OpenAI-compatible endpoint; key in ~/.config/proveml/together-key.
 *
 * The prompt is the same for both: a system text with the ProveML rules and
 * the registry, and one user message with the data and the question.
 */
import { existsSync, readFileSync, writeFileSync, mkdtempSync, rmSync } from 'fs';
import { homedir, tmpdir } from 'os';
import { join } from 'path';
import { execFile } from 'child_process';
import { promisify } from 'util';
const execFileP = promisify(execFile);

const cfg = (name) => {
    const f = join(homedir(), '.config', 'proveml', name);
    return existsSync(f) ? readFileSync(f, 'utf8').trim() : null;
};

export const MODELS = {
    'claude-opus-5': { provider: 'anthropic', label: 'Claude Opus 5' },
    'claude-sonnet-5': { provider: 'anthropic', label: 'Claude Sonnet 5' },
    'deepseek-ai/DeepSeek-V4-Pro-0813': { provider: 'together', label: 'DeepSeek V4 Pro (open weights, via Together)' },
};

/**
 * Claude is reached one of two ways: the Anthropic SDK when a key is present,
 * otherwise the Claude Code CLI (`claude -p`) with whatever login the machine
 * has. The CLI is what runs on the laptop; a hosted server needs the key.
 */
let cliPath = null;
function claudeCli() {
    if (cliPath !== null) return cliPath;
    const candidates = [process.env.CLAUDE_CLI, join(homedir(), '.npm-global', 'bin', 'claude'), join(homedir(), '.local', 'bin', 'claude'), '/opt/homebrew/bin/claude', '/usr/local/bin/claude']
        .filter(Boolean);
    cliPath = candidates.find(existsSync) || (process.env.PATH.split(':').map(d => join(d, 'claude')).find(existsSync)) || '';
    return cliPath;
}
function hasAnthropicKey() { return Boolean(process.env.ANTHROPIC_API_KEY || cfg('anthropic-key')); }

export function availableModels() {
    const hasAnthropic = hasAnthropicKey() || Boolean(claudeCli());
    const hasTogether = Boolean(process.env.TOGETHER_API_KEY || cfg('together-key'));
    return Object.entries(MODELS)
        .filter(([, m]) => (m.provider === 'anthropic' ? hasAnthropic : hasTogether))
        .map(([id, m]) => ({ id, ...m, via: m.provider === 'anthropic' ? (hasAnthropicKey() ? 'api' : 'claude-cli') : 'together' }));
}

let anthropic;
async function anthropicClient() {
    if (!anthropic) {
        if (!process.env.ANTHROPIC_API_KEY && cfg('anthropic-key')) process.env.ANTHROPIC_API_KEY = cfg('anthropic-key');
        const { default: Anthropic } = await import('@anthropic-ai/sdk');
        anthropic = new Anthropic();
    }
    return anthropic;
}

/**
 * @returns {Promise<{ text: string, model: string, ms: number, usage?: object }>}
 */
export async function generate({ model, system, user }) {
    const spec = MODELS[model];
    if (!spec) throw new Error(`Unknown model ${model}`);
    const t0 = Date.now();

    if (spec.provider === 'anthropic' && !hasAnthropicKey()) {
        const cli = claudeCli();
        if (!cli) throw new Error('No Anthropic key and no claude CLI on this machine');
        const dir = mkdtempSync(join(tmpdir(), 'proveml-'));
        const file = join(dir, 'prompt.txt');
        writeFileSync(file, `${system}\n\n${user}`);
        try {
            const { stdout } = await execFileP('/bin/sh', ['-c', `cat "${file}" | "${cli}" -p --model ${model}`], { maxBuffer: 10 * 1024 * 1024, timeout: 300000 });
            const text = stdout.trim();
            if (!text) throw new Error('claude CLI returned an empty answer');
            return { text, model, ms: Date.now() - t0 };
        } finally { rmSync(dir, { recursive: true, force: true }); }
    }

    if (spec.provider === 'anthropic') {
        const client = await anthropicClient();
        const response = await client.messages.create({
            model,
            max_tokens: 16000,
            system,
            messages: [{ role: 'user', content: user }],
        });
        if (response.stop_reason === 'refusal') throw new Error(`The model declined: ${response.stop_details?.explanation || 'no explanation'}`);
        const text = response.content.filter(b => b.type === 'text').map(b => b.text).join('\n').trim();
        return { text, model, ms: Date.now() - t0, usage: response.usage };
    }

    const key = process.env.TOGETHER_API_KEY || cfg('together-key');
    if (!key) throw new Error('No Together key');
    const res = await fetch('https://api.together.ai/v1/chat/completions', {
        method: 'POST',
        headers: { authorization: `Bearer ${key}`, 'content-type': 'application/json' },
        body: JSON.stringify({ model, max_tokens: 16384, messages: [{ role: 'system', content: system }, { role: 'user', content: user }] }),
    });
    const json = await res.json();
    if (!res.ok || json.error) throw new Error(`Together: ${json.error?.message || res.status}`);
    const text = json.choices?.[0]?.message?.content?.trim();
    if (!text) throw new Error(`Together: empty answer (finish_reason=${json.choices?.[0]?.finish_reason})`);
    return { text, model, ms: Date.now() - t0, usage: json.usage };
}
