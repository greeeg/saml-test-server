import { execFileSync, spawn, type ChildProcess } from 'node:child_process';
import { existsSync } from 'node:fs';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { normalizeArgv } from '../src/cli-program.js';

const root = new URL('..', import.meta.url).pathname;
const cli = new URL('../dist/cli.js', import.meta.url).pathname;

describe('normalizeArgv', () => {
  it('expands the aliases of the original saml-idp', () => {
    expect(normalizeArgv(['--acs', 'http://a', '--aud=urn:x', '--static', '--no-signResponse', '-p', '1'])).toEqual([
      '--acsUrl',
      'http://a',
      '--audience=urn:x',
      '--disableRequestAcsUrl',
      '--signResponse=false',
      '-p',
      '1',
    ]);
  });
});

describe('CLI', () => {
  const children: ChildProcess[] = [];

  beforeAll(() => {
    if (!existsSync(cli)) execFileSync('npm', ['run', 'build'], { cwd: root, stdio: 'ignore' });
  }, 60_000);

  afterAll(() => {
    for (const child of children) child.kill();
  });

  function start(args: string[]): Promise<{ url: string; output: () => string }> {
    return new Promise((resolve, reject) => {
      const child = spawn('node', [cli, ...args], { env: { ...process.env, NO_COLOR: '1' } });
      children.push(child);
      let output = '';
      const onData = (chunk: Buffer) => {
        output += chunk;
        const match = /IdP server ready at\s+(http\S+)/.exec(output);
        if (match) resolve({ url: match[1], output: () => output });
      };
      child.stdout.on('data', onData);
      child.stderr.on('data', onData);
      child.on('exit', (code) => reject(new Error(`exited with ${code}\n${output}`)));
    });
  }

  it('starts the IdP with the original flags and aliases', async () => {
    const { url, output } = await start([
      '--acs', 'https://sp.example.com/acs',
      '--aud', 'urn:sp',
      '--slo', 'https://sp.example.com/slo',
      '--iss', 'urn:cli:idp',
      '--port', '0',
    ]);
    const res = await fetch(`${url}/metadata`);
    expect(res.status).toBe(200);
    const xml = await res.text();
    expect(xml).toContain('entityID="urn:cli:idp"');
    expect(xml).toContain('SingleLogoutService');
    expect(output()).toContain('Audience URI:');
  });

  it('exits with an error when required options are missing', () => {
    expect(() => execFileSync('node', [cli, '--port', '0'], { stdio: 'pipe' })).toThrow(/--acsUrl/);
  });

  it('exits with an error on invalid certificates', () => {
    let stderr = '';
    try {
      execFileSync('node', [cli, '--acs', 'a', '--aud', 'b', '--cert', 'nope'], { stdio: 'pipe' });
    } catch (error: any) {
      stderr = error.stderr.toString();
    }
    expect(stderr).toContain('Invalid / missing');
  });
});
