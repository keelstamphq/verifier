// Copyright 2026 PowerQuant ApS
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// npm run build [-- --out <dir>]  →  <dir>/keelstamp-verifier.html (default dir: dist)
//
// One self-contained HTML file: the verifier and its dependencies are bundled (unminified, so the
// page can be read) into a single inline script. The page's Content-Security-Policy is
// default-src 'none' with the inline script and style pinned by SHA-256 hash, so the browser
// itself refuses any network connection from the page.

import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const OUTPUT_NAME = 'keelstamp-verifier.html';

function outDir(argv) {
  const i = argv.indexOf('--out');
  if (i === -1) return join(root, 'dist');
  if (i + 1 >= argv.length) throw new Error('--out needs a directory');
  return resolve(argv[i + 1]);
}

const cspHash = (text) => `'sha256-${createHash('sha256').update(text, 'utf8').digest('base64')}'`;

/** License texts of the runtime dependencies bundled into the page, as one HTML comment. */
function thirdPartyNotices() {
  const { dependencies } = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
  const parts = Object.keys(dependencies).map((name) => {
    const dir = join(root, 'node_modules', name);
    const pkg = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'));
    const license = readFileSync(join(dir, 'LICENSE'), 'utf8').trim();
    return `${pkg.name} ${pkg.version} (${pkg.license})\n\n${license}`;
  });
  const text = `Third-party code bundled into the script of this page:\n\n${parts.join('\n\n----\n\n')}`;
  if (/-->|<!--|--!>/.test(text)) throw new Error('a license text cannot be placed in an HTML comment');
  return `<!--\n${text}\n-->`;
}

export async function buildPage(dir) {
  const bundled = await build({
    entryPoints: [join(root, 'web/app.mjs')],
    bundle: true,
    format: 'iife',
    platform: 'browser',
    target: ['es2022'],
    charset: 'utf8',
    legalComments: 'inline',
    minify: false,
    write: false,
    logLevel: 'warning',
  });
  const js = bundled.outputFiles[0].text;
  // The script is inlined verbatim; refuse sequences that would end or confuse the <script> element.
  if (/<\/script|<!--/i.test(js)) throw new Error('bundle contains "</script" or "<!--"; cannot inline it safely');

  const template = readFileSync(join(root, 'web/index.html'), 'utf8');
  const style = /<style>([\s\S]*?)<\/style>/.exec(template)?.[1];
  if (style === undefined) throw new Error('web/index.html has no <style> element');
  const script = `\n${js}`;
  const csp = [
    "default-src 'none'",
    `script-src ${cspHash(script)}`,
    `style-src ${cspHash(style)}`,
    "connect-src 'none'",
    "img-src 'none'",
    "form-action 'none'",
    "base-uri 'none'",
  ].join('; ');
  const { version } = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
  const buildId = `v${version}+${createHash('sha256').update(script, 'utf8').digest('hex').slice(0, 12)}`;

  const html = template
    .replace('__CSP__', csp)
    .replace('__BUILD_ID__', buildId)
    .replace('<!--SCRIPT-->', () => `<script>${script}</script>\n${thirdPartyNotices()}`);

  mkdirSync(dir, { recursive: true });
  const path = join(dir, OUTPUT_NAME);
  writeFileSync(path, html);
  return { path, bytes: Buffer.byteLength(html), sha256: createHash('sha256').update(html, 'utf8').digest('hex'), buildId };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const out = await buildPage(outDir(process.argv.slice(2)));
  console.log(`built ${out.path} (${out.bytes} bytes, ${out.buildId})\nsha256 ${out.sha256}`);
}
