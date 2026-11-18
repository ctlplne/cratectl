// SPDX-License-Identifier: BUSL-1.1
import {mkdir, readFile, writeFile} from 'node:fs/promises';
import {basename, dirname, extname, isAbsolute, join} from 'node:path';
import {fileURLToPath} from 'node:url';

const destination = process.argv[2];
if (!destination || !isAbsolute(destination) || process.env.ESBUILD_BINARY_PATH) {
  throw new Error('Supply an absolute staging directory and use the installed esbuild binary.');
}

const root = dirname(fileURLToPath(import.meta.url));
const {build} = await import('esbuild');
const {outputFiles, metafile} = await build({
  absWorkingDir: root,
  entryPoints: ['src/main.tsx'],
  outdir: 'assets',
  entryNames: 'console-[hash]',
  platform: 'browser',
  format: 'esm',
  target: ['chrome111', 'edge111', 'firefox114', 'safari16.4', 'ios16.4'],
  jsx: 'automatic',
  define: {'process.env.NODE_ENV': '"production"'},
  bundle: true,
  minify: true,
  metafile: true,
  write: false,
});

const filenames = new Map(outputFiles.map(file => [extname(file.path), basename(file.path)]));
if (outputFiles.length !== 2 || !filenames.has('.js') || !filenames.has('.css')
    || outputFiles.some(file => !/^console-[A-Z0-9]{8}\.(?:js|css)$/.test(basename(file.path)))
    || Object.values(metafile.outputs).some(file => file.imports.length !== 0)) {
  throw new Error('The embedded build requires one local JavaScript bundle and one stylesheet.');
}

const template = await readFile(join(root, 'index.html'), 'utf8');
const sourceScript = '<script type="module" src="/src/main.tsx"></script>';
if (template.split(sourceScript).length !== 2 || template.split('</head>').length !== 2) {
  throw new Error('The console template requires one script entry and one head element.');
}
const index = template
  .replace(sourceScript, '<script type="module" src="/console/assets/' + filenames.get('.js') + '"></script>')
  .replace('</head>', '<link rel="stylesheet" href="/console/assets/' + filenames.get('.css') + '"/></head>');

const assets = join(destination, 'assets');
await mkdir(assets);
for (const file of outputFiles) {
  await writeFile(join(assets, basename(file.path)), file.contents, {flag: 'wx'});
}
await writeFile(join(destination, 'index.html'), index, {flag: 'wx'});
