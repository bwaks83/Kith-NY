import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const [source, manifest] = await Promise.all([
  readFile('dist/server/index.js', 'utf8'),
  readFile('dist/.openai/hosting.json', 'utf8'),
]);
const config = JSON.parse(manifest);
assert.equal(config.project_id, 'appgprj_6ab571966a70819180dcafdf7e8d8ace');
assert.equal(config.d1, 'DB');
assert.equal(config.r2, 'BUCKET');
const moduleUrl = `data:text/javascript;base64,${Buffer.from(source).toString('base64')}`;
const worker = await import(moduleUrl);
assert.equal(typeof worker.default?.fetch, 'function');
console.log('Secure dashboard artifact is valid');
