import { mkdir, readFile, rm, writeFile, cp } from 'node:fs/promises';

await rm('dist', { recursive: true, force: true });
await mkdir('dist/server', { recursive: true });
await mkdir('dist/.openai', { recursive: true });
await mkdir('dist/drizzle', { recursive: true });

const [html, handler] = await Promise.all([
  readFile('web/index.html', 'utf8'),
  readFile('worker/handler.js', 'utf8'),
]);

await writeFile('dist/server/index.js', `const page = ${JSON.stringify(html)};\n${handler}`);
await cp('.openai/hosting.json', 'dist/.openai/hosting.json');
await cp('drizzle/0000_private_documents.sql', 'dist/drizzle/0000_private_documents.sql');
console.log('Built secure dashboard worker');
