const encoder = new TextEncoder();
const json = (data, status = 200, headers = {}) => new Response(JSON.stringify(data), {
  status,
  headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers },
});

const securityHeaders = {
  'content-security-policy': "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'self'; base-uri 'self'; form-action 'self'",
  'referrer-policy': 'no-referrer',
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'SAMEORIGIN',
};

function cookies(request) {
  return Object.fromEntries((request.headers.get('cookie') || '').split(';').map(v => v.trim()).filter(Boolean).map(v => {
    const index = v.indexOf('=');
    return [v.slice(0, index), decodeURIComponent(v.slice(index + 1))];
  }));
}

async function signature(secret) {
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const bytes = new Uint8Array(await crypto.subtle.sign('HMAC', key, encoder.encode('kith-documents-authorized-v1')));
  return btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}

async function isUnlocked(request, env) {
  if (!env.SESSION_SECRET) return false;
  const supplied = cookies(request).kith_documents;
  if (!supplied) return false;
  return supplied === await signature(env.SESSION_SECRET);
}

function isOwner(request, env) {
  const userId = request.headers.get('oai-authenticated-user-id');
  const email = request.headers.get('oai-authenticated-user-email')?.trim().toLowerCase();
  const adminEmail = String(env.ADMIN_EMAIL || '').trim().toLowerCase();
  return Boolean(
    (userId && env.ADMIN_USER_ID && userId === env.ADMIN_USER_ID) ||
    (email && adminEmail && email === adminEmail)
  );
}

function setCookie(value, maxAge) {
  return `kith_documents=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;
}

async function unlock(request, env) {
  let body;
  try { body = await request.json(); } catch { return json({ error: 'Invalid request' }, 400); }
  if (!env.DOCUMENTS_PASSWORD || body.password !== env.DOCUMENTS_PASSWORD) {
    return json({ error: 'Incorrect password' }, 401);
  }
  return json({ ok: true }, 200, { 'set-cookie': setCookie(await signature(env.SESSION_SECRET), 28800) });
}

async function listDocuments(request, env, url) {
  if (!await isUnlocked(request, env)) return json({ error: 'Locked' }, 401);
  const store = url.searchParams.get('store');
  if (!store) return json({ error: 'Store is required' }, 400);
  const result = await env.DB.prepare(`SELECT id, store_id, filename, content_type, size, category, description, created_at FROM documents WHERE store_id = ? ORDER BY created_at DESC`).bind(store).all();
  return json(result.results || []);
}

async function uploadDocument(request, env) {
  if (!isOwner(request, env)) return json({ error: 'Owner access required' }, 403);
  if (!await isUnlocked(request, env)) return json({ error: 'Locked' }, 401);
  let form;
  try { form = await request.formData(); } catch { return json({ error: 'Invalid upload' }, 400); }
  const file = form.get('file');
  const storeId = String(form.get('store_id') || '').trim();
  const category = String(form.get('category') || 'Other').slice(0, 40);
  const description = String(form.get('description') || '').trim().slice(0, 180);
  if (!file || typeof file.arrayBuffer !== 'function' || !storeId) return json({ error: 'File and store are required' }, 400);
  if (file.size > 20 * 1024 * 1024) return json({ error: 'Maximum file size is 20 MB' }, 413);
  const id = crypto.randomUUID();
  const safeName = String(file.name || 'document').replace(/[\r\n]/g, ' ').slice(0, 180);
  const objectKey = `stores/${storeId}/${id}`;
  const createdAt = new Date().toISOString();
  await env.BUCKET.put(objectKey, await file.arrayBuffer(), { httpMetadata: { contentType: file.type || 'application/octet-stream' } });
  try {
    await env.DB.prepare(`INSERT INTO documents (id, store_id, filename, object_key, content_type, size, category, description, uploaded_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(id, storeId, safeName, objectKey, file.type || 'application/octet-stream', file.size, category, description || null, request.headers.get('oai-authenticated-user-id'), createdAt).run();
  } catch (error) {
    await env.BUCKET.delete(objectKey);
    throw error;
  }
  return json({ id }, 201);
}

async function downloadDocument(request, env, id) {
  if (!await isUnlocked(request, env)) return json({ error: 'Locked' }, 401);
  const doc = await env.DB.prepare(`SELECT filename, object_key, content_type FROM documents WHERE id = ?`).bind(id).first();
  if (!doc) return new Response('Not found', { status: 404 });
  const object = await env.BUCKET.get(doc.object_key);
  if (!object) return new Response('Not found', { status: 404 });
  const filename = String(doc.filename).replace(/["\\\r\n]/g, '_');
  return new Response(object.body, { headers: { 'content-type': doc.content_type, 'content-disposition': `inline; filename="${filename}"`, 'cache-control': 'private, no-store', ...securityHeaders } });
}

async function deleteDocument(request, env, id) {
  if (!isOwner(request, env)) return json({ error: 'Owner access required' }, 403);
  if (!await isUnlocked(request, env)) return json({ error: 'Locked' }, 401);
  const doc = await env.DB.prepare(`SELECT object_key FROM documents WHERE id = ?`).bind(id).first();
  if (!doc) return json({ error: 'Not found' }, 404);
  await env.BUCKET.delete(doc.object_key);
  await env.DB.prepare(`DELETE FROM documents WHERE id = ?`).bind(id).run();
  return json({ ok: true });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    try {
      if (url.pathname === '/api/me' && request.method === 'GET') return json({ isOwner: isOwner(request, env), unlocked: await isUnlocked(request, env) });
      if (url.pathname === '/api/documents/unlock' && request.method === 'POST') return unlock(request, env);
      if (url.pathname === '/api/documents/lock' && request.method === 'POST') return json({ ok: true }, 200, { 'set-cookie': setCookie('', 0) });
      if (url.pathname === '/api/documents' && request.method === 'GET') return listDocuments(request, env, url);
      if (url.pathname === '/api/documents' && request.method === 'POST') return uploadDocument(request, env);
      const download = url.pathname.match(/^\/api\/documents\/([^/]+)\/download$/);
      if (download && request.method === 'GET') return downloadDocument(request, env, decodeURIComponent(download[1]));
      const remove = url.pathname.match(/^\/api\/documents\/([^/]+)$/);
      if (remove && request.method === 'DELETE') return deleteDocument(request, env, decodeURIComponent(remove[1]));
      if (url.pathname !== '/') return new Response('Not found', { status: 404, headers: securityHeaders });
      return new Response(page, { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', ...securityHeaders } });
    } catch (error) {
      console.error('Kith dashboard request failed', { path: url.pathname, message: error instanceof Error ? error.message : String(error) });
      return json({ error: 'Service temporarily unavailable' }, 500);
    }
  },
};
