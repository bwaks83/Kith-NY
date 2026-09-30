CREATE TABLE documents (
  id TEXT PRIMARY KEY NOT NULL,
  store_id TEXT NOT NULL,
  filename TEXT NOT NULL,
  object_key TEXT NOT NULL UNIQUE,
  content_type TEXT NOT NULL,
  size INTEGER NOT NULL,
  category TEXT NOT NULL,
  description TEXT,
  uploaded_by TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX idx_documents_store_created
ON documents(store_id, created_at DESC);
