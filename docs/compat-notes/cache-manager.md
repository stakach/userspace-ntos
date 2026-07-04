# NT Cache Manager (section-backed file cache) — compatibility notes

The NT Cache Manager (spec: NT Cache Manager + Section-Backed File Cache). A per-stream cache of
4 KiB pages over a filesystem-neutral backing, exposing the Cc* exports a WDM/FS driver calls.

## nt-cache-manager (implemented, Milestones 23.1-23.6)

- `CachedStreamBacking` trait (§10.2): read_at/write_at/flush/set_file_size — the filesystem-neutral
  backing (MemoryBacking for tests; a MemFs file bridge in nt-fs).
- `SharedCacheMap<B>` (§8): a per-stream cache — 4 KiB pages (dirty/pinned/LRU tick), file/valid/
  allocation sizes.
- Cc* exports: `cc_initialize_cache_map` (§11), `cc_copy_read` (§12 — faults pages in from the
  backing, clips to EOF, zero bytes at/beyond EOF), `cc_copy_write` (§13 — dirties pages, extends
  EOF, optional write-through flush), `cc_flush_cache` (§14 — writes dirty pages back + flushes;
  keeps a page dirty on write failure), `cc_set_file_sizes` (§15 — truncate drops pages past EOF +
  clips the partial page), `cc_get_file_size`, `cc_is_there_dirty_data`, `cc_purge_cache_section`
  (§20 — drops clean/unpinned pages).
- Pin/unpin (§16): `cc_pin_read` / `cc_prepare_pin_write` → `Bcb`, `cc_set_dirty_pinned_data`,
  `cc_unpin_data` (pinned pages resist purge/evict).
- Lazy writer (§17): `lazy_write_pass` flushes all dirty pages. LRU `evict` (§19) drops the
  least-recently-used clean, unpinned page.
- 7 unit tests: copy-read faults from backing, copy-write dirties + flush writes back + cached
  read hits, EOF behaviour, truncate drops pages, pin/dirty/unpin, purge + evict clean pages,
  write-through flushes immediately.
