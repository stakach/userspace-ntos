# ALPC steps 2-4 (over the unified nt-port-core)

## Step 2 — full NtAlpc* surface + REAL cross-endpoint port-section/view shared memory
- [x] nt-alpc-abi: WRITE/READ_SECTION_VIEW opcodes + AlpcViewIoRequest (32B) + size assert
- [x] nt-alpc: real backing store for PortSection (Vec<u8>), views alias the section; write/read view ops
- [x] host test: two views on one section, write via A read via B == not a copy
- [x] live spec exec_alpc_section_view_shared: big data via shared section, not the message body
- [x] FLAG: physical copy_cap+page_map into two real VSpaces deferred (no real ALPC binary; = CSRSS_ANON_BASE machinery)

## Step 3 — full ALPC_MESSAGE_ATTRIBUTES serialize/parse in the out-param path
- [x] nt-alpc: serialize_attrs(allocated, attrs) -> ALPC_MESSAGE_ATTRIBUTES blob (fixed order); valid = allocated & present
- [x] receive path: RECV_ATTRIBUTES flag → attrs blob at front of reply, body after
- [x] host test: CONTEXT+VIEW round-trip; bridge degradation (VIEW/HANDLE/SECURITY/TOKEN drop to LPC) with full parse
- [x] live spec exec_alpc_message_attributes_roundtrip

## Step 4 — ALPC peer-direct data plane
- [x] nt-alpc: PeerDirect cache (executive-cacheable cross-endpoint mailbox), send/recv, mirrors LpcConnRecord
- [x] host test: peer-direct A<->B delivery + attrs carried
- [x] live spec exec_alpc_peer_direct: server (ring) not in per-message path (ring op count unchanged)

## Discipline
- gate >=121 pass, 0 FAIL, winsrv ON, sentinel, desktop paint 0x003a6ea5
- cargo test crates first/throughout; build SUBMODULE rust-micro; run_specs; commit each green step; update project_alpc.md

## Review — DONE (2026-07-13, gate 124 pass, 0 FAIL, winsrv ON, paint 0x003a6ea5)
- Step 2 committed (122): real shared backing store, WRITE/READ_SECTION_VIEW, exec_alpc_section_view_shared.
- Step 3 committed (123): serialize_attrs/parse_message_attributes + RECV_ATTRIBUTES, exec_alpc_message_attributes_roundtrip.
- Step 4 committed (124): PeerDirect executive-local data plane, exec_alpc_peer_direct (ring unchanged per-message).
- No rust-micro/src change → sel4test byte-identical. Host tests: nt-alpc 7->11.
- FLAG (not a kernel-primitive gap): physical copy_cap+page_map of section frames into two REAL VSpaces is
  deferred until a real ALPC binary provides two endpoint VSpaces (= CSRSS_ANON_BASE machinery). With the
  synthetic single-address-space endpoints the broker's shared backing IS the shared region — the broker model.
