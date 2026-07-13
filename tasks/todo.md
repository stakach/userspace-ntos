# ALPC steps 2-4 (over the unified nt-port-core)

## Step 2 — full NtAlpc* surface + REAL cross-endpoint port-section/view shared memory
- [ ] nt-alpc-abi: WRITE/READ_SECTION_VIEW opcodes + AlpcViewIoRequest (32B) + size assert
- [ ] nt-alpc: real backing store for PortSection (Vec<u8>), views alias the section; write/read view ops
- [ ] host test: two views on one section, write via A read via B == not a copy
- [ ] live spec exec_alpc_section_view_shared: big data via shared section, not the message body
- [ ] FLAG: physical copy_cap+page_map into two real VSpaces deferred (no real ALPC binary; = CSRSS_ANON_BASE machinery)

## Step 3 — full ALPC_MESSAGE_ATTRIBUTES serialize/parse in the out-param path
- [ ] nt-alpc: serialize_attrs(allocated, attrs) -> ALPC_MESSAGE_ATTRIBUTES blob (fixed order); valid = allocated & present
- [ ] receive path: RECV_ATTRIBUTES flag → attrs blob at front of reply, body after
- [ ] host test: CONTEXT+VIEW round-trip; bridge degradation (VIEW/HANDLE/SECURITY/TOKEN drop to LPC) with full parse
- [ ] live spec exec_alpc_message_attributes_roundtrip

## Step 4 — ALPC peer-direct data plane
- [ ] nt-alpc: PeerDirect cache (executive-cacheable cross-endpoint mailbox), send/recv, mirrors LpcConnRecord
- [ ] host test: peer-direct A<->B delivery + attrs carried
- [ ] live spec exec_alpc_peer_direct: server (ring) not in per-message path (ring op count unchanged)

## Discipline
- gate >=121 pass, 0 FAIL, winsrv ON, sentinel, desktop paint 0x003a6ea5
- cargo test crates first/throughout; build SUBMODULE rust-micro; run_specs; commit each green step; update project_alpc.md
