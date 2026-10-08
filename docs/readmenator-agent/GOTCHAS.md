# Gotchas

## God Nodes (high connectivity)

These files have the most connections. Changes here have high blast radius.

- `gen_ebird3.sh` (score: 0.20)
- `app.py` (score: 0.00)
- `install.sh` (score: 0.00)

## Hotspots (complexity + centrality)

- `app.py` -- complexity: 0.0, centrality: 1.0, combined: 0.6
- `gen_ebird3.sh` -- complexity: 1.0, centrality: 0.0, combined: 0.4
- `install.sh` -- complexity: 0.0, centrality: 0.0, combined: 0.0

## Dataflow Issues (INFERRED, review each lead)

- `gen_ebird3.sh:262` `xor_string` [DEAD_STORE] `path_len`: `path_len` assigned at line 262 but never read afterwards.
- `gen_ebird3.sh:356` `xor_string` [DEAD_STORE] `SHELLCODE_URL`: `SHELLCODE_URL` assigned at line 356 but never read afterwards.
- `gen_ebird3.sh:358` `xor_string` [DEAD_STORE] `USER_AGENT`: `USER_AGENT` assigned at line 358 but never read afterwards.
- `gen_ebird3.sh:206` `xor_string` [UNCHECKED_ALLOC] `sc`: Result of allocator stored in `sc` is never checked against NULL.
- `gen_ebird3.sh:279` `xor_string` [UNCHECKED_ALLOC] `sock`: Result of allocator stored in `sock` is never checked against NULL.
