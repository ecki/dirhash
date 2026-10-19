# Shared unit-test vectors

Java and Go unit suites consume these exact same logical trees and expected
hashes. Small fixture-building helpers may remain duplicated in their native
test languages. Implementation-specific reader/instrumentation tests remain
local; larger recursive/network/upstream-archive scenarios belong in the
black-box conformance suite.

`trees.tsv` has five tab-separated columns: case ID, UTF-8 relative path,
kind (`file`, `dir`, `link`), octal Unix mode, and hexadecimal payload.
An empty payload is an empty final field. `empty` has no entry rows.
Parents are inferred. These are logical trees, not ZIP manifests: explicit
directory markers and raw legacy ZIP names are tested separately in both
ecosystems.

`hashes.tsv` has four columns: case ID, scheme, digest, expected rendered value.
It covers six trees, four constructions, and seven hashlib-supported digest
choices (168 assertions per ecosystem). BLAKE3 and Go-compatible archive
manifests have separate native vectors because hashlib does not implement
BLAKE3 and archive spelling is not represented by a logical tree.

Cases cover empty roots, binary payloads, nested paths, empty subdirectories,
owner/group/other execute bits, typed symlinks, and Git's virtual-slash ordering.
The SWH vectors preserve empty directories; Git omits them.

Regenerate with `python tests/vectors/generate.py`. Expected values come from
the independent Python serializers in `conformance.py`, not either production
implementation. They are project-owned construction vectors, not externally
published official vectors; licensed official archives live in `../fixtures`.

Native test loaders use `DIRHASH_TEST_VECTORS` when set and otherwise locate
this directory relative to their ecosystem root. Docker build wrappers pass
it as the named BuildKit context `test-vectors`, so both builds use one resource
copy without enlarging the runtime distribution or embedding tests in it.
