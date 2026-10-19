# dirhash specification

(this is GitHub Copilot AI Slop).

## 1. Purpose and conformance

`dirhash` computes reproducible roll-up hashes of a directory or an archive's
logical contents. Independent Java and Go implementations MUST implement the
same input interpretation, hash constructions, validation, CLI, and output for
mutually supported inputs. ZIP codec availability may differ as specified below.

The Java distribution is an executable JAR requiring Java 21 or later:

```text
java -jar dirhash.jar [options] INPUT
```

The Go distribution is a standalone native executable:

```text
dirhash [options] INPUT
```

Both distributions target Windows, Linux, and macOS. Required dependencies,
including codecs and digest implementations, MUST be bundled. No external Git,
archive, hashing, or download executable is required at runtime.

MUST, MUST NOT, SHOULD, and MAY describe conformance requirements. In particular,
an unsupported-streaming error defined below is a specified outcome, not
permission to silently omit a hash or nested archive.

## 2. Core semantics

### 2.1 Input and selected root

Exactly one explicit input is required. It is either:

* A local filesystem directory.
* A local supported archive file.
* An HTTP or HTTPS URL whose response is a supported archive.

There is no implicit current directory, stdin input, multiple-input mode, or
general URL-scheme support in version 1. A top-level ordinary file is an error.
`--` ends option parsing. Local paths use the host platform's syntax.

Resolve a symlink used as the explicitly selected local input to establish its
actual root. This does not imply following symlinks found inside that root.
For a directory input, the resolved directory is the confinement base for
`--h1-go` filesystem dereferences.

The selected directory itself, archive filename, URL, and containing directory
are not components of its logical-tree hash. Actual top-level directories
inside an archive are retained; there is no automatic stripping of a package
or `module@version/` directory unless explicitly requested through
`--strip-components`.

### 2.2 Common input abstraction

Input adapters expose a tree of directories, regular files, and symbolic links,
plus source metadata needed for compatibility interpretations. Each entry
provides:

* Its root-relative logical path and original archive name, if applicable.
* Entry type, logical byte length, and available Unix permission bits.
* A stream of regular-file bytes, or the symbolic link's stored target bytes.
* Source identity and integrity information needed to detect corruption/change.

Archive hard links are resolved into regular-file content references. Implicit
parent directories and explicit directory records establish the same logical
directories. Directory metadata other than their existence is not hashed.

The common abstraction does not force every hash scheme to select the same
metadata. Go-compatible h1 retains an archive-entry manifest view in addition
to the common tree.

### 2.3 Directory/archive equivalence

Common-tree hashes MUST agree for directory and archive inputs representing
the same included tree, file bytes, link targets, and relevant executable
metadata. Compression, entry order, timestamps, owners, archive comments, and
container layout are not part of a common-tree hash.

Equivalence is scheme-specific:

| Property | Common h1 | Git tree | SWH directory | NAR |
|---|---|---|---|---|
| File paths and bytes | Included | Included | Included | Included |
| Executable metadata | Ignored | Owner-execute | Any execute bit | Owner-execute |
| Symlink target bytes | As file-like content | Typed symlink blob | Typed symlink blob | Typed symlink |
| Empty directories | Ignored | Omitted | Preserved | Preserved |
| Timestamps/ownership | Ignored | Ignored | Ignored | Ignored |

Missing Unix executable metadata means non-executable. Do not infer executable
status from extensions, file contents, Windows executable associations, or the
current user's effective access. Preserve available Unix modes so each scheme
can apply its native rule: Git/NAR use `mode & 0100`; SWH uses `mode & 0111`.

Consequently, Git SHA-1 and the SWH directory digest normally agree but MAY
differ for group/other-only executable modes or included empty directories.
The SWHID is not universally just
an alternative display of the computed Git SHA-1 tree.

### 2.4 ZIP directory markers

A ZIP directory marker is an explicit entry whose name ends in `/`, such as
`lib/`. It ordinarily has zero content. These two ZIP entry lists represent the
same non-empty logical directory:

```text
Archive A: lib/                 Archive B: lib/a.txt
           lib/a.txt
```

The common tree has one directory `lib` and one file `lib/a.txt` in both cases.
Common h1 does not hash the marker. Git/SWH and NAR do not add a second entry
for it. However, Go's `HashZip` includes stored directory entries in its h1
manifest, so `--h1-go` can differ between A and B.

A marker `empty/` with no descendants represents a real empty directory:
SWH and NAR preserve it; common h1 and Git tree omit it.
A non-empty payload on a ZIP directory marker is invalid.

### 2.5 Ordinary entries, hard links, and special files

Filesystem hard links hash like independent regular files with identical
contents. Their inode relationship is not hashed.

TAR hard links refer only to entries within that archive. Support forward
references, resolve chains to regular files, and reuse content digests where
possible. Missing targets, cycles, or non-regular ultimate targets are errors.
Resolve against the complete archive namespace before exclusions; an included
link can obtain bytes from an excluded target, without including that target's
name in a hash. Hard-link target paths follow TAR's archive-root-relative
convention, not symlink-relative resolution. Never consult the host filesystem.
Use the referring entry's represented mode for its own tree position.

Sparse regular files hash their complete logical bytes, including zero-filled
holes; hash values MUST NOT depend on allocation or sparse representation.
Sparse map metadata is not part of file content.

Sockets, FIFOs, devices, unsupported reparse points, and other special entry
types are errors in every mode, including when excluded. Never read them or
invent empty content for them.

## 3. Names and baseline validity

### 3.1 Unicode and ordering

Logical names MUST be losslessly representable as Unicode scalar values and
UTF-8. Reject malformed encodings and unpaired surrogates in every mode; never
substitute replacement characters. Do not normalize Unicode, fold case, or
apply locale-dependent collation to hashed names.

Decode ZIP names using the UTF-8 flag when set. Otherwise use a valid Info-ZIP
Unicode Path extra field (`0x7075`, version 1, matching name CRC), or CP437 when
that field is absent. A present malformed or contradictory encoding field is
an error. TAR/PAX effective paths MUST be valid UTF-8. Filesystem adapters MUST
reject names they cannot expose losslessly under this contract.

Unless a hash explicitly requires another ordering, compare UTF-8 byte
sequences lexicographically as unsigned bytes. Java UTF-16 string ordering is
not an acceptable substitute.

`--h1-go` ZIP manifests use Go's original stored filename bytes, not CP437
transcoding or Unicode Path substitutions, to reproduce Go's manifest.
Logical decoded names still undergo baseline/strict validation and exclusions.
This source-name view is distinct from the common UTF-8 tree.

### 3.2 Root-relative path grammar

Logical paths use `/` on all platforms. Archive names MUST NOT contain:

* Absolute, UNC, or drive-qualified paths, including drive-relative `C:x`.
* NUL, backslashes, empty interior components, or `..` components.
* Interior `.` components.

As a narrow interoperability exception, leading `./` components mean the
selected root and are removed for common-tree interpretation. A standalone
`./` is a root directory marker; bare `.` is not accepted as an entry name.
Preserve the original stored spelling for
Go-compatible archive manifests. Strip one directory-marker suffix `/` for
tree interpretation, not for the compatibility manifest.

Root markers MUST be directories. Reject an empty ordinary entry name.
Reject collisions after logical mapping, such as `a` and `./a`.

Reject duplicate explicit logical entry paths, duplicate root markers, and
file/directory conflicts in every mode. A previously inferred parent directory
may subsequently receive one explicit directory record; that is not a
duplicate. An entry below a path occupied by a file or symlink is a conflict;
never follow archive links to construct the entry namespace.

The baseline applies before exclusion filtering. Filename LF is additionally
invalid whenever either h1 scheme is selected, because its manifest is
newline-delimited. Baseline rules are deliberate restrictions on accepting
otherwise library-readable archives.

### 3.3 Explicit archive-prefix stripping

`--strip-components=N` removes exactly N leading slash-separated components
from entry paths in the original archive input only, including an archive
downloaded from a URL. N is a non-negative decimal integer, default 0.
Reject this option for a filesystem-directory input. It is not reapplied to
nested archives, even under recursion.

Count components in the effective stored entry path after PAX/GNU/ZIP name
resolution but before common-tree leading-`./` interpretation. Each leading
`.` component counts toward N; the directory-marker trailing slash is not a
component:

| Stored path | N | Transformed path |
|---|---|---|
| `./pkg/a.txt` | 1 | `pkg/a.txt` |
| `pkg/a.txt` | 1 | `a.txt` |
| `./pkg/a.txt` | 2 | `a.txt` |
| `./pkg/a.txt` | 0 | Unchanged stored spelling; common tree interprets `./` as root |

If a non-directory entry has N or fewer components, fail with `INVALID_PATH`;
do not silently skip it, even if excluded. A directory entry entirely consumed
by stripping establishes the projected root and is not an h1-go manifest
entry with an empty name. Surviving explicit directory markers retain their
trailing slash in the compatibility view.

Validate the original namespace before stripping, then reject duplicate or
conflicting surviving projected paths. Stripping must not hide an unsafe
original name. Apply common-tree `./` interpretation to the remaining path.
Hash all schemes, including `--h1-go`, using the explicitly transformed names;
Go compatibility then concerns the transformed entry set, not the original
archive's go.sum value. With N=0, retain the original compatibility semantics.

Use original logical paths for exclusions, archive discovery identities,
reported locations, and diagnostics. Stripping does not affect nested archive
contents or their raw-byte contribution to the parent.

Do not rewrite symlink-target bytes. Strict mode validates links in both the
original namespace and the surviving projected namespace; an existing original
target must not become dangling or escaping after projection. Resolve hard
links in the original namespace before projecting their referring entry names.

## 4. Hash schemes and digest overrides

### 4.1 Selection

At least one explicit hash-selection switch is required. There are no default
hashes. An unqualified switch selects its default primitive:

| Switch | Scheme key | Default digest |
|---|---|---|
| `--h1` | `h1` | `sha256` |
| `--h1-go` | `h1-go` | `sha256` |
| `--gittree` | `gittree` | `sha1` |
| `--swhid` | `swhid` | `sha1` |
| `--nar` | `nar` | `sha256` |
| `--plain` | `plain` | `sha256` |

Each accepts `:<digest>`, for example `--nar:blake3` or
`--gittree:sha256`, `--plain:sha256`. Multiple selections coexist; equivalent duplicate
selections are deduplicated. There is no bare positional digest argument.

Required primitive names and output widths are:

| Name | Bytes |
|---|---|
| `sha1` | 20 |
| `sha256` | 32 |
| `sha512` | 64 |
| `blake2b-256` | 32 |
| `blake2b-512` | 64 |
| `blake3` | 32 |
| `sha3-256` | 32 |
| `sha3-512` | 64 |

BLAKE2b-256 uses BLAKE2b configured for a 32-byte digest, not truncation of
BLAKE2b-512. BLAKE3 is unkeyed with its first 32 output bytes, with no
derive-key context. SHA-3 means standardized SHA-3, not legacy Keccak. There
are no SHAKE modes, bare `sha3` alias, keys, plugins, or runtime-provider names.
Unknown schemes, digests, and malformed switches are usage errors before I/O.

The selected primitive replaces hashing throughout a construction, including
all children. It never means "rehash the standard final digest."

### 4.2 Common-tree h1

Let `H` be the selected primitive. Select included regular files and symbolic
links, excluding directory markers. For each selected entry:

1. Use its common root-relative path, encoded as UTF-8.
2. For a regular file, compute `H(logical file bytes)`.
3. For a symlink, compute `H(stored link-target bytes)` without dereferencing.

Sort by the full UTF-8 path bytes. Construct one manifest line per entry:

```text
lowercase_hex(content_digest) + "  " + path_bytes + LF
```

The result digest is `H(concatenation_of_manifest_lines)`. All hex digits are
lowercase ASCII; the separator is exactly two ASCII spaces; LF is byte `0x0a`.
Empty input hashes an empty manifest. Do not add `./`, an archive name, or a
platform line ending.

With SHA-256, output `h1:` followed by padded standard Base64 of the result
digest. This is the Go Hash1 construction over the common-tree file list,
not a promise to match Go's ZIP adapter or a module's go.sum.

h1 does not encode entry type: a link and a regular file at the same path with
identical bytes have the same h1 contribution. Git/SWH/NAR distinguish them.

### 4.3 Go-compatible h1

Use the same manifest construction as above but a different input view:

**Filesystem directory:** reproduce `dirhash.HashDir(root, "", Hash1)` on
accepted inputs. Enumerate non-directory entries without walking symlinked
directories, use Go-style root-relative `/` paths, and open symlinks as files.
The fully resolved read target MUST remain under the resolved base. Reject
escaping/dangling/cyclic links and targets that cannot be read as regular
files. This confinement is unconditional and does not depend on `--strict`.

**ZIP:** reproduce `dirhash.HashZip` on accepted inputs. Include every included
explicit entry, including directory markers, using its original stored name
bytes and uncompressed payload. A symlink entry contributes its stored target
payload. Do not insert inferred directory entries or remove `./` or an actual
module prefix.

**TAR/TAR.GZ extension:** Go has no HashTar helper. Define the analogous
manifest over effective archive-entry names, preserving their stored spelling
after PAX/GNU name resolution, including explicit directory/root markers.
Directories contribute empty bytes; links contribute target text for symlinks
and resolved logical file content for hard links. Sparse files contribute
reconstructed bytes. PAX/GNU control records are not entries in this manifest.
Label the source as TAR/TAR.GZ in output; do not claim a Go-standard TAR hash.

Exclusions remove selected source entries without rewriting the surviving
names. Explicit prefix stripping is the separate opt-in transformation in
section 3.3. Standard SHA-256 uses `h1:` output; overrides use nonstandard labels.

Compatibility restrictions include confinement, Unicode/path validation,
duplicate rejection, unsupported features, exclusions, explicit prefix
stripping, and resource limits.
Do not reproduce Go's duplicate-ZIP last-entry lookup behavior.

Actual go.sum module ZIP compatibility additionally requires exactly the
module's entry names, including its `module@version/` prefix, and its included
file set. A go.sum `version/go.mod` checksum concerns a separate single-file
manifest and is not automatically produced from a whole module tree.
Go currently defines Hash1 only; dirhash does not invent an `h2:` version.

### 4.4 Git tree

Let `H` be the selected primitive, with raw output width `w`. For a regular
file or symlink target byte sequence `B`, compute:

```text
blob_id = H(ASCII("blob " + decimal(length(B))) + NUL + B)
```

Decimal lengths have no sign or leading zeroes, except the value `0`.
Use byte lengths, never character counts.

Select the included tree and recursively omit empty directories; the root
itself remains a tree even when empty. Use these mode strings:

| Logical entry | Mode bytes |
|---|---|
| Non-executable regular file | `100644` |
| Owner-executable regular file | `100755` |
| Symbolic link | `120000` |
| Non-empty directory | `40000` |

For each directory, sort immediate entries by their UTF-8 name bytes with a
virtual `/` appended to directory names for comparison only. This is Git's
tree ordering, not ordinary full-path sorting.

Serialize each entry, using its unmodified single-component name:

```text
mode_ascii + SPACE + name_utf8 + NUL + raw_child_id
```

Concatenate entries into `T`, then compute:

```text
tree_id = H(ASCII("tree " + decimal(length(T))) + NUL + T)
```

Child IDs are `w` raw bytes, not hexadecimal. The root tree ID is the result.
SHA-256 therefore changes every blob/tree ID, child-reference width, and
affected tree length; it is not SHA-256 of a SHA-1 tree or digest.

SHA-1 and SHA-256 are Git-standard object hash choices. Other selected
primitives use this tool's explicitly nonstandard Git-style construction.
Do not create commits, read the Git index, apply attributes/filters, infer
submodules/gitlinks, or implicitly exclude `.git` or ignored files.

### 4.5 Software Heritage directory

Use the tree construction in section 4.4, except that a regular file is
executable when any represented Unix execute bit is set (`mode & 0111`).
Preserve included empty subdirectories, as required by the official Software
Heritage directory construction. An empty subdirectory contributes a `40000`
entry referring to its empty tree ID; recursively preserve parent directories
containing only empty subdirectories. Git's empty-subtree omission does not
apply to SWH. This distinction also applies to digest overrides.

With SHA-1, render the root as:

```text
swh:1:dir:<40 lowercase hexadecimal digits>
```

This is a version-1 directory SWHID for the selected tree. It makes no claim
that the object has been ingested into the Software Heritage archive.
There are no qualifiers, revision IDs, or content SWHID outputs in version 1.

Digest overrides replace all blob/tree hashes and reference widths, as for
Git. They MUST NOT use `swh:1:dir:` or be described as standard SWHIDs.

### 4.6 Nix Archive hash

Serialize the included common tree as a canonical NAR stream and hash that
stream with the selected primitive. Do not hash an existing input container's
bytes as though they were its NAR representation.

Define `S(B)` as:

```text
uint64_little_endian(length(B)) + B + zero_padding_to_8_byte_boundary
```

Padding applies to `B` and is zero to seven zero bytes. Tokens below are ASCII;
names are UTF-8 and file/target values are their actual bytes.

The stream is `S("nix-archive-1")` followed by the root node. Serialize nodes:

* Regular: `S("("), S("type"), S("regular")`, optionally
  `S("executable"), S("")` for owner-executable files, then
  `S("contents"), S(file_bytes), S(")")`.
* Symlink: `S("("), S("type"), S("symlink"), S("target"),
  S(link_target_bytes), S(")")`.
* Directory: `S("("), S("type"), S("directory")`, its entries, then `S(")")`.

Each directory entry is `S("entry"), S("("), S("name"), S(name),
S("node"), child_node, S(")")`. Sort children by unmodified UTF-8 name bytes;
do not apply Git's virtual-slash sorting rule. Preserve included empty
directories. The root is always a directory for this tool.

SHA-256 output uses the Nix-compatible SRI form
`sha256-<padded standard Base64 digest>`. This is a NAR hash, not a Nix store
path, derivation ID, or hash of the input ZIP/TAR bytes. Non-SHA-256 selections
receive the tool's nonstandard labels.

### 4.7 Value rendering and scheme identity

JSON MUST identify both scheme and digest, independently of value. Text labels
omit the digest suffix when it equals the scheme default, including when that
default was selected explicitly; nondefault digests retain the suffix:

| Selection | `value` |
|---|---|
| `h1:sha256`, `h1-go:sha256` | `h1:<standard padded Base64>` |
| `gittree:sha1`, `gittree:sha256` | Lowercase hex object ID |
| `swhid:sha1` | `swh:1:dir:<lowercase hex>` |
| `nar:sha256` | `sha256-<standard padded Base64>` |
| `plain:<any digest>` | `<digest>:<lowercase hex>` |
| Any other combination | `dirhash:1:<scheme>:<digest>:<lowercase hex>` |

The `h1` versus `h1-go` label MUST NOT be dropped merely because both values
start with `h1:`. A custom `swhid` scheme label denotes construction lineage,
not a valid SWHID. No `h2:` or invented standard SWH scheme version is emitted.

`plain` values use the canonical primitive name as label, for example
`sha256:<64 hex digits>` or `blake2b-256:<hex>`. This is deliberately neither
SRI nor `h1:`, and it does not use the `dirhash:1:` prefix: it is a byte
digest, not a tree construction, and the `scheme` field (`plain`) still
distinguishes it in every record. The form is not a promise of
interoperability with other tools' checksum syntax.

### 4.8 Plain archive-byte digest

`--plain[:<digest>]` selects scheme key `plain`, default digest `sha256`
(consistent with `h1`/`nar`; any section 4.1 primitive may be named). It is
the selected primitive applied once over the exact original bytes of an
archive, with no tree, manifest, path, or normalization semantics. It is not
a tree hash and does not take part in directory/archive equivalence.

* Only archive inputs are meaningful. A directory root (or a directory as the
  selected root under any selection set) with `--plain` fails with
  `UNSUPPORTED_FORMAT` (exit 3) before publishing anything; plain results are
  never silently omitted and the other selections are not reduced to succeed.
  Ordinary top-level files remain errors as in section 2.1.
* Root digest: all bytes of the selected local archive file, or of the HTTP(S)
  response body exactly as downloaded (identity coding, section 8.4), never
  of a decompressed or re-encoded representation. A `.tar.gz` digests the
  gzip bytes, not the TAR. Accepted prefix bytes, concatenated gzip members,
  ZIP comments, and other non-strict allowances of section 5.2 are included
  in the digest as stored.
* With `--recurse`, additionally emit a plain record for each included
  discovered archive. Its bytes are exactly that nested entry's decoded
  payload as the enclosing archive yields it as a regular file (section 5.3):
  ZIP entries after reversing the ZIP method (stored/DEFLATE/...) only, TAR
  entries as their data (sparse holes reconstructed, hard links resolved),
  and inside a `.tar.gz` the entry data of the decompressed TAR. A nested
  `.tgz` entry digests its own gzip bytes, a nested `.jar` its own ZIP bytes.
  Nothing is extracted, repacked, or additionally decompressed, and no
  member of the nested archive is part of its own plain digest.
* Prefix stripping (`--strip-components`) and exclusion of entries inside an
  archive never change any plain value. Exclusion of a whole nested archive
  (section 6) removes its record and prevents opening it, as for tree
  schemes. Discovery rules (section 5.2) and `--strict`/non-strict handling
  are unchanged; discovery and recursion limits apply as for any scheme.
* Validation is unchanged: the root and every discovered included archive are
  parsed and integrity-checked (CRCs, sizes, checksums, truncation, strict
  accounting) exactly as for tree schemes, even when `plain` is the only
  selection. Any failure publishes no output. A valid archive digest is never
  published for a corrupt input.
* `plain` records follow the existing order and identity rules and sort last
  among schemes (section 11.2). Other selections' values are unaffected.

## 5. Archives and discovery

### 5.1 Required formats and features

Required containers are ZIP/ZIP64, including ordinary JAR/WAR/EAR, TAR, and
TAR.GZ (`.tgz`). TAR supports ustar, PAX, GNU long-name/long-link records,
hard links, and GNU sparse formats: legacy GNU and PAX sparse 0.0, 0.1, 1.0.
Reject invalid/overlapping/out-of-range sparse extents and reconstruct holes
without allocating their full length. Other sparse extensions MAY be rejected.

Only implement codecs available through standard libraries or established
ecosystem decoder libraries. Do not implement/port a compression algorithm or
fork a codec to achieve feature parity. Small ZIP framing/decoder-registration
adapters are permitted; a new entropy decoder is not an adapter.

The version-1 ZIP method matrix is:

| ID | Method | Java | Go |
|---|---|---|---|
| 0 | Stored | Required | Required |
| 8 | DEFLATE | Required | Required |
| 9 | Deflate64 | Existing Commons Compress decoder | Unsupported unless a suitable established decoder is adopted |
| 12 | BZIP2 | Existing Commons Compress decoder | Standard-library decoder, registered for ZIP |
| 20, 93 | Zstandard | Established decoder integration | Established pure-Go decoder integration |
| 95 | XZ | Commons Compress/XZ for Java | Established pure-Go XZ decoder integration |
| 14 | ZIP-LZMA | Not required; no custom codec/port | Not required; no custom codec/port |
| 98 | ZIP PPMd variant I | Not required; no custom codec/port | Not required; no custom codec/port |

Stored, DEFLATE, BZIP2, Zstandard, and XZ are the shared intended set;
Deflate64 is additionally intended for Java. A release MUST list its actual
supported ZIP methods in `--help`; do not advertise unimplemented or untested
integrations. A method without an adopted decoder fails explicitly with
`UNSUPPORTED_METHOD`, never a silently omitted entry. Different ecosystems may
reject different codec inputs, but MUST agree on accepted common inputs.
There are no CLI switches for writing/recompressing archives.

Having a generic LZMA or 7z PPMd decoder is not evidence of ZIP method support.
In particular, a PPMd variant-H/PPMd7 decoder does not implement ZIP variant I.
Additional methods require a compatible existing decoder and interoperability
fixtures; they are not justification for hand-writing codecs.

Support ZIP comments, ZIP64 end/size records, extra fields, and data descriptors
with their defined variants. ZIP64 and descriptors are not compression methods.
Encryption, split/multi-disk ZIP, unsupported methods/features, and non-TAR gzip
payloads are explicit errors. An APK signing block or arbitrary ZIP-based
ecosystem extension is not implicitly a supported structural record.

Integrity checks run in all modes: validate applicable ZIP/gzip CRCs and sizes,
TAR header checksums, decoder termination, sparse maps, and truncation.
PAX/GNU control records affect interpretation but are not logical files.

Narrow ZIP compatibility exception: for Unix creator IDs 3 or 19, an external
Unix mode exactly `0177777` (`0xffff`), a stored name ending in `/`, and zero
uncompressed entry bytes, with no ASi Unix extra field, may represent a
malformed producer directory marker.
In non-strict mode, interpret this exact combination as a directory and emit
`WARN_ZIP_DIRECTORY_MODE` on stderr, identifying the entry and recorded mode.
Strict mode rejects it as `SPECIAL_FILE` without applying the exception.
Other invalid types, nonempty entries, missing directory suffixes, conflicting
extra-field types, CRC/size mismatches, and structural corruption remain errors.
Emit each warning once per logical entry, not once per metadata scan or reread.
Retain warnings until the complete operation succeeds; they do not relax atomic
stdout or permit a partial result after an error.

A second non-strict ZIP-only exception accepts empty directory markers with
repeated trailing `/` characters, such as `9/java.activation//`. Remove the
trailing slashes for the common logical path; preserve the original stored name
for `h1-go`. The remaining path must be nonempty and pass all normal validation.
Interior empty components, absolute paths, dot components, conflicting entry
types, and nonempty directory payloads remain errors. Emit
`WARN_ZIP_DIRECTORY_SLASH` once per entry after the complete operation succeeds,
identifying the original name. Strict mode rejects this condition as
`INVALID_PATH`. Normal collision and integrity checks still apply.

### 5.2 Discovery

Discover archives by content, not solely by filename. A supported archive
named `payload.bin` is eligible. Require sufficient structural evidence, such
as a valid TAR header/checksum or valid ZIP record structure, rather than
classifying an arbitrary short magic-byte coincidence as a complete archive.
A valid non-zero TAR header with a matching checksum takes precedence over
ZIP-like signature bytes in its filename. Apply the same content detection
rules to original inputs and nested entries.
For ZIP discovery, require a local header of at least 30 bytes with version
needed at least 10 and a nonzero filename length; or an empty classic EOCD
of at least 22 bytes with zero disk numbers, entry counts, central-directory
size and offset; or an empty ZIP64 EOCD of at least 56 bytes with record size
at least 44 and zero disk entry count, total entry count, central-directory
size and offset. ZIP64 version fields do not constrain this sniff. Each
predicate also requires its corresponding ZIP signature. These predicates
identify candidates only; full format and integrity validation remains required.
Gzip magic alone is not evidence of a TAR archive. Inspect a bounded decoded
prefix for TAR structure before treating an extensionless or ordinary `.gz`
member as TAR.GZ. Valid gzip containing non-TAR data (for example `.js.gz`)
remains an opaque ordinary member. A `.tar.gz` or `.tgz` suffix still requires
a valid TAR.GZ archive and mismatched content is an error.
A failed TAR-header checksum during discovery is a nonmatch for a member
without an explicit `.tar`, `.tar.gz`, or `.tgz` suffix, not a fatal archive
error. Keep that member opaque. This does not suppress integrity errors after
positive archive identification, I/O failures, or resource-limit violations.

Also recognize these case-insensitive suffixes:
`.zip`, `.jar`, `.war`, `.ear`, `.tar`, `.tar.gz`, `.tgz`.
A non-excluded entry with one of these suffixes MUST be a valid supported
archive when discovery is active; malformed candidates and format/suffix
mismatches are errors. ZIP-family suffixes are interchangeable, as are
`.tar.gz` and `.tgz`.

Discovery inside a selected root is active under `--recurse` or `--strict`.
Otherwise nested archive files remain opaque ordinary files. Never discover
through a symlink or fetch any URL mentioned in an archive.

In all modes, reject bytes after the ZIP EOCD and its declared comment.
Outside strict mode, a reader MAY accept an accounted-for ZIP with an
executable prefix or concatenated gzip members. The logical ZIP is the
terminal structurally valid central-directory/EOCD chain; TAR stops at its
first complete end marker; gzip members are concatenated before TAR parsing.
None of these allowances permit corruption, duplicate logical entries, or
silently ignoring an unsupported codec in a selected archive.

### 5.3 Recursion and parent contributions

`--recurse` computes every selected scheme/digest for the root and each
included discovered archive, at every permitted nesting level.

In a parent tree, an archive file contributes its original byte contents,
not an expanded tree or a nested result digest. Nested exclusions likewise do
not change those parent bytes. Enabling recursion MUST NOT itself change a
root or parent hash.

Recompression can change a parent's hash while leaving the nested archive's
own common-tree hashes unchanged. This is intended.

A `plain` selection (section 4.8) is the only construction that digests an
archive's original bytes as a result of its own; recursion with it reports the
raw bytes of each included nested archive entry, never a tree.

`--strict` without `--recurse` discovers and validates included nested archives
but publishes hashes only for the root. It does not require constructing
unrequested nested hashes. With both switches, validate and report them.

## 6. Exclusions and nested paths

By default include everything, including hidden entries, `.git`, and files
mentioned by `.gitignore`. No ignore file is read automatically.

`--exclude=PATTERN` is repeatable. Patterns are case-sensitive and anchored at
the original selected root; they are not reapplied relative to every nested
archive root.

Pattern grammar:

* `/` separates directory components.
* `*` matches zero or more Unicode scalar values within one component.
* A whole component `**` matches zero or more directory components.
* A trailing `/` matches a directory and excludes its entire subtree.
* `!/` enters an archive; neither wildcard crosses this boundary.
* `!!` represents a literal `!` in an entry name, including within patterns.
* All other characters are literal. No `?`, character classes, negation,
  backslash escaping, environment expansion, or gitignore re-inclusion.

Malformed patterns are usage errors. CLI/shell quoting is outside this grammar.

Examples:

```text
*.tmp                         root-level temporary files only
**/*.tmp                      temporary files at any ordinary directory depth
.git/                         the root's .git directory
dir/file.zip                  do not open this archive
dir/file.zip!/.git/            exclude .git inside this particular archive
dir/file.zip!/**/*.tmp         temporary files inside this archive
outer.zip!/inner.jar!/x.txt    a file inside two archive boundaries
a!!b.zip!/x.txt               x.txt inside the archive named a!b.zip
```

An exact path without a trailing slash excludes that entry; if it is a
directory, its descendants are also excluded. An inner pattern does not
exclude or discover its containing archive by itself: discovery still
requires `--strict` or `--recurse`.

Exclusions affect membership and discovery, not basic input validity:

* Still enumerate and validate excluded entries' names/types, duplicate paths,
  and the containing archive's physical integrity.
* Strict link resolution uses the full containing-archive namespace, including
  excluded targets. A link does not become dangling merely through exclusion.
* Do not open an excluded nested archive, even with `--strict`; its internal
  structure/names/links are outside validation scope.
* Integrity validation MAY require decompressing excluded ordinary payloads.

The same boundary syntax is used for displayed nested paths. JSON also exposes
structured archive-entry components, so parsing this display syntax is optional.
Boundary notation is never inserted into bytes hashed for an individual root.

## 7. Strict validation

`--strict` is validation, not hash normalization. For an accepted input and
unchanged exclusions, it MUST NOT alter a result value.

### 7.1 Portable names

Apply these checks to filesystem and archive logical names, including excluded
entries encountered in the selected namespace:

* Reject all Unicode general-category `Cc` and `Cf` characters, including
  controls, DEL/C1, bidi controls, joiners, and other format characters.
* Reject Unicode noncharacters: U+FDD0 through U+FDEF and each plane's final
  U+FFFE/U+FFFF code points. Surrogates are already invalid in every mode.
* Reject Windows-reserved characters `< > : " | ? *`; separators/backslashes
  are governed by the baseline path grammar.
* Reject components ending in ASCII dot or space.
* Reject Windows device basenames case-insensitively, including `CON`, `PRN`,
  `AUX`, `NUL`, `CONIN$`, `CONOUT$`, `COM1` through `COM9`, and `LPT1` through
  `LPT9`, also with an extension. Include superscript 1/2/3 aliases for COM/LPT.
* Reject sibling names colliding under
  `NFC(full_default_case_fold(NFC(name)))`.

Use Unicode 16.0.0 normalization, general categories, and default full case
folding data, independent of the runtime's bundled Unicode version. These
checks do not modify the names used in hashes. Do not silently normalize or
select one colliding entry.

### 7.2 Archive symlinks

Strict symlink-target confinement applies to archives only. Common-tree
filesystem symlinks remain undereferenced, including under `--strict`.
The independent `--h1-go` filesystem-read confinement always applies.

In a strict archive, each symlink target MUST be lossless UTF-8, non-empty,
relative, free of NUL/backslashes, and not drive-qualified or UNC/absolute.
Resolve relative to the link's parent directory. Target `.` and `..` have
their path-resolution meanings; reject any traversal above the archive root.
Resolve existing symlink chains component by component: a lexical prefix
test alone is insufficient.

The final target MUST exist within the complete archive namespace, whether
included or excluded. Directories, including inferred directories and the
archive root, are valid destinations. Reject dangling targets, cycles,
non-directory intermediate components, and any chain escaping the root.
Never resolve through the host filesystem. Hash original target bytes, not
the resolved or normalized destination.

### 7.3 ZIP physical accounting

A strict ZIP MUST be a single fully accounted-for archive:

* No self-extracting/opaque prefix, unexplained gaps, overlapping entry ranges,
  appended archive, or trailing bytes.
* Inventory local entries independently of the central directory and establish
  a one-to-one correspondence; central-directory order need not match local
  order.
* Reconcile names, methods, relevant flags, offsets, sizes, and CRCs, honoring
  defined ZIP64 fields and descriptor placeholders.
* Reconcile semantic extra fields present in both views. Do not require every
  local/central extra-field byte to be identical when the ZIP format permits
  different placement or representation.
* Validate data descriptors, per-entry decompression boundaries, central
  directory extent/counts, ZIP64 records, and final end records.
* Account explicitly for any supported standard ancillary record; an unknown
  block is not excused as metadata.
* End exactly after the EOCD's declared comment.

An EOCD-looking byte sequence within a comment or payload is not a second
archive end. Encrypted central directories and unsupported extensions fail.
Merely opening a ZIP with a library is not evidence that these checks passed.

### 7.4 TAR and gzip physical accounting

Strict TAR requires valid records, checksums, extents, and entry padding; a
complete pair of 512-byte zero end blocks; and only zero block padding
afterward, up to physical EOF. Reject appended TAR archives/nonzero junk and
truncated/non-block-aligned termination. Account for sparse extension records,
PAX records, and GNU name/link records as defined by their formats.

Strict TAR.GZ requires exactly one valid gzip member containing exactly one
strict TAR stream. Validate header/trailer fields, CRC and ISIZE modulo
2^32 against the actual expanded count. Reject additional gzip members and
all bytes after the member. Gzip optional header fields are permitted when
valid; they do not affect the logical hash.

## 8. Streaming, memory, and temporary files

### 8.1 Shared payload reads

For non-NAR schemes, read each original regular-file payload at most once
per logical occurrence. Feed each read buffer to all applicable raw-content,
blob, CRC, parent-container, and discovery consumers. Metadata and digests
MAY be retained for sorting and bottom-up finalization; whole file payloads
MUST NOT be buffered in memory except for the bounded nested archive buffers
in section 8.3. Ordinary member payloads MUST NOT be spooled to disk.

The bound is metadata plus per-entry/per-selection digest state, codec state,
bounded link-target/header state, and fixed-size transfer buffers. It is not
memory proportional to total ordinary member payload length. Do not extract
members into filesystem trees; section 8.3 permits opaque nested archives.
Independently named filesystem hard links or intentional `--h1-go` symlink
reads are separate logical occurrences; digest reuse is allowed where safe.

Metadata-only preflight is allowed on seekable containers. Reading structural
ZIP ranges without rereading file payloads is not a second payload pass.
Bytes consumed to sniff a file MUST be replayed from a bounded lookahead
buffer rather than reread. Forward hard links can reuse retained target
digests without storing target payloads.

### 8.2 NAR exception

NAR needs actual bytes in canonical tree order, not a roll-up of independent
file digests. NAR selections MAY cause additional reads or decompression
passes to determine lengths/metadata and serialize the canonical NAR stream.
This exception permits additional source passes, not payload buffering or
arbitrary member spooling. Nested archive spooling follows section 8.3.
Share each such read with any still-pending compatible hash
consumers and share one NAR serialization across selected NAR primitives.

Seekable temporary nested archives may supply metadata to every selected
construction, not just NAR. A combination must not fail solely because a
nested ZIP uses deferred sizes that its central directory resolves.

Plain exception: `plain` MAY likewise use an additional read pass, but is not
required to. Preferred: feed the same single read of an archive's bytes to the
plain digest and the parser. Allowed: (a) re-read the seekable root file or
downloaded temporary file; (b) for a nested archive, re-decode from the
seekable root along its entry path (each enclosing layer re-streamed in turn)
to feed only the digest. Bytes need not come from one pass, but: nested
archives MUST NOT be extracted into member trees; bounded seekable memory
buffers and private nested archive spools are permitted under section 8.3. Digest state
is bounded; the re-decoded stream MUST pass the
same integrity checks and match the first pass's inventory/length (mismatch
is `INPUT_CHANGED`, corruption `ARCHIVE_INTEGRITY`); and a parser that
finishes early (for example at a TAR end marker or ZIP end) must still feed
every remaining payload byte to the digest. `plain` adds no
`UNSUPPORTED_STREAMING` condition of its own, but it does not rescue a nested
archive whose required discovery/validation is itself unsupported or
non-streamable under the other rules: that remains an explicit error, never a
dropped nested record. Re-reads of a nested payload are not charged again
against `--max-expanded-bytes` or `--max-entries`; they consume time and I/O.
The root's own file length is not counted, as for tree schemes.

### 8.3 Explicit streaming limitations

Fail with `UNSUPPORTED_STREAMING`, rather than changing semantics, when a
selected non-NAR construction cannot be completed under these constraints.
For example:

* Git/SWH blob headers need uncompressed length before payload bytes.
* A nested ZIP using deferred sizes/descriptors may reveal that length only
  after content, with its central directory not seekable in advance.
* A nested stream may expose essential type/permission/name metadata only
  after the bytes that would need the corresponding typed hash.
* A TAR variant may require unavailable metadata before a selected digest can
  be initialized correctly.

Known metadata from a top-level or temporary seekable archive avoids these failures.
Do not reject a stream merely because payload order differs from manifest
order when retaining per-file digests suffices.

Included nested archives MAY be materialized as opaque byte streams to make
them seekable. Keep streams up to 10,000,000 bytes (10 MB, inclusive) in bounded
seekable memory rather than creating temporary files. For unknown lengths,
retain at most this threshold before spilling to a private temporary file;
larger known streams may go directly to disk. Preserve all already buffered
bytes on spill. The threshold applies to the encoded nested archive bytes,
not their expanded member contents, and is per archive, not a global memory
limit. Implementations use an aggregate 10,000,000-byte retained archive-buffer
budget; spill when that budget is exhausted even for a smaller individual
archive. Release retained buffers when no longer needed.
Implementations MUST use this capability
when needed to process supported nested ZIP/JAR metadata, including deferred
sizes and central-directory names/types, for all selected constructions.
Do not extract members into a filesystem tree. Use generated private paths,
never archive-controlled filenames, and do not materialize excluded archives.
Place disk spools outside selected input directory trees. Do not exempt
directory timestamps or sizes from mutation checks to accommodate spool writes;
if no safe external temporary location is available, fail explicitly.
Share the original source read with parent hashes and integrity consumers;
spooling must not change parent bytes, nested root identity, or output paths.
Enforce the expanded-byte budget before writing each chunk; bytes already
charged during the original read are not charged again for spool reads.
Bound memory independently of spool length. Delete temporary files on success,
handled failure and cancellation; an uncatchable kill may leave private orphans.
Temporary-file failures are explicit I/O errors with no partial output.
Count actual entry bytes through EOF and require equality with every applicable
declared uncompressed length, including ZIP descriptor and central-directory
values once available. Reject shorter or longer content as `ARCHIVE_INTEGRITY`
in every mode, with no published results. A seekable buffer or spool must not
bypass CRC, decoder termination, or length reconciliation. For sparse entries,
compare reconstructed logical bytes with the declared logical length.
Truly unavailable metadata can still require an explicit error.
A required codec remains required; codec support does not promise that
every codec/container/nesting/hash combination is streamable.

### 8.4 URL download exception

HTTP(S) input is downloaded once to a private opaque temporary file and then
processed as a seekable local archive. Together with section 8.3, this defines
the allowed archive-payload disk materialization. Arbitrary member spools are
not allowed. No attacker-controlled archive name is used as a temporary path.

Verify TLS, follow at most five redirects, and reject HTTPS-to-HTTP downgrade
redirects. Reject URL user-info credentials and unsupported schemes. Do not
forward sensitive request state to another origin. Version 1 has no
authentication flags or remote resources referenced from within archives.

Request an identity HTTP content coding; never transparently decompress an
HTTP response into different archive bytes. Fail on a non-identity content
coding, unsuccessful response, truncation, redirect violation, timeout, or
download-limit violation. Bound transfer waits; do not retry or resume a
partially downloaded representation automatically.

Do not begin archive processing until the successful transfer is complete.
Delete temporary files on success and handled failure/cancellation. A forced
process kill can leave a private orphan; do not claim guaranteed cleanup after
an uncatchable termination.

## 9. Resource limits and concurrent changes

Required limit flags:

| Flag | Default | Meaning |
|---|---|---|
| `--max-depth=N` | `16` | Archive-boundary depth; original root is depth 0 |
| `--max-entries=N` | `1000000` | Entries across the original tree and all opened archives |
| `--max-expanded-bytes=N` | `107374182400` | 100 GiB expanded archive file payload |
| `--max-download-bytes=N` | `10737418240` | 10 GiB HTTP response body |

Values are non-negative decimal integers or the literal `unlimited`.
Zero is a real zero limit, not a disabling shortcut. Reject invalid/overflowing
values; do not clamp them.

Count explicit archive entries and implicit directories once per logical
archive namespace, plus filesystem entries once per logical path, excluding
each namespace's root. Also count archive control/header records against the
entry budget so metadata-only bombs cannot bypass it. Excluded entries in an
opened namespace still count; unopened excluded archives do not contribute
internal entries.

Count reconstructed regular-file bytes, including sparse holes and hard-link
logical content occurrences, plus symlink payload bytes, at each opened
archive layer. Thus a nested archive contributes its raw file length in its
parent and its expanded entry bytes in its own namespace. Apply to strict
validation even when nested hashes are not reported. Count excluded payloads
that must be inspected. Do not charge repeated NAR passes again against this
logical expansion limit; they still consume actual time/I/O.

An archive inside an original directory is at depth 1; entries in an original
archive are at depth 0 and archives contained in it are at depth 1.
Exceeding a limit is an error, never truncation or a skipped subtree.
There is no compression-ratio limit.

Finite limits do not guarantee a particular heap requirement. Implementations
MUST avoid stack overflow on deeply nested ordinary directory paths and MUST
report allocation/representation limits explicitly rather than changing
results. Do not silently impose ecosystem-library directory-depth limits.

Callers MUST supply quiescent inputs. Compare available file identity, type,
size, modification metadata, and namespace inventories before/after relevant
reads/passes. Fail on detected changes, including during NAR rereads; do not
automatically retry. These checks are not a filesystem snapshot and cannot
prove absence of concurrent modification.

## 10. CLI contract

```text
dirhash HASH_SELECTION... [--strict] [--recurse]
        [--exclude=PATTERN]... [--strip-components=N]
        [--format=text|json|jsonl]
        [--max-depth=N] [--max-entries=N]
        [--max-expanded-bytes=N] [--max-download-bytes=N]
        [--] INPUT
```

`HASH_SELECTION` is one of `--h1`, `--h1-go`, `--gittree`, `--swhid`, `--nar`,
or `--plain`, each with an optional `:<digest>`. The spelling is `--recurse`;
there is no `--recursie` or other alias.

The Java invocation accepts the identical argument sequence after its JAR name.
Support `--help` and `--version` without an input or hash selection; these do
not traverse/download anything. Unknown flags are errors. Options taking
values accept `--name=value` and `--name value`; digest qualifiers use the
colon syntax only. Repeated singleton options are usage errors; exclusions
and hash selections are repeatable.

Examples:

```text
dirhash --h1 --gittree:sha256 --nar .
java -jar dirhash.jar --h1-go library.jar
dirhash --swhid --strict --recurse --format=json source.tar.gz
dirhash --nar:blake3 --exclude="lib/a.jar!/.git/" --recurse tree
dirhash --h1 --strip-components=1 source-with-package-root.tar.gz
dirhash --plain:sha256 --recurse bundle.zip
dirhash --h1 --max-download-bytes=21474836480 https://example.org/a.zip
```

The `.` in the first example is an explicit filesystem input, not a hashed
root-name prefix. Shell quoting in these examples is illustrative.

## 11. Output and failures

### 11.1 Atomic result publication

Compute/validate the entire invocation before writing any result bytes to
stdout. Buffer result records in memory, not payloads. On an input,
validation, resource, unsupported-feature, or computation error, fail fast,
write diagnostics only to stderr, and publish no successful result records.
Do not downgrade errors to warnings or continue with a reduced hash set.

This prevents late central-directory/trailing-junk failures from leaving
success-shaped checksum output. A physical stdout failure during final
publication can still leave truncated output; exit nonzero and report it
when possible. No byte-stream interface can retract bytes already written.

### 11.2 Stable ordering and identities

Report the original root first. Within each namespace, report discovered
archives depth-first, sorting archive entry paths by exact UTF-8 bytes.
Validated-only nested archives under `--strict` produce no result records.

Within each root, order schemes as `h1`, `h1-go`, `gittree`, `swhid`, `nar`,
`plain`.
Within each scheme, order digests as listed in section 4.1. Command-line switch
order does not affect output order.

Every record has these fields in this order:

| Field | Meaning |
|---|---|
| `path` | Native filesystem path followed by `!/` only across archive boundaries |
| `source` | Original input argument, never a temporary/local download path |
| `archiveEntries` | Array of unescaped discovery paths; for a directory root the first is its filesystem-relative archive path |
| `inputType` | `directory`, `zip`, `tar`, or `tar.gz` for this result root (never `directory` for `plain`) |
| `scheme` | Scheme key from section 4.1 |
| `digestAlgorithm` | Canonical primitive name |
| `value` | Rendered value from section 4.7 |

For the original root, `archiveEntries` is empty. For
`outer.zip!/lib/inner.jar!/data.zip`, it is
`["lib/inner.jar","data.zip"]`; components remain whole root-relative paths,
not individual directory names. The literal source string is retained in
`source`. For a directory input, join the first discovered archive path to
the source using native filesystem separators; this is not an archive boundary.
Thus a directory `C:\repo` containing `lib/a.jar` reports `C:\repo\lib\a.jar`,
and an archive inside that JAR reports `C:\repo\lib\a.jar!/inner.zip`.
Keep the same `archiveEntries` identity array; only display-path formatting
changes. Filesystem-only paths retain literal `!` characters. When an actual
archive boundary is appended, escape literal `!` characters in the filesystem
prefix and archive entry names using `!!` to distinguish them from `!/`.
Native separators in display paths do not affect hashed logical paths.

Do not include timestamps, durations, thread order, temporary names, absolute
path expansion, or terminal-dependent coloring. UTF-8 encoding and LF line
endings apply on all platforms. Values and fields MUST agree across
implementations for the same source spelling and accepted logical input.

### 11.3 Formats

`--format=text` is the default. Emit one line per record:

```text
<scheme>[:<nondefault digestAlgorithm>]<TAB><value><TAB><display path><LF>
```

The final column has no surrounding quotes. Preserve backslashes and double
quotes literally for readable filesystem paths. Escape U+0000 through U+001F
using JSON control escapes (including lowercase `\u00xx` where needed), so
paths cannot create extra output columns or lines. Text paths are for display;
use JSON or JSONL for unambiguous machine-readable paths.

`--format=jsonl` emits one JSON object with the fields above per LF-terminated
line, with no wrapper or progress messages.

`--format=json` emits one object followed by LF:

```json
{"schemaVersion":1,"results":[]}
```

Replace the empty array with ordered result objects. JSONL uses the same
version-1 record schema. Serialize compact JSON with the field order above,
no insignificant whitespace, raw valid UTF-8 for non-ASCII scalars, and
standard escapes for quotes, backslashes, and controls. Escape control
characters not having a short JSON escape as lowercase `\u00xx`.
There is no BOM.

### 11.4 Exit status and diagnostics

| Exit | Meaning |
|---|---|
| `0` | All requested results published, or successful help/version |
| `1` | Invalid/corrupt/unsafe input, detected change, or limit exceeded |
| `2` | CLI usage error |
| `3` | Unsupported archive feature or unsupported streaming combination |
| `4` | I/O, network, temporary-file, output, or other runtime failure |

A diagnostic begins with a stable error code and the affected source/nested
location, followed by a useful reason. Required categories include
`INVALID_PATH`, `INVALID_ENCODING`, `DUPLICATE_ENTRY`, `NAME_COLLISION`,
`UNSAFE_SYMLINK`, `DANGLING_SYMLINK`, `INVALID_HARDLINK`, `SPECIAL_FILE`,
`ARCHIVE_INTEGRITY`, `ARCHIVE_LAYOUT`, `UNSUPPORTED_FORMAT`,
`UNSUPPORTED_METHOD`, `UNSUPPORTED_STREAMING`, `LIMIT_EXCEEDED`,
`INPUT_CHANGED`, `NETWORK_ERROR`, and `IO_ERROR`.
Human-readable diagnostic locations preserve native backslashes without JSON
quoting; escape unsafe control/format characters. Use native filesystem paths
for filesystem children and `!/` only for actual archive boundaries.
`SPECIAL_FILE` for ZIP entries identifies the offending member, complete octal
Unix mode, and file-type bits, rather than naming only the containing archive.

Escape diagnostic path/control characters so they cannot inject terminal
control sequences or additional diagnostic lines. Do not expose URL secrets,
credentials, payload contents, or stack traces in ordinary diagnostics.
No fallback value, empty digest, or partial-success exit is permitted.

## 12. Cross-language acceptance requirements

Both implementations MUST share fixtures with expected exact values, output
records, or stable error categories. Tests MUST cover the requirement itself,
not merely successful library opening.

Required coverage:

1. Empty root, empty file, nested paths, Unicode ordering, LF rejection,
   directory markers, empty directories, leading `./`, and real root folders.
2. Directory/ZIP/TAR/TAR.GZ equivalence under each common scheme, with mode and
   empty-directory differences explicitly exercised.
3. Independent Go Hash1/HashDir/HashZip oracle comparisons on accepted inputs,
   module-prefix fixtures, directory-marker differences, CP437/raw-name
   differences, and documented safety restrictions.
4. Git SHA-1 and SHA-256 oracle trees, virtual-slash ordering, executable-bit
   normalization, symlink blobs, omitted empty subtrees, and no `.git` magic.
5. SWH v1 serialization, preserved empty directories, and native executable
   rules, including fixtures where Git/SWH agree and empty directories or
   group/other-only execute bits make them differ.
6. NAR byte-for-byte reference serialization, SRI output, directory ordering,
   empty directories, owner-execute, target bytes, and additional-pass cases.
7. Known-answer primitive tests, especially BLAKE2b-256 versus truncation,
   BLAKE3's fixed output, and SHA-3 versus Keccak; every primitive under every
   scheme with distinct nonstandard labels.
8. Every adopted ZIP codec and explicit unsupported-method outcomes, ZIP64,
   descriptors, extra fields, comments, local
   versus central inconsistencies, overlapping extents, prefixes, gaps,
   hidden local entries, duplicate entries, junk, and truncated payloads.
9. PAX/GNU names, metadata records, hard-link forward references/cycles,
   GNU sparse variants and zero holes, TAR termination, gzip integrity,
   concatenation, and appended data.
10. Strict control/format/reserved names, noncharacters, invalid UTF-8,
    NFC/case-fold collisions, target existence, indirect escape, cycles, and
    host-filesystem-independent archive resolution.
11. Root and nested exclusions, literal `!`, `!/` boundaries, no automatic
    pattern reset, unchanged parent bytes, and excluded-archive non-opening.
12. Strict nested validation without recursive output, recursion invariance of
    parent hashes, malformed suffixed candidates, and extensionless archives.
13. Instrumented payload reads proving non-NAR single-read fan-out, bounded
    buffers, bounded private nested archive spools, NAR extra passes, and explicit failures
    when the required stream metadata is unavailable.
14. Limit boundaries, sparse/recursive expansion accounting, metadata bombs,
    deep ordinary trees, changed inputs, and errors after initial hash work
    producing no stdout.
15. HTTP redirects, TLS failure/downgrade, non-identity coding, truncation,
    missing Content-Length, download limits, temporary cleanup, and no nested
    remote fetching.
16. Prefix-depth counting including `./`, N=0 preservation, consumed directory
    markers, shallow-file errors, transformed collisions, projected link
    validity, original-path exclusions, and no stripping of nested archives.
17. Exact CLI, text/JSON/JSONL escaping and ordering, stdout/stderr separation,
    exit statuses, and Java/Go interoperability on Windows/Linux/macOS.

18. `plain` (section 4.8): known-answer digests of exact archive
    bytes for ZIP, TAR, and TAR.GZ roots with every primitive, labelled
    `<digest>:<hex>`; root bytes unchanged by `--strip-components` and entry
    exclusions; accepted non-strict prefix/concatenated-gzip bytes included;
    ZIP trailing bytes rejected even with plain-only selections;
    HTTP downloaded bytes; `--recurse` nested ZIP/JAR/TAR/TGZ raw entry
    payloads (stored versus DEFLATE entries, TAR sparse/hard-link entries,
    nested archive inside gzip-wrapped TAR) matching a reference digest of the
    standalone extracted nested file; excluded nested archive omitted; strict
    without recurse reports root only; directory root and top-level ordinary
    file errors with no output; corrupt root or nested archive yields no
    output; mixed selections leave tree values and record order unchanged;
    recursion does not change any parent value; re-read paths charge no extra
    expanded bytes/entries and detect changed input; only section 8.3 spooling.

Golden vectors SHOULD include their logical input descriptions and reference
construction, not only opaque fixture archives. Compressed fixture variants
MUST NOT change expected common-tree hashes. Reference programs may be used in
test development; they are not runtime dependencies.

## 13. Deliberate non-goals and limitations

Version 1 does not implement content verification against an expected value,
Git working-set/index emulation, gitignore, automatic package-root stripping,
commit hashes, SWH qualifiers, IPFS, OCI digests, Nix store paths, archive
extraction, custom compression codecs/ports, authentication flags, arbitrary
Unix byte filenames, or universal streamability of nested archives.

SHA-1 support exists for interoperability and MUST NOT be represented as a
modern collision-resistant security recommendation. A matching checksum
establishes agreement under a particular scheme and input selection, not
authenticity or trust in the publisher.

## 14. Repository layout and builds

The repository separates ecosystem tooling and sources:

```text
SPECIFICATION.md
README.md
build.sh
build.ps1
java/
    Dockerfile
    build.sh
    build.ps1
    pom.xml
    src/main/java/
    src/test/java/
go/
    Dockerfile
    build.sh
    build.ps1
    go.mod
    *.go
```

Both top-level scripts build both ecosystems by default and can select one.
The ecosystem-local scripts build only their own project. Scripts MUST locate
the project relative to themselves, not assume a particular working directory,
and propagate Docker/build failures. POSIX scripts are invoked with `sh`;
PowerShell scripts require no local Java/Maven/Go installation.

All compilation and tests run in Linux Docker builder containers. Buildx's
local exporter publishes artifacts without installing build tools on the host.
Builds may fetch images and dependency artifacts; the distributed tool remains
standalone.

The Java builder uses Maven on Azul Zulu JDK 21. An available upstream image is
`ghcr.io/carlossg/maven:3.10.0-azulzulu-21`; this Azul variant is maintained by
the Maven image project but is not published as a Docker Official `maven`
variant. Pin the selected image and compile with Java release 21. Run tests
before exporting `dist/java/dirhash.jar`, with runtime dependencies included
and a main-class manifest. Do not require a Java runtime container to execute
the resulting JAR.

The Go builder uses a version-pinned Go image, with CGO disabled. Reused
libraries MUST support pure-Go cross-compilation; do not add C toolchains or
target-specific shared-library runtime requirements merely to obtain codecs.
Run formatting checks, `go vet`, and tests natively in the builder, then
cross-compile:

| Artifact | GOOS | GOARCH | Architecture baseline |
|---|---|---|---|
| `dist/go/dirhash-linux-amd64` | `linux` | `amd64` | `GOAMD64=v1` |
| `dist/go/dirhash-linux-arm64` | `linux` | `arm64` | ARMv8-A, `GOARM64=v8.0` |
| `dist/go/dirhash-windows-amd64.exe` | `windows` | `amd64` | `GOAMD64=v1` |

Use trimmed source paths and no embedded local VCS state. Foreign-target
execution tests are separate from successful cross-compilation; do not claim
ARM or Windows runtime validation solely from an emitted binary.

Git attributes enforce LF text files except `*.ps1`, which use CRLF in working
trees. Binary archives and executable artifacts are not text-normalized.

The executable artifacts implement hashing and archive processing; builds
run ecosystem tests before export. Shared conformance tests exercise packaged
artifacts, including small licensed upstream archives with published vectors.

## 15. Library reuse and implementation-effort assessment

This assessment distinguishes ready codecs from ZIP framing and validation.
Library APIs/releases must be verified and pinned when adopted; a master-branch
feature or enum constant alone is not proof of released decoder support.
No optional codec in this assessment justifies custom compression development.

| Area | Reuse opportunity | Remaining effort/risk |
|---|---|---|
| Stored/DEFLATE ZIP, gzip | Java and Go standard libraries | Low for content access; not sufficient for strict physical validation |
| ZIP BZIP2 | Commons Compress; Go `compress/bzip2` registered with `archive/zip` | Low adapter effort; no new algorithm |
| ZIP Zstandard | Existing Java decoders; Go `klauspost/compress/zstd` | Integration and framing/termination tests; no new algorithm |
| ZIP XZ | Commons Compress with XZ for Java; Go `ulikunitz/xz` | Integration and memory/termination limits; no new algorithm |
| ZIP Deflate64 | Commons Compress has a decoder | Java reuse; no suitable Go decoder adopted, so reject there rather than port |
| ZIP LZMA | Raw LZMA decoders exist, but are not automatically ZIP method-14 decoders | Extra ZIP-specific framing/integration; excluded from requirements pending suitable reuse |
| ZIP PPMd | 7z PPMd support is not ZIP variant-I support | Highest codec-port risk; excluded unless an established compatible decoder is adopted |
| Ordinary and sparse TAR | Commons Compress and Go `archive/tar` already cover substantial GNU/PAX/sparse reading | Medium integration effort; hard-link graph resolution and strict raw-record accounting remain custom |
| Digest primitives | JDK/Go crypto plus established BLAKE2/BLAKE3 libraries, e.g. Bouncy Castle in Java | Low/moderate integration; do not implement cryptographic primitives |
| h1, Git/SWH tree encoding | Short, externally defined constructions | Moderate custom orchestration/serialization, not custom cryptography |
| NAR encoding | Compact deterministic serialization | Encoding is modest; canonical-order scheduling over sequential archives is expensive and may require many allowed passes |
| Strict ZIP accounting | Library entry metadata and codec streams can be reused | High custom validation effort: independent local/CD inventories, extents, descriptors, hidden entries, EOF and overlaps |
| Strict TAR/gzip EOF checks | Existing parsers/decompressors | Supplementary raw-record/member accounting; a library reporting EOF is not enough |
| Pinned Unicode-16 rules | ICU/data-pinned Unicode libraries and published tables | Medium dependency/data-version work; Java 21's character tables alone do not satisfy this contract |
| Nested archive processing | Existing streams/codecs with bounded seekable buffers and private spill files | Seekable preflight resolves late ZIP metadata; genuinely unavailable metadata still fails explicitly |
| Lossless filesystem links | Ordinary filesystem APIs for common names/targets | Java portability needs care for raw target bytes; never silently replace/re-encode an inaccessible byte sequence |

The largest unavoidable self-implemented portions are strict archive-layout
validation and the cross-scheme streaming/tree scheduler. They are core tool
semantics, not reasons to write compression algorithms. Relaxing codec parity
removes the need to port Deflate64 or ZIP PPMd just to match the other language.

Sparse TAR is not inherently a new compression algorithm: reuse existing
readers to reconstruct its logical stream and add tests for the required
variants. NAR is likewise a serialization, not a new digest primitive; its
main cost under the agreed constraints is additional I/O rather than complex
encoding.

Useful implementation sources:

* [Commons Compress ZIP support and streaming limitations](https://commons.apache.org/proper/commons-compress/zip.html)
* [Commons Compress ZIP decoder dispatch](https://github.com/apache/commons-compress/blob/master/src/main/java/org/apache/commons/compress/archivers/zip/ZipFile.java)
* [Go ZIP decoder registration](https://pkg.go.dev/archive/zip#Reader.RegisterDecompressor)
* [Pure-Go Zstandard](https://github.com/klauspost/compress/tree/master/zstd)
* [Pure-Go XZ/LZMA](https://github.com/ulikunitz/xz)
* [Go 7z PPMd variant-H decoder; not ZIP variant I](https://github.com/stangelandcl/ppmd)
* [Go TAR reader and sparse handling](https://github.com/golang/go/blob/master/src/archive/tar/reader.go)
* [Maven image project's Azul variants](https://github.com/carlossg/docker-maven#linux-based-images)

## 16. Authoritative format references

The explicit selections and restrictions in this document take precedence
over ecosystem import defaults. References explain the external formats;
their future revisions do not silently change this version's semantics.

* [Go dirhash source and Hash1 construction](https://github.com/golang/mod/blob/master/sumdb/dirhash/hash.go)
* [Go module checksum documentation](https://go.dev/ref/mod#authenticating)
* [Git object model](https://git-scm.com/book/en/v2/Git-Internals-Git-Objects)
* [Git hash-function transition](https://git-scm.com/docs/hash-function-transition)
* [Git permission normalization](https://github.com/git/git/blob/master/object.h)
* [SWHID specification 1.2: core identifiers](https://www.swhid.org/specification/v1.2/5.Core_identifiers/)
* [SWH filesystem mode interpretation](https://github.com/SoftwareHeritage/swh-model/blob/master/swh/model/from_disk.py)
* [NAR serialization](https://nix.dev/manual/nix/2.34/protocols/nix-archive/)
* [Nix filesystem executable interpretation](https://github.com/NixOS/nix/blob/master/src/libutil/posix-source-accessor.cc)
* [PKWARE ZIP APPNOTE](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
* [Info-ZIP extra fields](https://infozip.sourceforge.net/doc/)
* [GNU TAR sparse formats](https://www.gnu.org/software/tar/manual/html_node/Sparse-Formats.html)
* [Gzip format, RFC 1952](https://www.rfc-editor.org/rfc/rfc1952)
* [BLAKE2, RFC 7693](https://www.rfc-editor.org/rfc/rfc7693)
* [BLAKE3 specification and reference implementation](https://github.com/BLAKE3-team/BLAKE3)
* [SHA-3, FIPS 202](https://doi.org/10.6028/NIST.FIPS.202)
* [Unicode 16.0.0 data](https://www.unicode.org/Public/16.0.0/ucd/)
