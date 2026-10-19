# Upstream archive vectors

These unmodified small archives are bundled so conformance tests need no
network access. Their licenses apply to the fixtures, not to dirhash's code.
Archive-byte SHA-256 pins in the tests detect accidental fixture replacement;
they are **not** the published logical-content vectors.

## Go module: rsc.io/quote v1.5.2

- Archive: <https://proxy.golang.org/rsc.io/quote/@v/v1.5.2.zip> (2,987 bytes).
- Official vector: <https://sum.golang.org/lookup/rsc.io/quote@v1.5.2>.
- Module ZIP h1: `h1:w5fcysjrx7yqtD/aO+QwRjYZOKnaM9Uh2b40tElTs3Y=`.
- Separate `/go.mod` h1:
  `h1:LzX7hefJvL54yjefDEDHNONDjII0t9xZLPXsUe+TKr0=`, from the same
  official lookup record.
- License: BSD-3-Clause; the full copyright, conditions, and disclaimer are
  retained inside the archive at `rsc.io/quote@v1.5.2/LICENSE`.

Use the stored `rsc.io/quote@v1.5.2/` prefix unchanged. This archive has no
explicit directory markers, so both `--h1` and `--h1-go` match the official
module checksum. The suite also runs the other constructions against its
independent serialization oracles; those values are not upstream vectors.

The separate `go.mod` vector is checked with both `--h1` and `--h1-go`,
using a directory and a generated ZIP containing only the unchanged file
named exactly `go.mod` (no module/version prefix or directory markers).
This is Go's single-file h1 construction, not a plain file SHA-256.

## Go module: github.com/google/uuid v1.6.0

- Archive: <https://proxy.golang.org/github.com/google/uuid/@v/v1.6.0.zip>
  (31,981 bytes).
- Official vector: <https://sum.golang.org/lookup/github.com/google/uuid@v1.6.0>.
- Module ZIP h1: `h1:NIvaJDMOsjHA8n1jAhLSgzrAzy1Hgr+hNrb57e+94F0=`.
- Archive-byte SHA-256 pin:
  `d0f02f377217f42702e259684e06441edbf5140dddcc34ba9bea56038b38a6ed`.
- License: BSD-3-Clause (Google); the full notice is retained inside the
  archive at `github.com/google/uuid@v1.6.0/LICENSE`.

Like quote, the stored `github.com/google/uuid@v1.6.0/` prefix is kept
unchanged and the archive has no explicit directory markers, so both `--h1`
and `--h1-go` match the official module checksum.

## Go module: github.com/pkg/errors v0.9.1

- Archive: <https://proxy.golang.org/github.com/pkg/errors/@v/v0.9.1.zip>
  (17,866 bytes).
- Official vector: <https://sum.golang.org/lookup/github.com/pkg/errors@v0.9.1>.
- Module ZIP h1: `h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=`.
- Archive-byte SHA-256 pin:
  `d4c36b8bcd0616290a3913215e0f53b931bd6e00670596f2960df1b44af2bd07`.
- License: BSD-2-Clause (Dave Cheney); the full notice is retained inside
  the archive at `github.com/pkg/errors@v0.9.1/LICENSE`.

Same properties as the other module ZIPs: prefix retained, no directory
markers, official h1 applies to the unchanged archive.

## Recursive wrapper regression test

`test_recursive_wrapped_official_archive_vectors` builds a temporary outer
ZIP (never checked in) holding `a/quote-v1.5.2.zip`, `b/uuid-v1.6.0.zip`,
and `c/errors-v0.9.1.zip` — the unchanged module archives at second-level
prefixes — and runs `--recurse`. The parent hashes the nested archives' raw
bytes; each nested root directly matches its published module h1 because
module ZIPs inherently keep their `module@version/` prefix. This is why the
recursive official test uses module ZIPs rather than the SWH/Nix archives:
those published roots describe the tree *after* removing the packaging
directory, while `--strip-components` applies only to the outermost input,
never to a nested archive, so their raw nested roots intentionally do not
equal the published stripped values.

## Software Heritage: sample-folder

- Archive (555 bytes):
  <https://raw.githubusercontent.com/SoftwareHeritage/swh-model/e546dd95914d50de447464002b4cbf2790fe4784/swh/model/tests/data/dir-folders/sample-folder.tgz>.
- Published directory vectors:
  <https://github.com/SoftwareHeritage/swh-model/blob/e546dd95914d50de447464002b4cbf2790fe4784/swh/model/tests/swh_model_data.py>.
- Upstream test connecting the vectors to this archive:
  <https://github.com/SoftwareHeritage/swh-model/blob/e546dd95914d50de447464002b4cbf2790fe4784/swh/model/tests/test_cli.py>.
- License: GPL-3.0-or-later. The upstream license and author list are retained
  as `swh-model-LICENSE.txt` and `swh-model-AUTHORS.txt`. The unchanged archive
  contains the fixture's source-form files; it is not linked into dirhash.

The tests hash the whole archive with `--strip-components=1` and additionally
materialize the regular-file subtrees `sample-folder/bar` and
`sample-folder/bar/barfoo`, asserting their published SWH directory IDs:

| Subtree | Published SWHID |
|---|---|
| Archive root after stripping | `swh:1:dir:e8b0f1466af8608c8a3fb9879db172b887e80759` |
| `bar` | `swh:1:dir:3c1f578394f4623f74a0ba7fe761729f59fc6ec4` |
| `bar/barfoo` | `swh:1:dir:c3020f6bf135a38c6df3afeb5fb38232c5e07087` |

The upstream root includes an empty directory. SWH preserves it according to
the official construction, whereas Git omits it; the root vector exercises
this distinction alongside executable files and symlinks.

## Nix systems: default at d36eeed

- Archive (1,213 bytes):
  <https://codeload.github.com/nix-systems/default/tar.gz/d36eeed142f88b5a636f2e3856a53c61654cf29b>.
- Official NixOS lockfile:
  <https://github.com/NixOS/nixos-homepage/blob/2661ccb3de9f2dd3288c32ccc46d097e261ead30/flake.lock>,
  `nodes.systems.locked.narHash`.
- Published recursive NAR SHA-256:
  `sha256-uuanbkFk8a313Zfrxdcz8Us/yQtaxNnKJtX8v0ZPpd8=`.
- Published Git tree SHA-1:
  `534351a8910b267d46775dcd0bf1678a52505a39`, from the
  [source commit](https://github.com/nix-systems/default/commit/d36eeed142f88b5a636f2e3856a53c61654cf29b)
  and its [GitHub API record](https://api.github.com/repos/nix-systems/default/commits/d36eeed142f88b5a636f2e3856a53c61654cf29b).
- License: MIT, Copyright (c) 2023 nix-systems; full notice retained in the
  archive's `LICENSE` file.

Use `--strip-components=1` to remove GitHub's packaging directory. Nix's
`narHash` here describes the unpacked source tree, not the compressed archive
bytes or a flat hash of its contents. The conformance test asserts both
published values directly on this archive.

## Coverage limits

No small archive with officially published values for **all** h1, Git tree,
SWH directory, and NAR constructions was identified. Official vectors are
asserted only for the schemes stated above; independently computed oracle
values remain clearly separate. Together these five archives provide
published vectors for both h1 interpretations (three module ZIPs), Git tree
SHA-1, SWH directory SHA-1, and NAR SHA-256, alongside the suite's
independent construction tests.
