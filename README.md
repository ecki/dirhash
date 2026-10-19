# dirhash

Independent Java and Go implementations of the semantics in
[SPECIFICATION.md](SPECIFICATION.md).

| Method | Name | Reference |
|---|---|---|
| `--h1` | Go module `h1` directory hash | [`golang.org/x/mod/sumdb/dirhash.Hash1`](https://github.com/golang/mod/blob/master/sumdb/dirhash/hash.go) |
| `--h1-go` | Go module `h1` directory hash, strict semantics | [`golang.org/x/mod/sumdb/dirhash.HashZip`](https://github.com/golang/mod/blob/master/sumdb/dirhash/hash.go) |
| `--gittree` | Git tree object hash | [Git object model](https://git-scm.com/book/en/v2/Git-Internals-Git-Objects) |
| `--swhid` | Software Heritage directory identifier | [SWHID specification 1.2, core identifiers](https://www.swhid.org/specification/v1.2/5.Core_identifiers/) |
| `--nar` | Nix Archive hash | [Nix Archive serialization](https://nix.dev/manual/nix/2.34/protocols/nix-archive/) |
| `--plain` | Raw archive-byte digest | [dirhash specification, section 4.8](SPECIFICATION.md#48-plain-archive-byte-digest) |

Hash a directory, ZIP/JAR, TAR, TAR.GZ, or an archive downloaded over HTTP(S),
without extracting member trees.

## Usage

```text
dirhash HASH_SELECTION... [--strict] [--recurse]
        [--exclude=PATTERN]... [--strip-components=N]
        [--format=text|json|jsonl]
        [--max-depth=N] [--max-entries=N]
        [--max-expanded-bytes=N] [--max-download-bytes=N]
        [--] INPUT
```

Select one or more constructions: `--h1`, `--h1-go`, `--gittree`, `--swhid`,
`--nar`, or `--plain`. Digest overrides use a colon, for example `--nar:blake3` or
`--gittree:sha256`. Native hash selection is default.

`--plain[:digest]` (default `sha256`)
digests the exact original bytes of an archive (not a tree hash; no directory
input), and with `--recurse` also each nested archive's raw entry bytes.

## Container builds

Install Docker with a running Linux engine and Buildx. Host Java, Maven, and
Go installations are not required. From PowerShell at the repository root:

```powershell
.\build.ps1
```

Or build one ecosystem:

```powershell
.\build.ps1 -Ecosystem Java
.\build.ps1 -Ecosystem Go
```

On a POSIX shell, use `sh ./build.sh`, `sh ./build.sh java`, or `sh ./build.sh go`.
Each ecosystem directory also has its own `build.ps1` and `build.sh`; invoke
those directly to build just that ecosystem, from any working directory.
All six scripts delegate compilation and tests to Docker.

The Java builder uses `ghcr.io/carlossg/maven:3.10.0-azulzulu-21`, pinned to its
multi-platform image digest. This is the Maven image project's Azul Zulu
variant, not the Docker Official `maven` image. Maven compiles for Java 21,
runs unit tests, and packages an executable, dependency-shaded JAR.

The Go builder uses Go 1.27.2. It checks formatting, runs tests and `go vet`
on the builder's native architecture, and cross-compiles with CGO disabled:

| Exported artifact | Target |
|---|---|
| `dist\java\dirhash.jar` | Java 21+ |
| `dist\go\dirhash-linux-amd64` | Linux x64, baseline AMD64 v1 |
| `dist\go\dirhash-linux-arm64` | Linux ARMv8-A, `GOARM64=v8.0` |
| `dist\go\dirhash-windows-amd64.exe` | Windows x64, baseline AMD64 v1 |

Cross-compilation is not execution testing of the foreign targets. The Docker
build smoke-checks the JAR; Go unit tests execute on the build platform.
The exported JAR and executables do not require Docker to run.

```powershell
java -jar .\dist\java\dirhash.jar --help
.\dist\go\dirhash-windows-amd64.exe --version
```

Equivalent explicit Buildx exports:

```powershell
docker buildx build --target artifacts --build-context test-vectors=.\tests\vectors --build-context project-license=. --file .\java\Dockerfile --output type=local,dest=.\dist\java .\java
docker buildx build --target artifacts --build-context test-vectors=.\tests\vectors --build-context project-license=. --file .\go\Dockerfile --output type=local,dest=.\dist\go .\go
```

Builds may download container images and Maven/Go dependencies. Source files are
copied into builder containers, and only artifacts are exported. Docker build
caches stay under Docker's management; there is no host toolchain installation.

### Distribution licenses and notices

Both artifact directories include the canonical project `LICENSE` and `NOTICE`.
The shaded JAR also includes their original bytes at `META-INF/LICENSE` and
`META-INF/NOTICE`. Dependency legal resources are preserved in separate
artifact-specific directories under `META-INF/licenses`, so duplicate filenames
cannot discard another dependency's copyright or terms. Release-pinned upstream
texts supplement dependencies whose published JARs omit legal resources; see
`java/licenses/README.txt`, including the BSD option selected for bundled
Zstandard native code and the full ICU third-party notices.

**Distribute `dist/go/THIRD-PARTY-LICENSES` together with every Go executable**,
as well as `LICENSE` and `NOTICE`; bare executables do not embed these texts.
The build derives sidecars from packages linked for all three release targets,
including transitive modules, package-local notices, the Go runtime/standard
library, and generated Unicode data. Test-only and lint dependencies are excluded.

Container builds check the actual JAR's legal bytes, runtime dependency
coverage, service descriptor preservation, and absence of signatures and test
resources. The Go collector checks linked-module coverage and copied bytes.
Dependency updates still require upstream license review; these checks do not
constitute legal certification. Test fixtures retain their separate licenses
and are not included in either runtime distribution.

## Tools Usage

Compare existing Java and Windows Go artifacts on local directories with
PowerShell 7:

```powershell
.\test-dirs.ps1 -Directories C:\data\one,C:\data\two
.\test-dirs.ps1 -Mode Plain -Directories C:\data\one,C:\data\two
.\test-dirs.ps1 -Directories C:\data\one -Algorithms sha256,blake3,sha3-512
.\test-dirs.ps1 -Directories C:\data\one -Schemes h1,gittree -Algorithms sha256 -StrictModes NonStrict
```

Default algorithms are `sha1` and `sha256`; `-Algorithms` selects any supported
digest list in either mode. Default `-Mode Tree` tests every non-plain scheme
with those digests on the specified roots with `--recurse`, both with and
without `--strict`. `-Schemes` selects tree constructions; `-StrictModes`
accepts `Strict`, `NonStrict`, or both (the default). Plain mode tests `plain`
with the selected digests and strict modes.

Successful JSON must match exactly for both implementations.
Failures must match exit status and error category and must not publish stdout.
`-Mode Plain` collects archive files throughout the named roots by
supported suffix or ZIP/gzip/TAR header and tests each with `--plain` and
recursion.

## Description

```powershell
.\dist\go\dirhash-windows-amd64.exe --h1 --gittree:sha256 --nar .
java -jar .\dist\java\dirhash.jar --h1-go library.jar
java -jar .\dist\java\dirhash.jar --h1 --strict --recurse --format=json bundle.zip
.\dist\go\dirhash-windows-amd64.exe --nar:blake3 --strip-components=1 source.tar.gz
```

`--h1` uses the normalized logical tree. `--h1-go` preserves Go's archive
filename and explicit-directory-marker interpretation; these can produce
different results for the same ZIP. Git omits empty directories; SWH and NAR
preserve them. Executable bits and symlinks follow each construction's native
rules. See specification sections 2-4 before treating different schemes as
interchangeable identifiers.

`--recurse` additionally reports contained archives. The parent still hashes
the archive's original bytes, not its expanded tree.

`--strict` validates
archive structure, portable names, and archive-local symlink confinement;
it also validates included nested archives without requiring `--recurse`.
Nothing is printed to stdout unless the whole operation succeeds.

Archive prefix stripping is specified as `--strip-components=N`, for the
original archive input only. A stored leading `./` counts as a component;
non-directory entries too shallow for N are errors. Nested archives are not
stripped. Exclusions still use original root-relative paths.

Exclusions are root-anchored, case-sensitive globs. `*` stays within a path
component, `**` spans components, and `!/` explicitly crosses into an archive.
For example, `--exclude="lib/a.jar!/.git/"` removes that nested archive's
`.git` subtree. There are no default exclusions.

The specification permits standard-library and established ecosystem codecs,
but no custom compression implementations or ports. Java and Go may support
different ZIP methods; `--help` lists each distribution's supported methods.
An unavailable method is an explicit error.
Nested archive streams up to 10 MB use seekable memory within an aggregate
10 MB retained-buffer budget; larger streams or exhausted capacity spill to
private temporary files.
Remaining genuinely unavailable metadata is an explicit `UNSUPPORTED_STREAMING`,
never a changed hash.

Gzip magic alone does not identify TAR.GZ: ordinary compressed files such as
`.js.gz` remain opaque unless the decoded prefix identifies TAR. Explicit
`.tar`, `.tar.gz`, and `.tgz` names must contain the promised archive.
In non-strict mode only, the exact legacy ZIP marker with Unix mode `0177777`,
a trailing-slash name and no content is treated as a directory with a
`WARN_ZIP_DIRECTORY_MODE` diagnostic. Strict mode and other invalid types fail.
Empty ZIP directory markers with repeated trailing slashes (as found in some
JDK `ct.sym` files) are also accepted only in non-strict mode, with a
`WARN_ZIP_DIRECTORY_SLASH` diagnostic. Other invalid path components still fail.

Text output is the default; `--format=json` emits a versioned document and
`--format=jsonl` emits one record per line. Limits on depth, entries, expanded
bytes, and downloaded bytes are configurable; consult `--help` and
specification sections 9-11 for defaults, record fields, and exit codes.

## Cross-language conformance tests

Both native unit suites consume the same
[`tests/vectors`](tests/vectors/README.md) resources: 168 expected values across
six logical trees, four constructions, and seven digest choices. Small
implementation-independent cases remain native unit tests in both languages;
implementation-specific instrumentation stays local. Only larger integration
scenarios use the packaged black-box suite.

Run the ecosystem builds and the independent black-box suite entirely in
Docker:

```powershell
.\test.ps1
```

On a POSIX shell, use `sh test.sh`. This runs the packaged JAR and the native
Linux Go artifact against independently constructed h1, Git/SWH, and NAR
oracles. Fixtures cover digest substitutions, archive codecs, sparse TAR,
ZIP64/descriptors, recursion, exclusions, prefix stripping, symlinks,
malformed archives, atomic output, limits, and local HTTP downloads.
Tests create disposable inputs; they do not contact an external HTTP service.
Small licensed upstream archives and published Go/SWH vectors are bundled
under [`tests/fixtures`](tests/fixtures/README.md), with provenance and license
notices, including the full official SWH sample root with empty directories.

The black-box conformance suite has 49 tests and typically takes about
one to two minutes to run after the artifacts and test image are built; actual
time depends on the host, Docker, and filesystem. A clean first run also builds
both implementations and downloads the pinned build images and dependencies,
so allow several minutes or more when those are not cached. The complete
build-and-test entry points are `.\test.ps1` on Windows and `sh test.sh` on
POSIX. To build one implementation only, use `.\java\build.ps1` or
`.\go\build.ps1` (POSIX: `sh java/build.sh` or `sh go/build.sh`). To run the
already-built host conformance suite without rebuilding, use
`python .\tests\conformance.py`; `--backend java` and `--backend go` select one
implementation. These host commands require Python 3.11+ and Java 21+, plus
the matching Go executable in `dist`.

After building, the same suite can run on the host with Python 3.11+ and
Java 21+:

```powershell
python .\tests\conformance.py -v
python .\tests\conformance.py --backend go -v
python .\tests\conformance.py --backend java -v
```

The host suite selects the Windows or Linux Go artifact automatically.
Linux tests additionally exercise filesystem symlinks even if the Windows
host does not grant symlink creation privileges. Containers require no
host Java, Python, Maven, or Go installation.

## License and Copyright

Copyright 2026 Bernd Eckenfels (SEEBURGER AG), Germany. All rights reserved.

Licensed under the [Apache License, Version 2.0](LICENSE). Third-party
dependencies and bundled fixtures retain their respective licenses.
