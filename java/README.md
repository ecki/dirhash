# Java implementation

Build and test (Docker, no host JDK needed):

```
.\java\build.ps1      # or: sh java/build.sh
```

Output: `dist/java/dirhash.jar` (standalone, Java 21+). Run
`java -jar dist/java/dirhash.jar --help`.

Optional native build: `mvn -f java/pom.xml verify` (needs `tests/vectors`, or
set `DIRHASH_TEST_VECTORS`).

Notes:

* Uses Commons Compress, XZ, Zstd JNI, Bouncy Castle and ICU; dependency
  notices are bundled under `META-INF/licenses`.
* Supports ZIP Deflate64 (method 9); Go does not.
* PAX sparse files with a real size above 2 GiB fail with `LIMIT_EXCEEDED`
  (Commons Compress limitation).
