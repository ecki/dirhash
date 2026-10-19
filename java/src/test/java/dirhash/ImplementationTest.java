package dirhash;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.zip.GZIPOutputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;
import org.apache.commons.compress.archivers.tar.TarUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class ImplementationTest {
    Path work;
    String temporaryDirectory;
    record Invocation(int status, String out, String err) {}

    @BeforeEach
    void createWorkspace() throws Exception {
        work = Files.createDirectories(Path.of("target", "fixtures-" + UUID.randomUUID()));
        temporaryDirectory = System.getProperty("java.io.tmpdir");
        System.setProperty("java.io.tmpdir", Path.of("target").toRealPath().toString());
    }
    @AfterEach
    void cleanWorkspace() throws Exception {
        System.setProperty("java.io.tmpdir", temporaryDirectory);
        try (var paths = Files.walk(work)) {
            for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) Files.delete(path);
        }
    }

    private Invocation invoke(String... args) {
        var output = new ByteArrayOutputStream();
        var errors = new ByteArrayOutputStream();
        int status = Main.run(args, new PrintStream(output, true, StandardCharsets.UTF_8),
                new PrintStream(errors, true, StandardCharsets.UTF_8));
        return new Invocation(status, output.toString(StandardCharsets.UTF_8), errors.toString(StandardCharsets.UTF_8));
    }

    private Path write(String name, byte[] bytes) throws Exception {
        Path path = work.resolve(name);
        Files.write(path, bytes);
        return path;
    }

    private static byte[] sha256(byte[] bytes) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(bytes);
    }

    private static String h1(Map<String, byte[]> files) throws Exception {
        ByteArrayOutputStream manifest = new ByteArrayOutputStream();
        for (String name : files.keySet().stream().sorted(Bytes::compare).toList()) {
            manifest.write(Bytes.utf8(Bytes.hex(sha256(files.get(name))) + "  " + name + "\n"));
        }
        return "h1:" + Base64.getEncoder().encodeToString(sha256(manifest.toByteArray()));
    }

    @Test
    void emptyConstructionVectors() {
        Invocation r = invoke("--h1", "--h1-go", "--gittree", "--gittree:sha256", "--swhid", "--nar", work.toString());
        assertEquals(0, r.status, r.err);
        assertTrue(r.out.contains("h1:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="));
        assertTrue(r.out.contains("4b825dc642cb6eb9a060e54bf8d69288fbee4904"));
        assertTrue(r.out.contains("6ef19b41225c5369f1c104d45d8d85efa9b057b53b14b4b9b939dd74decc5321"));
        assertTrue(r.out.contains("swh:1:dir:4b825dc642cb6eb9a060e54bf8d69288fbee4904"));
    }

    @Test
    void commonAndGoDirectoryManifestsIgnoreDirectories() throws Exception {
        Files.createDirectories(work.resolve("empty"));
        Files.createDirectories(work.resolve("nested"));
        Files.write(work.resolve("nested").resolve("a"), Bytes.utf8("hello"));
        Invocation r = invoke("--h1", "--h1-go", work.toString());
        assertEquals(0, r.status, r.err);
        String expected = h1(Map.of("nested/a", Bytes.utf8("hello")));
        assertEquals(2, r.out.lines().count());
        assertTrue(r.out.lines().allMatch(line -> line.contains(expected)));
    }

    @Test
    void swhPreservesEmptySubdirectoriesForEveryDigestWhileGitOmitsThem() throws Exception {
        Path directory = Files.createDirectories(work.resolve("tree"));
        Files.createDirectories(directory.resolve("outer").resolve("inner"));
        Path archive = write("empty-directories.zip", zip("outer/inner/", new byte[0], true));
        for (String digest : List.of("sha1", "sha256", "sha512", "blake2b-256",
                "blake2b-512", "blake3", "sha3-256", "sha3-512")) {
            byte[] empty = Digests.hash(digest, Bytes.utf8("tree 0\0"));
            byte[] inner = directoryObject(digest, "inner", empty);
            String value = Bytes.hex(directoryObject(digest, "outer", inner));
            String expected = digest.equals("sha1") ? "swh:1:dir:" + value
                    : "dirhash:1:swhid:" + digest + ":" + value;
            for (Path source : List.of(directory, archive)) {
                Invocation result = invoke("--swhid:" + digest, "--gittree:" + digest, source.toString());
                assertEquals(0, result.status, result.err);
                Map<String, String> values = result.out.lines().map(line -> line.split("\t"))
                        .collect(java.util.stream.Collectors.toMap(fields -> fields[0], fields -> fields[1]));
                assertEquals(expected, values.get(digest.equals("sha1") ? "swhid" : "swhid:" + digest), digest + " " + source);
                String git = digest.equals("sha1") || digest.equals("sha256") ? Bytes.hex(empty)
                        : "dirhash:1:gittree:" + digest + ":" + Bytes.hex(empty);
                assertEquals(git, values.get(digest.equals("sha1") ? "gittree" : "gittree:" + digest), digest + " " + source);
                Invocation excluded = invoke("--swhid:" + digest, "--exclude=outer/", source.toString());
                assertEquals(0, excluded.status, excluded.err);
                String emptySwh = digest.equals("sha1") ? "swh:1:dir:" + Bytes.hex(empty)
                        : "dirhash:1:swhid:" + digest + ":" + Bytes.hex(empty);
                assertEquals(emptySwh, excluded.out.split("\t")[1]);
            }
        }
    }

    private static byte[] directoryObject(String digest, String name, byte[] child) throws Exception {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(Bytes.utf8("40000 " + name + "\0"));
        body.write(child);
        ByteArrayOutputStream object = new ByteArrayOutputStream();
        object.write(Bytes.utf8("tree " + body.size() + "\0"));
        object.write(body.toByteArray());
        return Digests.hash(digest, object.toByteArray());
    }

    @Test
    void paxEffectiveUnicodeNameSupersedesNonportableFallbackHeader() throws Exception {
        byte[] archive = paxArchive("path=😀\n", "?", Bytes.utf8("A"));
        Path source = write("unicode.tar", archive);
        Invocation result = invoke("--h1", "--strict", source.toString());
        assertEquals(0, result.status, result.err);
        assertTrue(result.out.contains(h1(Map.of("😀", Bytes.utf8("A")))));
        Path actualQuestionMark = write("question.tar", tar("?", Bytes.utf8("A")));
        assertEquals(1, invoke("--h1", "--strict", actualQuestionMark.toString()).status);
    }

    @Test
    void gzipOptionalHeaderCrcIsValidatedForEveryMemberAndNestedArchive() throws Exception {
        byte[] content = tar("a", Bytes.utf8("x"));
        ByteArrayOutputStream basic = new ByteArrayOutputStream();
        try (var gzip = new GZIPOutputStream(basic)) { gzip.write(content); }
        byte[] fixed = Arrays.copyOf(basic.toByteArray(), 10);
        fixed[3] = 2 | 4 | 8 | 16;
        ByteArrayOutputStream header = new ByteArrayOutputStream();
        header.write(fixed);
        header.write(new byte[] {7, 0, 'x', 'y', 3, 0, 'a', 'b', 'c'});
        header.write(Bytes.utf8("source.tar\0a comment\0"));
        var crc = new java.util.zip.CRC32();
        crc.update(header.toByteArray());
        header.write((int) crc.getValue() & 255);
        header.write((int) (crc.getValue() >>> 8) & 255);
        ByteArrayOutputStream full = new ByteArrayOutputStream();
        full.write(header.toByteArray());
        full.write(basic.toByteArray(), 10, basic.size() - 10);
        byte[] valid = full.toByteArray();
        Path source = write("optional.tgz", valid);
        Invocation accepted = invoke("--h1", "--nar", "--strict", source.toString());
        assertEquals(0, accepted.status, accepted.err);
        byte[] corrupt = valid.clone();
        corrupt[header.size() - 1] ^= 1;
        Path bad = write("bad.tgz", corrupt);
        Path nested = write("gzip-parent.zip", zip("inner.tgz", corrupt, true));
        for (Path path : List.of(bad, nested)) {
            Invocation result = invoke("--h1", "--plain", "--recurse", path.toString());
            assertEquals(1, result.status, result.err);
            assertEquals("", result.out);
            assertTrue(result.err.startsWith("ARCHIVE_INTEGRITY"), result.err);
        }
        ByteArrayOutputStream joined = new ByteArrayOutputStream();
        joined.write(valid);
        joined.write(corrupt);
        Path concatenated = write("concatenated.tgz", joined.toByteArray());
        assertEquals(1, invoke("--h1", concatenated.toString()).status);
    }

    @Test
    void gzipIsDiscoveredAsArchiveOnlyAfterTarChecksumValidation() throws Exception {
        byte[] javascript = new byte[11_535];
        for (int i = 0; i < javascript.length; i++) javascript[i] = (byte) ('a' + i % 26);
        byte[] gzipJavascript = gzip(javascript);
        Path ordinaryParent = write("gzip-javascript-parent.zip",
                zip("VAADIN/vaadinBootstrap.js.gz", gzipJavascript, true));
        Invocation ordinary = invoke("--h1", "--h1-go", "--gittree", "--swhid", "--nar",
                "--plain:sha1", "--plain:sha256", "--plain:sha512", "--plain:blake2b-256",
                "--plain:blake2b-512", "--plain:blake3", "--plain:sha3-256", "--plain:sha3-512",
                "--recurse", "--strict", ordinaryParent.toString());
        assertEquals(0, ordinary.status, ordinary.err);
        assertEquals(13, ordinary.out.lines().count(), ordinary.out);
        assertFalse(ordinary.out.contains("vaadinBootstrap.js.gz"), ordinary.out);
        assertFalse(ordinary.err.contains("WARN"), ordinary.err);
        byte[] corruptJavaScriptGzip = gzipJavascript.clone();
        corruptJavaScriptGzip[corruptJavaScriptGzip.length - 1] ^= 1;
        Path corruptOrdinaryParent = write("corrupt-gzip-javascript-parent.zip",
                zip("VAADIN/vaadinBootstrap.js.gz", corruptJavaScriptGzip, true));
        Invocation opaqueCorruptGzip = invoke("--h1", "--recurse", "--strict",
                corruptOrdinaryParent.toString());
        assertEquals(0, opaqueCorruptGzip.status, opaqueCorruptGzip.err);
        assertEquals(1, opaqueCorruptGzip.out.lines().count(), opaqueCorruptGzip.out);

        byte[] nestedTar = gzip(tar("payload.txt", Bytes.utf8("nested")));
        assertEquals("tar.gz", Discovery.probe(new ByteArrayInputStream(nestedTar), "opaque", false).type());
        Path extensionless = write("extensionless-gzip-parent.zip", zip("opaque", nestedTar, true));
        Invocation discoveredTar = invoke("--h1", "--gittree", "--swhid", "--nar", "--plain",
                "--recurse", "--strict", extensionless.toString());
        assertEquals(0, discoveredTar.status, discoveredTar.err);
        assertEquals(10, discoveredTar.out.lines().count(), discoveredTar.out);
        assertTrue(discoveredTar.out.contains("!/opaque"), discoveredTar.out);
        byte[] corruptTarGzip = nestedTar.clone();
        corruptTarGzip[corruptTarGzip.length - 1] ^= 1;
        Path corruptDiscoveredTar = write("corrupt-extensionless-gzip-parent.zip",
                zip("opaque", corruptTarGzip, true));
        Invocation corruptArchive = invoke("--h1", "--recurse", "--strict", corruptDiscoveredTar.toString());
        assertEquals(1, corruptArchive.status, corruptArchive.err);
        assertEquals("", corruptArchive.out);
        assertTrue(corruptArchive.err.startsWith("ARCHIVE_INTEGRITY:"), corruptArchive.err);

        byte[] badTar = tar("bad", new byte[0]);
        badTar[148] = badTar[148] == '0' ? (byte) '1' : (byte) '0';
        byte[] gzipBadTar = gzip(badTar);
        Path opaqueTarLike = write("gzip-invalid-tar-checksum-parent.zip",
                zip("opaque.bin", gzipBadTar, true));
        Invocation opaque = invoke("--h1", "--recurse", "--strict", opaqueTarLike.toString());
        assertEquals(0, opaque.status, opaque.err);
        assertEquals(1, opaque.out.lines().count(), opaque.out);
        Path opaqueRawTarLike = write("raw-invalid-tar-checksum-parent.zip",
                zip("opaque.bin", badTar, true));
        Invocation opaqueRaw = invoke("--h1", "--recurse", "--strict", opaqueRawTarLike.toString());
        assertEquals(0, opaqueRaw.status, opaqueRaw.err);
        assertEquals(1, opaqueRaw.out.lines().count(), opaqueRaw.out);

        Path explicitBad = write("invalid-checksum.tgz", gzipBadTar);
        Invocation rejected = invoke("--h1", explicitBad.toString());
        assertEquals(1, rejected.status, rejected.err);
        assertEquals("", rejected.out);
        assertTrue(rejected.err.startsWith("ARCHIVE_INTEGRITY:"), rejected.err);
        Path explicitRawTar = write("invalid-checksum.tar", badTar);
        Invocation rejectedRaw = invoke("--h1", explicitRawTar.toString());
        assertEquals(1, rejectedRaw.status, rejectedRaw.err);
        assertEquals("", rejectedRaw.out);
        assertTrue(rejectedRaw.err.startsWith("ARCHIVE_INTEGRITY:"), rejectedRaw.err);
        Path explicitBadTarGz = write("invalid-checksum.tar.gz", gzipBadTar);
        Invocation rejectedTarGz = invoke("--h1", explicitBadTarGz.toString());
        assertEquals(1, rejectedTarGz.status, rejectedTarGz.err);
        assertEquals("", rejectedTarGz.out);
        assertTrue(rejectedTarGz.err.startsWith("ARCHIVE_INTEGRITY:"), rejectedTarGz.err);
        Path arbitraryGzipRoot = write("javascript.gz", gzipJavascript);
        Invocation unsupported = invoke("--h1", arbitraryGzipRoot.toString());
        assertEquals(3, unsupported.status, unsupported.err);
        assertEquals("", unsupported.out);
        assertTrue(unsupported.err.startsWith("UNSUPPORTED_FORMAT:"), unsupported.err);
    }

    private static byte[] gzip(byte[] input) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (GZIPOutputStream output = new GZIPOutputStream(bytes)) { output.write(input); }
        return bytes.toByteArray();
    }

    @Test
    void repeatedTrailingZipDirectorySlashesWarnAndPreserveRawGoManifest() throws Exception {
        byte[] repeated = framedZip(Bytes.utf8("9/java.activation//"), new byte[0],
                new byte[0], new byte[0], 0040755);
        Path source = write("repeated-directory.zip", repeated);
        Path canonical = write("canonical-directory.zip", framedZip(Bytes.utf8("9/java.activation/"),
                new byte[0], new byte[0], new byte[0], 0040755));
        for (String scheme : List.of("--h1", "--h1-go", "--gittree", "--swhid", "--nar", "--plain")) {
            Invocation accepted = invoke(scheme, source.toString());
            assertEquals(0, accepted.status, accepted.err);
            assertEquals("WARN_ZIP_DIRECTORY_SLASH: " + source
                    + "!/9/java.activation//: accepted empty ZIP directory with repeated trailing slashes\n",
                    accepted.err);
            Invocation normal = invoke(scheme, canonical.toString());
            assertEquals(0, normal.status, normal.err);
            if (!scheme.equals("--h1-go") && !scheme.equals("--plain"))
                assertEquals(normal.out.split("\t")[1], accepted.out.split("\t")[1], scheme);
            else assertNotEquals(normal.out.split("\t")[1], accepted.out.split("\t")[1], scheme);
        }
        Invocation excluded = invoke("--h1", "--exclude=9/", source.toString());
        assertEquals(0, excluded.status, excluded.err);
        assertEquals(1, excluded.err.lines().count(), excluded.err);
        Invocation strict = invoke("--h1", "--strict", "--exclude=9/", source.toString());
        assertEquals(1, strict.status, strict.err);
        assertEquals("", strict.out);
        assertTrue(strict.err.startsWith("INVALID_PATH:"), strict.err);
        assertFalse(strict.err.contains("WARN_"), strict.err);
        Path shortName = write("short-directory.zip", zip("a//", new byte[0], true));
        Invocation shortAccepted = invoke("--h1", shortName.toString());
        assertEquals(0, shortAccepted.status, shortAccepted.err);
        assertTrue(shortAccepted.err.startsWith("WARN_ZIP_DIRECTORY_SLASH:"), shortAccepted.err);
        ByteArrayOutputStream collisionBytes = new ByteArrayOutputStream();
        try (ZipOutputStream out = new ZipOutputStream(collisionBytes)) {
            for (String name : List.of("a//", "a/")) {
                out.putNextEntry(new ZipEntry(name));
                out.closeEntry();
            }
        }
        Path collision = write("slash-collision.zip", collisionBytes.toByteArray());
        Invocation duplicate = invoke("--h1", collision.toString());
        assertEquals(1, duplicate.status, duplicate.err);
        assertEquals("", duplicate.out);
        assertFalse(duplicate.err.contains("WARN_"), duplicate.err);
        for (boolean stored : List.of(false, true)) {
            Path parent = write("repeated-parent-" + stored + ".zip", zip("inner.zip", repeated, stored));
            Invocation nested = invoke("--h1", "--h1-go", "--gittree", "--swhid", "--nar", "--plain",
                    "--recurse", parent.toString());
            assertEquals(0, nested.status, nested.err);
            assertEquals(12, nested.out.lines().count(), nested.out);
            assertEquals(1, nested.err.lines().count(), nested.err);
            assertTrue(nested.err.contains("!/inner.zip!/9/java.activation//:"), nested.err);
            Invocation nestedStrict = invoke("--h1", "--recurse", "--strict", parent.toString());
            assertEquals(1, nestedStrict.status, nestedStrict.err);
            assertEquals("", nestedStrict.out);
            assertTrue(nestedStrict.err.startsWith("INVALID_PATH:"), nestedStrict.err);
            assertFalse(nestedStrict.err.contains("WARN_"), nestedStrict.err);
        }
        for (String name : List.of("//", "/a//", "a//b/", "a/..//", "a/.//", "a\\b//")) {
            Path invalid = write("invalid-slashes-" + UUID.randomUUID() + ".zip",
                    framedZip(Bytes.utf8(name), new byte[0], new byte[0], new byte[0], 0040755));
            Invocation rejected = invoke("--h1", invalid.toString());
            assertEquals(1, rejected.status, rejected.err);
            assertEquals("", rejected.out);
            assertFalse(rejected.err.contains("WARN_"), rejected.err);
        }
        for (int mode : List.of(0040755, 0100644, 0120777)) {
            Path invalid = write("invalid-directory-" + mode + ".zip",
                    framedZip(Bytes.utf8("a//"), mode == 0040755 ? Bytes.utf8("x") : new byte[0],
                            new byte[0], new byte[0], mode));
            Invocation rejected = invoke("--h1", invalid.toString());
            assertEquals(1, rejected.status, rejected.err);
            assertEquals("", rejected.out);
            assertFalse(rejected.err.contains("WARN_"), rejected.err);
        }
    }

    private static byte[] paxArchive(String fields, String fallback, byte[] content) throws Exception {
        ByteArrayOutputStream records = new ByteArrayOutputStream();
        for (String field : fields.split("\n")) {
            byte[] value = Bytes.utf8(field + "\n");
            int length = value.length + 2;
            while (Integer.toString(length).length() + 1 + value.length != length)
                length = Integer.toString(length).length() + 1 + value.length;
            records.write(Bytes.utf8(length + " "));
            records.write(value);
        }
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (TarArchiveOutputStream out = new TarArchiveOutputStream(bytes)) {
            TarArchiveEntry pax = new TarArchiveEntry("PaxHeaders/item", (byte) 'x');
            pax.setSize(records.size());
            out.putArchiveEntry(pax);
            out.write(records.toByteArray());
            out.closeArchiveEntry();
            TarArchiveEntry entry = new TarArchiveEntry(fallback);
            entry.setSize(content.length);
            out.putArchiveEntry(entry);
            out.write(content);
            out.closeArchiveEntry();
        }
        return bytes.toByteArray();
    }

    @Test
    void primitiveKnownAnswers() {
        Map<String, String> vectors = Map.of(
                "sha1", "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                "sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "sha512", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
                        + "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
                "blake2b-256", "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
                "blake2b-512", "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
                "blake3", "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
                "sha3-256", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
                "sha3-512", "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26");
        vectors.forEach((name, expected) -> assertEquals(expected, Bytes.hex(Digests.hash(name, new byte[0])), name));
        assertFalse(Arrays.equals(Digests.hash("blake2b-256", new byte[0]),
                Arrays.copyOf(Digests.hash("blake2b-512", new byte[0]), 32)));
    }

    @Test
    void plainHashesExactRootArchiveBytesWithEveryPrimitive() throws Exception {
        byte[] archive = zip("top/file", Bytes.utf8("payload"), true);
        Path source = write("plain-root.zip", archive);
        String[] args = java.util.stream.Stream.concat(
                Options.DIGESTS.stream().map(digest -> "--plain:" + digest),
                java.util.stream.Stream.of(source.toString())).toArray(String[]::new);
        Invocation result = invoke(args);
        assertEquals(0, result.status, result.err);
        List<String> records = result.out.lines().toList();
        assertEquals(Options.DIGESTS.size(), records.size());
        for (int i = 0; i < Options.DIGESTS.size(); i++) {
            String digest = Options.DIGESTS.get(i);
            String label = digest.equals("sha256") ? "plain" : "plain:" + digest;
            assertEquals(label + "\t" + digest + ":" + Bytes.hex(Digests.hash(digest, archive))
                    + "\t" + source, records.get(i));
        }
        Invocation defaultDigest = invoke("--plain", source.toString());
        assertEquals("plain\tsha256:" + Bytes.hex(Digests.hash("sha256", archive)) + "\t" + source + "\n",
                defaultDigest.out);
    }

    @Test
    void plainRootArchiveTypesUseOriginalEncodedBytesAndMixedHashesStayUnchanged() throws Exception {
        byte[] zipBytes = zip("a", Bytes.utf8("A"), true);
        byte[] tarBytes = tar("a", Bytes.utf8("A"));
        ByteArrayOutputStream gzipBytes = new ByteArrayOutputStream();
        try (GZIPOutputStream gzip = new GZIPOutputStream(gzipBytes)) { gzip.write(tarBytes); }
        List<byte[]> archives = List.of(zipBytes, tarBytes, gzipBytes.toByteArray());
        List<String> types = List.of("zip", "tar", "tar.gz");
        for (int i = 0; i < archives.size(); i++) {
            Path source = write("root-" + types.get(i), archives.get(i));
            Invocation mixed = invoke("--h1", "--plain", source.toString());
            Invocation treeOnly = invoke("--h1", source.toString());
            assertEquals(0, mixed.status, mixed.err);
            assertEquals(treeOnly.out.lines().findFirst().orElseThrow(),
                    mixed.out.lines().findFirst().orElseThrow());
            assertTrue(mixed.out.lines().toList().getLast().contains("sha256:"
                    + Bytes.hex(Digests.hash("sha256", archives.get(i)))));
            Invocation json = invoke("--plain", "--format=json", source.toString());
            assertTrue(json.out.contains("\"inputType\":\"" + types.get(i) + "\""), json.out);
            assertTrue(json.out.contains("\"scheme\":\"plain\",\"digestAlgorithm\":\"sha256\""), json.out);
        }
        Path source = write("strip-root.zip", zip("top/file", Bytes.utf8("payload"), true));
        assertEquals(invoke("--plain", source.toString()).out,
                invoke("--plain", "--strip-components=1", source.toString()).out);
    }

    @Test
    void recursivePlainHashesDecodedNestedArchiveBytesRegardlessOfParentCompression() throws Exception {
        byte[] inner = zip("folder/file", Bytes.utf8("nested"), true);
        for (boolean stored : List.of(true, false)) {
            Path outer = write("parent-" + stored + ".zip", zip("inner.zip", inner, stored));
            Invocation plain = invoke("--plain", "--recurse", outer.toString());
            assertEquals(0, plain.status, plain.err);
            assertEquals(2, plain.out.lines().count());
            String expectedRoot = "sha256:" + Bytes.hex(Digests.hash("sha256", Files.readAllBytes(outer)));
            String expectedNested = "sha256:" + Bytes.hex(Digests.hash("sha256", inner));
            assertTrue(plain.out.lines().anyMatch(line -> line.contains(expectedRoot)), plain.out);
            assertTrue(plain.out.lines().anyMatch(line -> line.contains(expectedNested)
                    && line.contains("!/inner.zip")), plain.out);
            Invocation excluded = invoke("--plain", "--recurse", "--exclude=inner.zip!/folder/file",
                    outer.toString());
            assertEquals(plain.out, excluded.out);
            Invocation treeOnly = invoke("--h1", outer.toString());
            Invocation mixed = invoke("--h1", "--plain", "--recurse", outer.toString());
            assertEquals(treeOnly.out.lines().findFirst().orElseThrow(),
                    mixed.out.lines().findFirst().orElseThrow());
        }
    }

    @Test
    void plainRereadsDoNotChargeExpansionOrEntryBudgetsAgain() throws Exception {
        byte[] contents = Bytes.utf8("inner payload");
        byte[] inner = zip("file", contents, true);
        Path outer = write("budget-parent.zip", zip("inner.zip", inner, true));
        long expanded = inner.length + contents.length;
        Invocation result = invoke("--plain", "--recurse", "--max-expanded-bytes=" + expanded,
                "--max-entries=2", outer.toString());
        assertEquals(0, result.status, result.err);
        assertEquals(2, result.out.lines().count());
    }

    @Test
    void plainRejectsDirectoriesAndNeverPublishesForCorruptArchives() throws Exception {
        Invocation directory = invoke("--h1", "--plain", work.toString());
        assertEquals(3, directory.status);
        assertEquals("", directory.out);
        assertTrue(directory.err.startsWith("UNSUPPORTED_FORMAT"), directory.err);
        byte[] valid = zip("a", Bytes.utf8("payload"), true);
        byte[] crc = valid.clone();
        crc[31] ^= 1;
        byte[] truncated = Arrays.copyOf(valid, valid.length - 8);
        for (byte[] invalid : List.of(crc, truncated)) {
            Path source = write("invalid-" + UUID.randomUUID() + ".zip", invalid);
            for (String[] selections : List.of(new String[] {"--plain"},
                    new String[] {"--h1", "--plain"})) {
                Invocation result = invoke(concat(selections, source.toString()));
                assertNotEquals(0, result.status);
                assertEquals("", result.out);
            }
            Path parent = write("invalid-parent-" + UUID.randomUUID() + ".zip",
                    zip("inner.zip", invalid, true));
            Invocation nested = invoke("--plain", "--recurse", parent.toString());
            assertNotEquals(0, nested.status);
            assertEquals("", nested.out);
        }
    }

    private static String[] concat(String[] values, String last) {
        String[] result = Arrays.copyOf(values, values.length + 1);
        result[result.length - 1] = last;
        return result;
    }

    @Test
    void narZipEntriesReuseOneValidatedZipInventoryAcrossAllPrimitiveRereads() throws Exception {
        Map<String, byte[]> files = new java.util.TreeMap<>(Bytes::compare);
        ByteArrayOutputStream zipBytes = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(zipBytes, StandardCharsets.UTF_8)) {
            for (int i = 0; i < 128; i++) {
                String name = "f" + String.format(java.util.Locale.ROOT, "%04d", i);
                byte[] contents = Bytes.utf8("contents-" + i);
                files.put(name, contents);
                zip.putNextEntry(new ZipEntry(name));
                zip.write(contents);
                zip.closeEntry();
            }
        }
        Path source = write("nar-many.zip", zipBytes.toByteArray());
        String[] args = java.util.stream.Stream.concat(
                Options.DIGESTS.stream().map(digest -> "--nar:" + digest),
                java.util.stream.Stream.of(source.toString())).toArray(String[]::new);
        Engine engine = new Engine(Options.parse(args));
        List<Model.Result> results = engine.run();
        assertEquals(1, engine.zipReaderOpens);
        assertEquals(Options.DIGESTS.size(), results.size());
        byte[] serialized = narDirectory(files);
        for (int i = 0; i < Options.DIGESTS.size(); i++) {
            String digest = Options.DIGESTS.get(i);
            byte[] expected = Digests.hash(digest, serialized);
            String value = digest.equals("sha256")
                    ? "sha256-" + Base64.getEncoder().encodeToString(expected)
                    : "dirhash:1:nar:" + digest + ":" + Bytes.hex(expected);
            assertEquals(value, results.get(i).value(), digest);
        }
    }

    private static byte[] narDirectory(Map<String, byte[]> files) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        narString(out, Bytes.utf8("nix-archive-1"));
        narString(out, Bytes.utf8("("));
        narString(out, Bytes.utf8("type"));
        narString(out, Bytes.utf8("directory"));
        for (Map.Entry<String, byte[]> file : files.entrySet()) {
            narString(out, Bytes.utf8("entry"));
            narString(out, Bytes.utf8("("));
            narString(out, Bytes.utf8("name"));
            narString(out, Bytes.utf8(file.getKey()));
            narString(out, Bytes.utf8("node"));
            narString(out, Bytes.utf8("("));
            narString(out, Bytes.utf8("type"));
            narString(out, Bytes.utf8("regular"));
            narString(out, Bytes.utf8("contents"));
            narString(out, file.getValue());
            narString(out, Bytes.utf8(")"));
            narString(out, Bytes.utf8(")"));
        }
        narString(out, Bytes.utf8(")"));
        return out.toByteArray();
    }

    private static void narString(ByteArrayOutputStream out, byte[] value) throws Exception {
        long size = value.length;
        for (int i = 0; i < 8; i++) out.write((int) (size >>> (8 * i)) & 255);
        out.write(value);
        for (int i = 0; i < ((8 - (value.length & 7)) & 7); i++) out.write(0);
    }

    @Test
    void bareDotIsNotARootMarkerButExplicitDotSlashDirectoryIs() throws Exception {
        byte[] dot = tarMarker(".", false);
        byte[] dotSlash = tarMarker("./", false);
        for (boolean strict : List.of(false, true)) {
            Path invalid = write("bare-dot-" + strict + ".tar", dot);
            Invocation rejected = strict
                    ? invoke("--h1", "--strict", invalid.toString())
                    : invoke("--h1", invalid.toString());
            assertNotEquals(0, rejected.status);
            assertEquals("", rejected.out);
            assertTrue(rejected.err.startsWith("INVALID_PATH"), rejected.err);
            Path valid = write("dot-slash-" + strict + ".tar", dotSlash);
            Invocation accepted = strict
                    ? invoke("--h1", "--strict", valid.toString())
                    : invoke("--h1", valid.toString());
            assertEquals(0, accepted.status, accepted.err);
        }
    }

    private static byte[] tarMarker(String name, boolean file) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (TarArchiveOutputStream out = new TarArchiveOutputStream(bytes, "UTF-8")) {
            TarArchiveEntry entry = new TarArchiveEntry(name, file);
            entry.setSize(0);
            out.putArchiveEntry(entry);
            out.closeArchiveEntry();
        }
        return bytes.toByteArray();
    }

    @Test
    void directoryArchiveDisplaysUseNativePathUntilActualNestedBoundary() throws Exception {
        Path directory = Files.createDirectories(work.resolve("!root"));
        byte[] inner = zip("data", Bytes.utf8("x"), true);
        byte[] outer = zip("inner!.zip", inner, true);
        Path outerPath = directory.resolve("outer!.zip");
        Files.write(outerPath, outer);
        Invocation result = invoke("--h1", "--recurse", "--format=json", directory.toString());
        assertEquals(0, result.status, result.err);
        String rootPath = directory.toString();
        String childPath = outerPath.toString();
        String nestedPath = childPath.replace("!", "!!") + "!/inner!!.zip";
        assertTrue(result.out.contains("\"path\":\"" + rootPath + "\""), result.out);
        assertTrue(result.out.contains("\"path\":\"" + childPath + "\""), result.out);
        assertTrue(result.out.contains("\"path\":\"" + nestedPath + "\""), result.out);
        assertTrue(result.out.contains("\"archiveEntries\":[\"outer!.zip\"]"), result.out);
        assertTrue(result.out.contains("\"archiveEntries\":[\"outer!.zip\",\"inner!.zip\"]"), result.out);
        Path direct = write("direct!.zip", zip("file", Bytes.utf8("x"), true));
        Invocation directResult = invoke("--h1", "--format=json", direct.toString());
        assertEquals(0, directResult.status, directResult.err);
        assertTrue(directResult.out.contains("\"path\":\"" + direct + "\""), directResult.out);
    }

    @Test
    void fanoutConsumesGeneratedPayloadOnlyOnce() throws Exception {
        long length = 8L * 1024 * 1024;
        Options options = Options.parse(new String[] {"--h1", "--h1:blake3", "--gittree",
                "--gittree:sha256", "--swhid:sha512", work.toString()});
        int[] maxBuffer = {0};
        long[] sourcePosition = {0};
        InputStream source = new InputStream() {
            @Override public int read(byte[] b, int off, int len) {
                maxBuffer[0] = Math.max(maxBuffer[0], len);
                if (sourcePosition[0] == length) return -1;
                int n = (int) Math.min(len, length - sourcePosition[0]);
                for (int i = 0; i < n; i++) b[off + i] = (byte) (sourcePosition[0]++ % 251);
                return n;
            }
            @Override public int read() { throw new AssertionError("bulk reads expected"); }
        };
        Payload p = new Payload(source, new Engine(options), length, false, true);
        Engine.drain(p);
        Model.Node node = new Model.Node("generated", Model.Type.REGULAR);
        p.finish(node, false);
        assertEquals(length, sourcePosition[0]);
        assertEquals(length, p.count);
        assertTrue(maxBuffer[0] <= 65536);
        assertEquals(2, node.raw.size());
        assertEquals(3, node.blobs.size());
        assertEquals(32, node.raw.get("blake3").length);
    }

    private static byte[] zip(String name, byte[] data, boolean stored) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ZipOutputStream out = new ZipOutputStream(bytes, StandardCharsets.UTF_8)) {
            ZipEntry entry = new ZipEntry(name);
            if (stored) {
                entry.setMethod(ZipEntry.STORED);
                entry.setSize(data.length);
                var crc = new java.util.zip.CRC32();
                crc.update(data);
                entry.setCrc(crc.getValue());
            }
            out.putNextEntry(entry);
            out.write(data);
            out.closeEntry();
        }
        return bytes.toByteArray();
    }

    @Test
    void validTarHeaderOutranksZipMagicDuringRootAndNestedDiscovery() throws Exception {
        byte[] archive = paxArchive("path=visible\n", "fallback", Bytes.utf8("A"));
        setTarNameAndChecksum(archive, 0, new byte[] {'P', 'K', 3, 4});
        Path direct = write("ambiguous.bin", archive);
        Path nested = write("ambiguous-parent.zip", zip("inner.bin", archive, true));
        String expected = h1(Map.of("visible", Bytes.utf8("A")));
        for (Path source : List.of(direct, nested)) {
            Invocation result = invoke("--h1", "--strict", "--recurse", source.toString());
            assertEquals(0, result.status, result.err);
            assertTrue(result.out.contains(expected), result.out);
        }
    }

    @Test
    void zipDiscoveryDoesNotImposeAnUpperBoundOnVersionNeeded() throws Exception {
        byte[] header = new byte[30];
        var fields = java.nio.ByteBuffer.wrap(header).order(java.nio.ByteOrder.LITTLE_ENDIAN);
        fields.putInt(0x04034b50).putShort(4, (short) 99).putShort(26, (short) 1);
        Discovery.Probe probe = Discovery.probe(new ByteArrayInputStream(header), "payload.bin", true);
        assertEquals("zip", probe.type());
    }

    @Test
    void deferredNestedZipSupportsGitAndSwhWithStandaloneSemantics() throws Exception {
        byte[] inner = zip("a", Bytes.utf8("A"), false);
        Path direct = write("direct.zip", inner);
        Path parent = write("parent.zip", zip("inner.zip", inner, false));
        for (boolean strict : List.of(false, true)) {
            String[] selections = {"--h1", "--h1-go", "--gittree", "--swhid", "--nar"};
            var standalone = new java.util.ArrayList<>(List.of(selections));
            if (strict) standalone.add("--strict");
            standalone.add(direct.toString());
            Invocation expected = invoke(standalone.toArray(String[]::new));
            assertEquals(0, expected.status, expected.err);
            var recursive = new java.util.ArrayList<>(List.of(selections));
            if (strict) recursive.add("--strict");
            recursive.add("--recurse");
            recursive.add(parent.toString());
            Invocation actual = invoke(recursive.toArray(String[]::new));
            assertEquals(0, actual.status, actual.err);
            assertEquals(expected.out.lines().map(line -> line.split("\t")[1]).toList(),
                    actual.out.lines().skip(5).map(line -> line.split("\t")[1]).toList());
            var opaque = new java.util.ArrayList<>(List.of(selections));
            opaque.add(parent.toString());
            Invocation parentOnly = invoke(opaque.toArray(String[]::new));
            assertEquals(0, parentOnly.status, parentOnly.err);
            assertEquals(parentOnly.out.lines().map(line -> line.split("\t")[1]).toList(),
                    actual.out.lines().limit(5).map(line -> line.split("\t")[1]).toList());
        }
    }

    @Test
    void nestedSpoolsAreRemovedAfterSuccessMalformedInputAndExpansionLimits() throws Exception {
        byte[] inner = zip("a", Bytes.utf8("A"), false);
        Path parent = write("spool-parent.zip", zip("inner.zip", inner, false));
        List<String> before = spoolFiles();
        Invocation exact = invoke("--gittree", "--swhid", "--strict", "--recurse",
                "--max-expanded-bytes=" + (inner.length + 1), parent.toString());
        assertEquals(0, exact.status, exact.err);
        assertEquals(before, spoolFiles());
        Invocation limited = invoke("--gittree", "--recurse",
                "--max-expanded-bytes=" + (inner.length - 1), parent.toString());
        assertEquals(1, limited.status, limited.err);
        assertTrue(limited.err.startsWith("LIMIT_EXCEEDED"), limited.err);
        assertEquals("", limited.out);
        assertEquals(before, spoolFiles());
        byte[] invalid = Arrays.copyOf(inner, inner.length + 1);
        Path malformed = write("spool-malformed.zip", zip("inner.zip", invalid, false));
        Invocation rejected = invoke("--gittree", "--recurse", malformed.toString());
        assertEquals(1, rejected.status, rejected.err);
        assertEquals("", rejected.out);
        assertEquals(before, spoolFiles());
        Invocation excluded = invoke("--gittree", "--strict", "--recurse", "--exclude=inner.zip",
                malformed.toString());
        assertEquals(0, excluded.status, excluded.err);
        assertEquals(before, spoolFiles());
    }

    @Test
    void nestedMaterializationPreservesDeclaredZipLengthValidationInBothModes() throws Exception {
        List<String> before = spoolFiles();
        for (int length : List.of(1, ArchiveSpool.MEMORY_LIMIT)) {
            byte[] content = new byte[length];
            byte[] valid = framedZip(Bytes.utf8("a"), content, new byte[0], new byte[0], 0100644);
            int central = 31 + length;
            for (int delta : List.of(-1, 1)) {
                byte[] wrong = valid.clone();
                var fields = java.nio.ByteBuffer.wrap(wrong).order(java.nio.ByteOrder.LITTLE_ENDIAN);
                fields.putInt(22, length + delta);
                fields.putInt(central + 24, length + delta);
                Path source = write("wrong-length.zip", zip("inner.zip", wrong, false));
                for (boolean strict : List.of(false, true)) {
                    Invocation result = strict
                            ? invoke("--h1", "--gittree", "--swhid", "--nar", "--recurse", "--strict", source.toString())
                            : invoke("--h1", "--gittree", "--swhid", "--nar", "--recurse", source.toString());
                    assertEquals(1, result.status, result.err);
                    assertTrue(result.err.startsWith("ARCHIVE_INTEGRITY"), result.err);
                    assertEquals("", result.out);
                    assertEquals(before, spoolFiles());
                }
            }
        }
    }

    @Test
    void nestedDeferredZipDescriptorAndCentralLengthsMustMatchActualPayload() throws Exception {
        byte[] content = Bytes.utf8("deferred");
        ByteArrayOutputStream compressed = new ByteArrayOutputStream();
        var encoder = new java.util.zip.Deflater(6, true);
        try (var output = new java.util.zip.DeflaterOutputStream(compressed, encoder)) { output.write(content); }
        finally { encoder.end(); }
        byte[] valid = descriptorZip(8, content, compressed.toByteArray());
        int descriptor = 31 + compressed.size(), central = descriptor + 16;
        List<String> before = spoolFiles();
        for (int delta : List.of(-1, 1)) for (int mutation : List.of(0, 1, 2)) {
            byte[] wrong = valid.clone();
            var fields = java.nio.ByteBuffer.wrap(wrong).order(java.nio.ByteOrder.LITTLE_ENDIAN);
            if (mutation != 0) fields.putInt(descriptor + 12, content.length + delta);
            if (mutation != 1) fields.putInt(central + 24, content.length + delta);
            Path source = write("wrong-deferred.zip", zip("inner.zip", wrong, false));
            for (boolean strict : List.of(false, true)) {
                Invocation result = strict ? invoke("--gittree", "--strict", "--recurse", source.toString())
                        : invoke("--gittree", "--recurse", source.toString());
                assertEquals(1, result.status, result.err);
                assertTrue(result.err.startsWith("ARCHIVE_INTEGRITY"), result.err);
                assertEquals("", result.out);
                assertEquals(before, spoolFiles());
            }
        }
    }

    @Test
    void diskSpillInsideSelectedWorkingDirectoryDoesNotReportInputChanged() throws Exception {
        byte[] content = new byte[ArchiveSpool.MEMORY_LIMIT];
        Arrays.fill(content, (byte) 'A');
        byte[] inner = framedZip(Bytes.utf8("a"), content,
                new byte[0], new byte[0], 0100644);
        write("archive.zip", zip("inner.zip", inner, false));
        Process process = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "-Djava.io.tmpdir=" + System.getProperty("java.io.tmpdir"),
                "-cp", System.getProperty("java.class.path"), Main.class.getName(),
                "--gittree", "--swhid", "--nar", "--strict", "--recurse", ".")
                .directory(work.toFile()).redirectErrorStream(true).start();
        String output;
        try (InputStream input = process.getInputStream()) {
            output = new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
        assertEquals(0, process.waitFor(), output);
        assertEquals(9, output.lines().count(), output);
        try (var paths = Files.list(work)) {
            assertEquals(List.of("archive.zip"), paths.map(path -> path.getFileName().toString()).sorted().toList());
        }
    }

    @Test
    void filesystemDiagnosticsDoNotIntroduceArchiveBoundaries() throws Exception {
        Path child = Files.createFile(work.resolve("bad\u200d"));
        Invocation result = invoke("--h1", "--strict", work.toString());
        assertEquals(1, result.status, result.err);
        assertTrue(result.err.contains(Bytes.diagnostic(child.toString())), result.err);
        assertFalse(result.err.contains("!/"), result.err);
    }

    @Test
    void filesystemArchiveDiagnosticsUseOnlyActualArchiveBoundaries() throws Exception {
        Path directory = Files.createDirectories(work.resolve("lib!"));
        Path source = directory.resolve("inner!.zip");
        Files.write(source, zip("../bad", new byte[0], true));
        Invocation result = invoke("--h1", "--strict", work.toString());
        assertEquals(1, result.status, result.err);
        assertTrue(result.err.contains(Bytes.diagnostic(source.toString().replace("!", "!!") + "!/../bad")),
                result.err);
    }

    @Test
    void unsupportedZipUnixModeReportsDecodedEntryAndFullOctalType() throws Exception {
        byte[] archive = framedZip(Bytes.utf8("META-INF/maven/"), new byte[0], new byte[0], new byte[0], 0177777);
        Path direct = write("unsupported-mode.zip", archive);
        Path nested = write("mode-parent!.zip", zip("bad!.zip", archive, false));
        for (Path source : List.of(direct, nested)) {
            Invocation result = invoke("--h1", "--strict", "--recurse", source.toString());
            assertEquals(1, result.status, result.err);
            assertEquals("", result.out);
            assertTrue(result.err.startsWith("SPECIAL_FILE:"), result.err);
            assertTrue(result.err.contains("META-INF/maven/"), result.err);
            assertTrue(result.err.contains("0177777"), result.err);
            assertTrue(result.err.contains("0170000"), result.err);
        }
    }

    @Test
    void exactLegacyEmptyDirectoryModeWarnsOnlyAfterSuccessfulNonStrictRun() throws Exception {
        byte[] legacy = framedZip(Bytes.utf8("META-INF/maven/"), new byte[0],
                new byte[0], new byte[0], 0177777);
        Path source = write("legacy-empty-dir.zip", legacy);
        Invocation accepted = invoke("--h1", source.toString());
        assertEquals(0, accepted.status, accepted.err);
        assertTrue(accepted.out.contains("h1:"), accepted.out);
        assertEquals(1, accepted.err.lines().count(), accepted.err);
        assertTrue(accepted.err.startsWith("WARN_ZIP_DIRECTORY_MODE:"), accepted.err);
        assertTrue(accepted.err.contains("META-INF/maven/"), accepted.err);
        assertTrue(accepted.err.contains("accepted malformed empty ZIP directory with Unix mode 0177777"),
                accepted.err);

        Invocation mixed = invoke("--h1", "--nar", "--plain", source.toString());
        assertEquals(0, mixed.status, mixed.err);
        assertEquals(1, mixed.err.lines().count(), mixed.err);

        Invocation strict = invoke("--h1", "--strict", source.toString());
        assertEquals(1, strict.status);
        assertEquals("", strict.out);
        assertTrue(strict.err.startsWith("SPECIAL_FILE:"), strict.err);
        assertTrue(strict.err.contains(source.toString() + "!/META-INF/maven/"), strict.err);
        assertTrue(strict.err.contains("0177777"), strict.err);
        assertTrue(strict.err.contains("0170000"), strict.err);

        byte[] nonempty = framedZip(Bytes.utf8("META-INF/maven/"), Bytes.utf8("x"),
                new byte[0], new byte[0], 0177777);
        byte[] noSlash = framedZip(Bytes.utf8("META-INF/maven"), new byte[0],
                new byte[0], new byte[0], 0177777);
        byte[] otherType = framedZip(Bytes.utf8("META-INF/maven/"), new byte[0],
                new byte[0], new byte[0], 0167777);
        byte[] otherCreator = framedZip(Bytes.utf8("META-INF/maven/"), new byte[0],
                new byte[0], new byte[0], 0177777, 0);
        byte[] asi = asi(0177777, "");
        byte[] withAsi = framedZip(Bytes.utf8("META-INF/maven/"), new byte[0],
                asi, asi, 0177777);
        for (byte[] invalid : List.of(nonempty, noSlash, otherType, withAsi)) {
            Path bad = write("near-match-" + UUID.randomUUID() + ".zip", invalid);
            Invocation rejected = invoke("--h1", bad.toString());
            assertEquals(1, rejected.status, rejected.err);
            assertEquals("", rejected.out);
            assertTrue(rejected.err.startsWith("SPECIAL_FILE:"), rejected.err);
            assertFalse(rejected.err.startsWith("WARN_ZIP_DIRECTORY_MODE:"), rejected.err);
        }
        Path otherPlatform = write("legacy-non-unix-creator.zip", otherCreator);
        Invocation ignoredUnixAttributes = invoke("--h1", otherPlatform.toString());
        assertEquals(0, ignoredUnixAttributes.status, ignoredUnixAttributes.err);
        assertEquals("", ignoredUnixAttributes.err);
        Path unix19 = write("legacy-creator-19.zip", framedZip(Bytes.utf8("META-INF/maven/"),
                new byte[0], new byte[0], new byte[0], 0177777, 19));
        Invocation accepted19 = invoke("--h1", unix19.toString());
        assertEquals(0, accepted19.status, accepted19.err);
        assertTrue(accepted19.err.startsWith("WARN_ZIP_DIRECTORY_MODE:"), accepted19.err);
    }

    @Test
    void legacyDirectoryModeWarningIsOnceForNestedArchiveOccurrence() throws Exception {
        byte[] legacy = framedZip(Bytes.utf8("META-INF/maven/"), new byte[0],
                new byte[0], new byte[0], 0177777);
        Path source = write("legacy-parent.zip", zip("inner.zip", legacy, true));
        Invocation result = invoke("--h1", "--recurse", source.toString());
        assertEquals(0, result.status, result.err);
        assertEquals(2, result.out.lines().count());
        assertEquals(1, result.err.lines().count(), result.err);
        assertTrue(result.err.contains("!/inner.zip!/META-INF/maven/"), result.err);
    }

    @Test
    void deferredFilesystemVerificationCapturesTheActualFailingDirectory() throws Exception {
        Files.createDirectories(work.resolve("first"));
        Path last = Files.createFile(work.resolve("last"));
        Engine engine = new Engine(Options.parse(new String[] {"--h1", work.toString()}));
        var directory = Engine.class.getDeclaredMethod("directory", Path.class);
        directory.setAccessible(true);
        directory.invoke(engine, work.toRealPath());
        Files.createFile(work.resolve("added"));
        engine.location = last.toString();
        var field = Engine.class.getDeclaredField("verifications");
        field.setAccessible(true);
        Object verification = ((List<?>) field.get(engine)).getFirst();
        var run = verification.getClass().getDeclaredMethod("run");
        run.setAccessible(true);
        var error = assertThrows(java.lang.reflect.InvocationTargetException.class, () -> run.invoke(verification));
        assertEquals("INPUT_CHANGED", ((Failure) error.getCause()).code);
        assertEquals(work.toRealPath().toString(), engine.location);
        assertFalse(engine.location.contains("!/"));
    }

    @Test
    void changedFilesystemObjectFailureRetainsItsPathInsteadOfLastEngineLocation() throws Exception {
        Path child = Files.createFile(work.resolve("changed!"));
        FilesInput.Stamp stamp = FilesInput.stamp(child);
        Files.writeString(child, "changed");
        Failure failure = assertThrows(Failure.class, () -> FilesInput.verify(child, stamp));
        assertEquals("INPUT_CHANGED", failure.code);
        assertEquals(child.toString(), failure.location);
        assertFalse(failure.location.contains("!/"));
    }

    private static List<String> spoolFiles() throws Exception {
        try (var paths = Files.list(Path.of(System.getProperty("java.io.tmpdir")))) {
            return paths.map(path -> path.getFileName().toString())
                    .filter(name -> name.startsWith("dirhash-spool-")).sorted().toList();
        }
    }

    @Test
    void trailingZipBytesAreRejectedInBothModesAtRootAndNested() throws Exception {
        byte[] valid = zip("a", Bytes.utf8("A"), true);
        byte[] trailing = Arrays.copyOf(valid, valid.length + 3);
        trailing[valid.length] = 'x';
        trailing[valid.length + 1] = 'y';
        trailing[valid.length + 2] = 'z';
        Path direct = write("trailing.bin", trailing);
        Path nested = write("trailing-parent.zip", zip("inner.bin", trailing, true));
        for (Path source : List.of(direct, nested)) for (boolean strict : List.of(false, true)) {
            Invocation result = strict
                    ? invoke("--h1", "--strict", "--recurse", source.toString())
                    : invoke("--h1", "--recurse", source.toString());
            assertEquals(1, result.status, result.err);
            assertTrue(result.err.startsWith("ARCHIVE_LAYOUT"), result.err);
            assertEquals("", result.out);
        }
    }

    private static void setTarNameAndChecksum(byte[] archive, int offset, byte[] name) {
        Arrays.fill(archive, offset, offset + 100, (byte) 0);
        System.arraycopy(name, 0, archive, offset, name.length);
        Arrays.fill(archive, offset + 148, offset + 156, (byte) ' ');
        long checksum = 0;
        for (int i = offset; i < offset + 512; i++) checksum += archive[i] & 255;
        byte[] encoded = String.format("%06o", checksum).getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(encoded, 0, archive, offset + 148, encoded.length);
        archive[offset + 154] = 0;
        archive[offset + 155] = ' ';
    }

    private static byte[] unicodeZip(byte[] name, String effective, boolean localUnicode) throws Exception {
        byte[] content = Bytes.utf8("X");
        var nameCrc = new java.util.zip.CRC32();
        nameCrc.update(name);
        byte[] text = Bytes.utf8(effective);
        var extra = java.nio.ByteBuffer.allocate(9 + text.length).order(java.nio.ByteOrder.LITTLE_ENDIAN);
        extra.putShort((short) 0x7075).putShort((short) (5 + text.length)).put((byte) 1)
                .putInt((int) nameCrc.getValue()).put(text);
        byte[] localExtra = localUnicode ? extra.array() : new byte[0];
        return framedZip(name, content, localExtra, extra.array(), 0100644);
    }

    private static byte[] framedZip(byte[] name, byte[] content, byte[] localExtra, byte[] centralExtra,
                                    int externalMode) throws Exception {
        return framedZip(name, content, localExtra, centralExtra, externalMode, 3);
    }

    private static byte[] framedZip(byte[] name, byte[] content, byte[] localExtra, byte[] centralExtra,
                                    int externalMode, int creatorPlatform) throws Exception {
        var crc = new java.util.zip.CRC32();
        crc.update(content);
        var local = java.nio.ByteBuffer.allocate(30 + name.length + localExtra.length + content.length)
                .order(java.nio.ByteOrder.LITTLE_ENDIAN);
        local.putInt(0x04034b50).putShort((short) 20).putShort((short) 0).putShort((short) 0)
                .putShort((short) 0).putShort((short) 0).putInt((int) crc.getValue())
                .putInt(content.length).putInt(content.length)
                .putShort((short) name.length).putShort((short) localExtra.length)
                .put(name).put(localExtra).put(content);
        var central = java.nio.ByteBuffer.allocate(46 + name.length + centralExtra.length)
                .order(java.nio.ByteOrder.LITTLE_ENDIAN);
        central.putInt(0x02014b50).putShort((short) (creatorPlatform << 8 | 20)).putShort((short) 20)
                .putShort((short) 0).putShort((short) 0).putShort((short) 0).putShort((short) 0)
                .putInt((int) crc.getValue()).putInt(content.length).putInt(content.length)
                .putShort((short) name.length).putShort((short) centralExtra.length).putShort((short) 0)
                .putShort((short) 0).putShort((short) 0).putInt(externalMode << 16).putInt(0).put(name).put(centralExtra);
        var end = java.nio.ByteBuffer.allocate(22).order(java.nio.ByteOrder.LITTLE_ENDIAN);
        end.putInt(0x06054b50).putShort((short) 0).putShort((short) 0).putShort((short) 1).putShort((short) 1)
                .putInt(central.capacity()).putInt(local.capacity()).putShort((short) 0);
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        output.write(local.array());
        output.write(central.array());
        output.write(end.array());
        return output.toByteArray();
    }

    private static byte[] descriptorZip(int method, byte[] content, byte[] compressed) throws Exception {
        byte[] name = Bytes.utf8("a");
        var crc = new java.util.zip.CRC32();
        crc.update(content);
        var local = java.nio.ByteBuffer.allocate(30 + name.length + compressed.length + 16)
                .order(java.nio.ByteOrder.LITTLE_ENDIAN);
        local.putInt(0x04034b50).putShort((short) 63).putShort((short) 8).putShort((short) method)
                .putShort((short) 0).putShort((short) 0).putInt(0).putInt(0).putInt(0)
                .putShort((short) name.length).putShort((short) 0).put(name).put(compressed)
                .putInt(0x08074b50).putInt((int) crc.getValue()).putInt(compressed.length).putInt(content.length);
        var central = java.nio.ByteBuffer.allocate(46 + name.length).order(java.nio.ByteOrder.LITTLE_ENDIAN);
        central.putInt(0x02014b50).putShort((short) (3 << 8 | 63)).putShort((short) 63)
                .putShort((short) 8).putShort((short) method).putShort((short) 0).putShort((short) 0)
                .putInt((int) crc.getValue()).putInt(compressed.length).putInt(content.length)
                .putShort((short) name.length).putShort((short) 0).putShort((short) 0)
                .putShort((short) 0).putShort((short) 0).putInt(0100644 << 16).putInt(0).put(name);
        var end = java.nio.ByteBuffer.allocate(22).order(java.nio.ByteOrder.LITTLE_ENDIAN);
        end.putInt(0x06054b50).putShort((short) 0).putShort((short) 0).putShort((short) 1).putShort((short) 1)
                .putInt(central.capacity()).putInt(local.capacity()).putShort((short) 0);
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        output.write(local.array());
        output.write(central.array());
        output.write(end.array());
        return output.toByteArray();
    }

    @Test
    void deflatePayloadMustEndExactlyAtAdvertisedCompressedExtent() throws Exception {
        byte[] content = Bytes.utf8("compressed payload");
        ByteArrayOutputStream compressed = new ByteArrayOutputStream();
        var encoder = new java.util.zip.Deflater(6, true);
        try (var out = new java.util.zip.DeflaterOutputStream(compressed, encoder)) { out.write(content); }
        finally { encoder.end(); }
        for (byte[] suffix : List.of(Bytes.utf8("junk"), compressed.toByteArray())) {
            ByteArrayOutputStream combined = new ByteArrayOutputStream();
            combined.write(compressed.toByteArray());
            combined.write(suffix);
            byte[] malformed = descriptorZip(8, content, combined.toByteArray());
            Path top = write("trailing.zip", malformed);
            Path nested = write("nested.zip", zip("inner.zip", malformed, true));
            for (Path source : List.of(top, nested)) for (boolean strict : List.of(false, true)) {
                Invocation result = strict ? invoke("--h1", "--strict", "--recurse", source.toString())
                        : invoke("--h1", "--recurse", source.toString());
                assertEquals(1, result.status, result.err);
                assertTrue(result.err.startsWith("ARCHIVE_INTEGRITY"), result.err);
                assertEquals("", result.out);
            }
        }
    }

    @Test
    void zip64OptionalEndRecordsAndRegisteredExtensibleSectorAreSupported() throws Exception {
        byte[] ordinary = zip("a", Bytes.utf8("x"), true);
        for (boolean sentinel : List.of(false, true)) for (boolean extension : List.of(false, true)) {
            byte[] archive = zip64End(ordinary, sentinel, extension);
            Path source = write("zip64.zip", archive);
            Path parent = write("zip64-parent.zip", zip("inner.zip", archive, false));
            for (Path path : List.of(source, parent)) {
                Invocation result = invoke("--h1", "--strict", "--recurse", path.toString());
                assertEquals(0, result.status, result.err);
                assertTrue(result.out.contains(h1(Map.of("a", Bytes.utf8("x")))));
            }
        }
    }

    private static byte[] zip64End(byte[] ordinary, boolean sentinel, boolean extension) throws Exception {
        int end = ordinary.length - 22;
        var legacy = java.nio.ByteBuffer.wrap(ordinary, end, 22).slice().order(java.nio.ByteOrder.LITTLE_ENDIAN);
        long cdSize = Integer.toUnsignedLong(legacy.getInt(12));
        long cdOffset = Integer.toUnsignedLong(legacy.getInt(16));
        byte[] sector = extension ? extraZip64Sector() : new byte[0];
        var records = java.nio.ByteBuffer.allocate(56 + sector.length + 20 + 22)
                .order(java.nio.ByteOrder.LITTLE_ENDIAN);
        records.putInt(0x06064b50).putLong(44 + sector.length).putShort((short) 45).putShort((short) 45)
                .putInt(0).putInt(0).putLong(1).putLong(1).putLong(cdSize).putLong(cdOffset).put(sector);
        records.putInt(0x07064b50).putInt(0).putLong(end).putInt(1);
        records.putInt(0x06054b50).putShort((short) 0).putShort((short) 0)
                .putShort((short) (sentinel ? 65535 : 1)).putShort((short) (sentinel ? 65535 : 1))
                .putInt(sentinel ? -1 : (int) cdSize).putInt(sentinel ? -1 : (int) cdOffset).putShort((short) 0);
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        output.write(ordinary, 0, end);
        output.write(records.array());
        return output.toByteArray();
    }

    private static byte[] extraZip64Sector() {
        var sector = java.nio.ByteBuffer.allocate(31).order(java.nio.ByteOrder.LITTLE_ENDIAN);
        sector.putShort((short) 0x0065).putInt(25).put(new byte[] {(byte) 0xe9, (byte) 0xf3, (byte) 0xf9, (byte) 0xf0});
        sector.order(java.nio.ByteOrder.BIG_ENDIAN)
                .putShort((short) 5).putShort((short) 0x71).put((byte) 0)
                .putShort((short) 5).putShort((short) 0x72).put((byte) 0)
                .putShort((short) 5).putShort((short) 0x73).put((byte) 0)
                .putShort((short) 6).putShort((short) 0x74).putShort((short) 0);
        return sector.array();
    }

    @Test
    void unsignedDescriptorWhoseCrcEqualsSignatureIsNotMisparsed() throws Exception {
        byte[] content = java.util.HexFormat.of().parseHex("ac0a7ad5");
        var crc = new java.util.zip.CRC32();
        crc.update(content);
        assertEquals(0x08074b50L, crc.getValue());
        ByteArrayOutputStream encoded = new ByteArrayOutputStream();
        var compressor = new java.util.zip.Deflater(6, true);
        try (var stream = new java.util.zip.DeflaterOutputStream(encoded, compressor)) { stream.write(content); }
        finally { compressor.end(); }
        byte[] signed = descriptorZip(8, content, encoded.toByteArray());
        int descriptor = 31 + encoded.size();
        byte[] unsigned = new byte[signed.length - 4];
        System.arraycopy(signed, 0, unsigned, 0, descriptor);
        System.arraycopy(signed, descriptor + 4, unsigned, descriptor, signed.length - descriptor - 4);
        var fields = java.nio.ByteBuffer.wrap(unsigned).order(java.nio.ByteOrder.LITTLE_ENDIAN);
        fields.putInt(unsigned.length - 6, fields.getInt(unsigned.length - 6) - 4);
        Path top = write("unsigned.zip", unsigned);
        Path nested = write("unsigned-parent.zip", zip("inner.zip", unsigned, false));
        for (Path path : List.of(top, nested)) {
            Invocation result = invoke("--h1", "--nar", "--strict", "--recurse", path.toString());
            assertEquals(0, result.status, result.err);
            assertTrue(result.out.contains(h1(Map.of("a", content))));
        }
    }

    @Test
    void streamedZipRejectsContradictoryPlaceholdersAndMissingZip64Chain() throws Exception {
        byte[] ordinary = zip("a", Bytes.utf8("A"), false);
        byte[] contradictory = ordinary.clone();
        java.nio.ByteBuffer.wrap(contradictory).order(java.nio.ByteOrder.LITTLE_ENDIAN).putInt(14, 1);
        byte[] missingZip64 = ordinary.clone();
        java.nio.ByteBuffer.wrap(missingZip64).order(java.nio.ByteOrder.LITTLE_ENDIAN)
                .putShort(missingZip64.length - 14, (short) 65535)
                .putShort(missingZip64.length - 12, (short) 65535);
        for (byte[] invalid : List.of(contradictory, missingZip64)) {
            Path source = write("bad-local.zip", zip("inner.zip", invalid, false));
            Invocation result = invoke("--h1", "--recurse", source.toString());
            assertEquals(1, result.status, result.err);
            assertEquals("", result.out);
        }
    }

    @Test
    void zipCommentMayContainEndRecordLookingBytes() throws Exception {
        byte[] ordinary = zip("a", Bytes.utf8("x"), true);
        byte[] comment = new byte[22];
        java.nio.ByteBuffer.wrap(comment).order(java.nio.ByteOrder.LITTLE_ENDIAN).putInt(0x06054b50);
        ordinary[ordinary.length - 2] = 22;
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        bytes.write(ordinary);
        bytes.write(comment);
        Path source = write("comment.zip", bytes.toByteArray());
        Invocation result = invoke("--h1", "--nar", "--strict", source.toString());
        assertEquals(0, result.status, result.err);
        assertTrue(result.out.contains(h1(Map.of("a", Bytes.utf8("x")))));
    }

    @Test
    void seekableZipMetadataPreflightDoesNotReadCompressedPayload() throws Exception {
        byte[] archive = zip("a", Bytes.utf8("payload".repeat(100)), true);
        int start = 31, end = start + 700;
        Model.SeekableOpener source = () -> new java.nio.channels.SeekableByteChannel() {
            int position;
            boolean open = true;
            @Override public int read(java.nio.ByteBuffer target) {
                int count = Math.min(target.remaining(), archive.length - position);
                if (position < end && position + count > start)
                    throw new AssertionError("metadata preflight read payload");
                target.put(archive, position, count);
                position += count;
                return count == 0 ? -1 : count;
            }
            @Override public long position() { return position; }
            @Override public java.nio.channels.SeekableByteChannel position(long value) { position = (int) value; return this; }
            @Override public long size() { return archive.length; }
            @Override public boolean isOpen() { return open; }
            @Override public void close() { open = false; }
            @Override public int write(java.nio.ByteBuffer bytes) { throw new UnsupportedOperationException(); }
            @Override public java.nio.channels.SeekableByteChannel truncate(long value) { throw new UnsupportedOperationException(); }
        };
        try (var channel = ZipMetadataChannel.open(source);
             var metadata = org.apache.commons.compress.archivers.zip.ZipFile.builder()
                     .setSeekableByteChannel(channel).get()) {
            ZipPhysical.check(source, java.util.Collections.list(metadata.getEntries()), true);
        }
    }

    @Test
    void establishedSelfTerminatingCodecsAllowStreamedDeferredLengths() throws Exception {
        byte[] content = Bytes.utf8("Data descriptors are framing, not a new codec.\n".repeat(100));
        ByteArrayOutputStream bzip = new ByteArrayOutputStream();
        try (var out = new org.apache.commons.compress.compressors.bzip2.BZip2CompressorOutputStream(bzip)) {
            out.write(content);
        }
        ByteArrayOutputStream xz = new ByteArrayOutputStream();
        try (var out = new org.tukaani.xz.XZOutputStream(xz, new org.tukaani.xz.LZMA2Options())) {
            out.write(content);
        }
        ByteArrayOutputStream deflate = new ByteArrayOutputStream();
        var compressor = new java.util.zip.Deflater(0, true);
        try (var out = new java.util.zip.DeflaterOutputStream(deflate, compressor)) { out.write(content); }
        finally { compressor.end(); }
        for (var codec : Map.of(9, deflate.toByteArray(), 12, bzip.toByteArray(), 95, xz.toByteArray()).entrySet()) {
            byte[] inner = descriptorZip(codec.getKey(), content, codec.getValue());
            Path source = write("deferred-" + codec.getKey() + ".zip", zip("inner.zip", inner, false));
            Invocation h1 = invoke("--h1", "--recurse", "--strict", source.toString());
            assertEquals(0, h1.status, h1.err);
            assertEquals(2, h1.out.lines().count());
            assertTrue(h1.out.contains(h1(Map.of("a", content))));
            Invocation nar = invoke("--nar", "--recurse", "--strict", source.toString());
            assertEquals(0, nar.status, nar.err);
            assertEquals(2, nar.out.lines().count());
            Invocation git = invoke("--gittree", "--recurse", source.toString());
            assertEquals(0, git.status, git.err);
            assertEquals(2, git.out.lines().count());
        }
    }

    private static byte[] asi(int mode, String target) {
        byte[] link = Bytes.utf8(target);
        var data = java.nio.ByteBuffer.allocate(14 + link.length).order(java.nio.ByteOrder.LITTLE_ENDIAN);
        data.position(4);
        data.putShort((short) mode).putInt(link.length).putShort((short) 12).putShort((short) 34).put(link);
        var crc = new java.util.zip.CRC32();
        crc.update(data.array(), 4, data.capacity() - 4);
        data.putInt(0, (int) crc.getValue());
        return extra(0x756e, data.array());
    }

    private static byte[] extra(int id, byte[] value) {
        return java.nio.ByteBuffer.allocate(value.length + 4).order(java.nio.ByteOrder.LITTLE_ENDIAN)
                .putShort((short) id).putShort((short) value.length).put(value).array();
    }

    @Test
    void asiModesParticipateInEveryNativeTreeConstruction() throws Exception {
        byte[] content = Bytes.utf8("X");
        Path reference = write("external.zip", framedZip(Bytes.utf8("a"), content, new byte[0], new byte[0], 0100755));
        for (boolean local : List.of(false, true)) {
            byte[] field = asi(0100755, "");
            Path alternate = write("asi-" + local + ".zip", framedZip(Bytes.utf8("a"), content,
                    local ? field : new byte[0], field, 0));
            for (String scheme : List.of("--h1", "--gittree", "--swhid", "--nar")) {
                Invocation expected = invoke(scheme, "--strict", reference.toString());
                Invocation result = invoke(scheme, "--strict", alternate.toString());
                assertEquals(0, result.status, result.err);
                assertEquals(expected.out.split("\t")[1], result.out.split("\t")[1]);
            }
        }
    }

    @Test
    void asiSymlinkUsesExtraTargetButGoManifestUsesActualPayload() throws Exception {
        byte[] field = asi(0120777, ".");
        for (boolean local : List.of(false, true)) {
            byte[] archive = framedZip(Bytes.utf8("link"), new byte[0], local ? field : new byte[0], field, 0);
            Path source = write("link-" + local + ".zip", archive);
            Invocation r = invoke("--h1", "--h1-go", "--gittree", "--nar", "--strict", source.toString());
            assertEquals(0, r.status, r.err);
            assertTrue(r.out.contains(h1(Map.of("link", Bytes.utf8(".")))));
            assertTrue(r.out.contains(h1(Map.of("link", new byte[0]))));
            Path outer = write("nested-" + local + ".zip", zip("inner.zip", archive, false));
            Invocation nested = invoke("--h1", "--nar", "--strict", "--recurse", outer.toString());
            assertEquals(0, nested.status, nested.err);
            assertEquals(4, nested.out.lines().count());
        }
    }

    @Test
    void pkwareUnixInlineSymlinkTargetIsNotMistakenForEmptyContent() throws Exception {
        byte[] value = new byte[13];
        value[12] = '.';
        byte[] field = extra(0x000d, value);
        Path source = write("pkware.zip", framedZip(Bytes.utf8("link"), new byte[0], field, field, 0120777));
        Invocation result = invoke("--h1", "--h1-go", "--nar", "--strict", source.toString());
        assertEquals(0, result.status, result.err);
        assertTrue(result.out.contains(h1(Map.of("link", Bytes.utf8(".")))));
        assertTrue(result.out.contains(h1(Map.of("link", new byte[0]))));
    }

    @Test
    void semanticNtfsAndOldUnixFieldsCompareValuesNotPlacementBytes() {
        var local = java.nio.ByteBuffer.allocate(36).order(java.nio.ByteOrder.LITTLE_ENDIAN);
        local.putInt(0).putShort((short) 1).putShort((short) 24).putLong(10).putLong(20).putLong(30)
                .putShort((short) 2).putShort((short) 0);
        var central = java.nio.ByteBuffer.allocate(36).order(java.nio.ByteOrder.LITTLE_ENDIAN);
        central.putInt(0).putShort((short) 2).putShort((short) 0)
                .putShort((short) 1).putShort((short) 24).putLong(10).putLong(20).putLong(30);
        assertDoesNotThrow(() -> ZipMetadata.reconcile(extra(0xa, local.array()), extra(0xa, central.array())));
        central.putLong(12, 11);
        assertEquals("ARCHIVE_LAYOUT", assertThrows(Failure.class,
                () -> ZipMetadata.reconcile(extra(0xa, local.array()), extra(0xa, central.array()))).code);
        byte[] oldUnix = {1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 4, 0};
        assertDoesNotThrow(() -> ZipMetadata.reconcile(extra(0x5855, oldUnix),
                extra(0x5855, Arrays.copyOf(oldUnix, 8))));
        byte[] disagree = Arrays.copyOf(oldUnix, 8);
        disagree[0] = 9;
        assertThrows(Failure.class, () -> ZipMetadata.reconcile(extra(0x5855, oldUnix), extra(0x5855, disagree)));
    }

    @Test
    void semanticExtrasRejectCorruptionConflictsAndPermitTimestampPlacement() throws Exception {
        byte[] a = asi(0100755, ""), b = asi(0100644, "");
        Path conflict = write("conflict.zip", framedZip(Bytes.utf8("a"), new byte[0], a, b, 0));
        assertEquals(1, invoke("--h1", "--strict", conflict.toString()).status);
        byte[] corrupt = a.clone();
        corrupt[4] ^= 1;
        Path crc = write("crc.zip", framedZip(Bytes.utf8("a"), new byte[0], corrupt, corrupt, 0));
        assertEquals(1, invoke("--h1", crc.toString()).status);
        byte[] local = extra(0x5455, new byte[] {7, 10, 0, 0, 0, 20, 0, 0, 0, 30, 0, 0, 0});
        byte[] central = extra(0x5455, new byte[] {7, 10, 0, 0, 0});
        Path valid = write("ut.zip", framedZip(Bytes.utf8("a"), new byte[0], local, central, 0100644));
        assertEquals(0, invoke("--h1", "--strict", valid.toString()).status);
        central[5] = 11;
        Path invalid = write("ut-conflict.zip", framedZip(Bytes.utf8("a"), new byte[0], local, central, 0100644));
        assertEquals(1, invoke("--h1", "--strict", invalid.toString()).status);
        byte[] uidLocal = extra(0x7875, new byte[] {1, 1, 42, 1, 17});
        byte[] uidCentral = extra(0x7875, new byte[] {1, 2, 42, 0, 2, 17, 0});
        Path uid = write("uid.zip", framedZip(Bytes.utf8("a"), new byte[0], uidLocal, uidCentral, 0100644));
        assertEquals(0, invoke("--h1", "--strict", uid.toString()).status);
        uidCentral[9] = 18;
        Path uidConflict = write("uid-conflict.zip", framedZip(Bytes.utf8("a"), new byte[0], uidLocal, uidCentral, 0100644));
        assertEquals(1, invoke("--h1", "--strict", uidConflict.toString()).status);
    }

    @Test
    void centralOnlyUnicodeCanBeAppliedAfterStreamingPayloadWhenDiscoveryIsInactive() throws Exception {
        byte[] archive = unicodeZip(Bytes.utf8("fallback"), "文件", false);
        // A stream callback has already digested the payload; only namespace metadata is deferred.
        Options options = Options.parse(new String[] {"--h1", "--exclude=fallback", work.toString()});
        Model.Root root = new Model.Root(List.of(), "zip", new Model.Tree());
        var method = Engine.class.getDeclaredMethod("zipStream", InputStream.class, Model.Opener.class,
                Model.Root.class, long.class, boolean.class);
        method.setAccessible(true);
        Engine engine = new Engine(options);
        method.invoke(engine, new ByteArrayInputStream(archive), (Model.Opener) () -> new ByteArrayInputStream(archive),
                root, 0L, true);
        root.tree.membership();
        assertEquals(h1(Map.of("文件", Bytes.utf8("X"))), Hashing.results(options, root).getFirst().value());
    }

    @Test
    void streamedUnicodeEffectiveNameSupersedesNonportableFallback() throws Exception {
        byte[] archive = unicodeZip(Bytes.utf8("?"), "😀", false);
        Path source = write("unicode-stream.zip", zip("inner.zip", archive, false));
        Invocation result = invoke("--h1", "--strict", "--recurse", source.toString());
        assertEquals(0, result.status, result.err);
        assertTrue(result.out.contains(h1(Map.of("😀", Bytes.utf8("X")))));
    }

    @Test
    void unicodePathFieldsCanAppearOnlyInCentralDirectory() throws Exception {
        byte[] raw = {'c', 'a', 'f', (byte) 0x82};
        for (boolean both : List.of(false, true)) {
            Path source = write("unicode-" + both + ".zip", unicodeZip(raw, "café-文件", both));
            Invocation r = invoke("--h1", "--strict", source.toString());
            assertEquals(0, r.status, r.err);
            assertTrue(r.out.contains(h1(Map.of("café-文件", Bytes.utf8("X")))));
        }
    }

    @Test
    void stripPreservesGoRawCp437Names() throws Exception {
        byte[] raw = {'p', 'k', 'g', '/', 'c', 'a', 'f', (byte) 0x82};
        Path source = write("legacy.zip", unicodeZip(raw, "pkg/café", false));
        Invocation r = invoke("--h1", "--h1-go", "--strip-components=1", source.toString());
        assertEquals(0, r.status, r.err);
        assertTrue(r.out.contains(h1(Map.of("café", Bytes.utf8("X")))));
        ByteArrayOutputStream manifest = new ByteArrayOutputStream();
        manifest.write(Bytes.utf8(Bytes.hex(sha256(Bytes.utf8("X"))) + "  "));
        manifest.write(Arrays.copyOfRange(raw, 4, raw.length));
        manifest.write('\n');
        String expected = "h1:" + Base64.getEncoder().encodeToString(sha256(manifest.toByteArray()));
        assertTrue(r.out.contains(expected));
    }

    private static byte[] tar(String name, byte[] data) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (TarArchiveOutputStream out = new TarArchiveOutputStream(bytes, "UTF-8")) {
            out.setLongFileMode(TarArchiveOutputStream.LONGFILE_POSIX);
            TarArchiveEntry entry = new TarArchiveEntry(name, true);
            entry.setSize(data.length);
            entry.setMode(0644);
            out.putArchiveEntry(entry);
            out.write(data);
            out.closeArchiveEntry();
        }
        return bytes.toByteArray();
    }

    @Test
    void allCommonSchemesAgreeAcrossFormats() throws Exception {
        byte[] data = Bytes.utf8("contents\n");
        Path directory = Files.createDirectories(work.resolve("directory"));
        Files.write(directory.resolve("a"), data);
        Path zip = write("payload.zip", zip("a", data, false));
        Path tar = write("payload.tar", tar("a", data));
        ByteArrayOutputStream gz = new ByteArrayOutputStream();
        try (GZIPOutputStream out = new GZIPOutputStream(gz)) { out.write(Files.readAllBytes(tar)); }
        Path gzip = write("payload.tgz", gz.toByteArray());
        List<String> previous = null;
        for (Path source : List.of(directory, zip, tar, gzip)) {
            Invocation r = invoke("--h1", "--gittree", "--swhid", "--nar", "--strict", source.toString());
            assertEquals(0, r.status, r.err);
            List<String> values = r.out.lines().map(line -> line.split("\t")[1]).toList();
            if (previous != null) assertEquals(previous, values);
            previous = values;
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"../x", "/x", "a\\b", "a//b", "a/./b", "C:x", "./C:x", "line\nfeed"})
    void unsafePathsRejectedEvenWhenExcluded(String name) throws Exception {
        Path source = write("bad.zip", zip(name, new byte[0], true));
        Invocation r = invoke("--h1", "--exclude=**", source.toString());
        assertEquals(1, r.status, r.err);
        assertTrue(r.out.isEmpty());
        assertTrue(r.err.startsWith("INVALID_PATH"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"CON.txt", "COM¹.log", "a.", "a ", "x\u200dy", "x\ufdd0y", "x\u0001y"})
    void strictPortableNames(String name) throws Exception {
        Path source = write("bad.zip", zip(name, new byte[0], true));
        Invocation r = invoke("--gittree", "--strict", source.toString());
        assertEquals(1, r.status, r.err);
        assertTrue(r.out.isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {"../x", "/absolute", "a\\b", "C:x", "a/./b", "a//b"})
    void tarOriginalNamesAreValidatedBeforeLibraryNormalization(String name) throws Exception {
        byte[] archive = tar("safe", new byte[0]);
        Arrays.fill(archive, 0, 100, (byte) 0);
        byte[] rawName = Bytes.utf8(name);
        System.arraycopy(rawName, 0, archive, 0, rawName.length);
        Arrays.fill(archive, 148, 156, (byte) ' ');
        byte[] header = Arrays.copyOf(archive, 512);
        TarUtils.formatCheckSumOctalBytes(TarUtils.computeCheckSum(header), archive, 148, 8);
        Path source = write("bad.tar", archive);
        Invocation r = invoke("--h1", source.toString());
        assertEquals(1, r.status, r.err);
        assertTrue(r.err.startsWith("INVALID_PATH"));
        assertEquals("", r.out);
    }

    @Test
    void changesDetectedOnReread() throws Exception {
        Path file = write("changing", Bytes.utf8("a"));
        var stamp = FilesInput.stamp(file);
        Model.Opener opener = FilesInput.opener(file, stamp);
        Files.write(file, Bytes.utf8("changed"));
        Failure e = assertThrows(Failure.class, opener::open);
        assertEquals("INPUT_CHANGED", e.code);
    }

    @Test
    void archiveLimitsAreAtomic() throws Exception {
        Path file = write("limits.zip", zip("dir/a", Bytes.utf8("abc"), true));
        for (String option : List.of("--max-entries=1", "--max-expanded-bytes=2")) {
            Invocation r = invoke("--h1", option, file.toString());
            assertEquals(1, r.status, r.err);
            assertEquals("", r.out);
            assertTrue(r.err.startsWith("LIMIT_EXCEEDED"));
        }
    }

    private static byte[] hardlinkArchive(byte[] content, boolean forward, String targetName) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (TarArchiveOutputStream output = new TarArchiveOutputStream(bytes, "UTF-8")) {
            TarArchiveEntry file = new TarArchiveEntry(targetName);
            file.setSize(content.length);
            TarArchiveEntry alias = new TarArchiveEntry("alias.zip", (byte) '1');
            alias.setLinkName(targetName);
            if (forward) {
                output.putArchiveEntry(alias);
                output.closeArchiveEntry();
            }
            output.putArchiveEntry(file);
            output.write(content);
            output.closeArchiveEntry();
            if (!forward) {
                output.putArchiveEntry(alias);
                output.closeArchiveEntry();
            }
        }
        return bytes.toByteArray();
    }

    @Test
    void tarHardlinkArchiveAliasesDiscoverWithIndependentBoundaryExclusions() throws Exception {
        byte[] nested = zip("a", Bytes.utf8("A"), true);
        for (boolean forward : List.of(false, true)) {
            Path source = write("alias-" + forward + ".tar", hardlinkArchive(nested, forward, "target.bin"));
            Invocation plain = invoke("--h1", source.toString());
            Invocation recursive = invoke("--h1", "--strict", "--recurse",
                    "--exclude=alias.zip!/a", source.toString());
            assertEquals(0, recursive.status, recursive.err);
            assertEquals(plain.out.lines().findFirst().orElseThrow(), recursive.out.lines().findFirst().orElseThrow());
            assertEquals(3, recursive.out.lines().count());
            assertTrue(recursive.out.contains("!/alias.zip"));
            assertTrue(recursive.out.contains("!/target.bin"));
            assertTrue(recursive.out.contains(h1(Map.of())));
            Invocation excluded = invoke("--h1", "--strict", "--recurse",
                    "--exclude=target.bin", source.toString());
            assertEquals(0, excluded.status, excluded.err);
            assertEquals(2, excluded.out.lines().count());
            assertTrue(excluded.out.contains(h1(Map.of("a", Bytes.utf8("A")))));
            Invocation limit = invoke("--h1", "--recurse",
                    "--max-expanded-bytes=" + (nested.length * 2L + 2), source.toString());
            assertEquals(0, limit.status, limit.err);
            Invocation exceeded = invoke("--h1", "--recurse",
                    "--max-expanded-bytes=" + (nested.length * 2L + 1), source.toString());
            assertEquals(1, exceeded.status, exceeded.err);
            assertTrue(exceeded.err.startsWith("LIMIT_EXCEEDED"));
        }
    }

    @Test
    void hardlinkAliasArchiveSuffixRequiresARealArchiveUnlessAliasIsExcluded() throws Exception {
        Path source = write("not-an-archive.tar", hardlinkArchive(Bytes.utf8("ordinary"), false, "target.bin"));
        Invocation recursive = invoke("--h1", "--recurse", source.toString());
        assertEquals(1, recursive.status, recursive.err);
        assertTrue(recursive.err.startsWith("ARCHIVE_INTEGRITY"));
        assertEquals("", recursive.out);
        Invocation excluded = invoke("--h1", "--strict", "--exclude=alias.zip", source.toString());
        assertEquals(0, excluded.status, excluded.err);
        assertEquals(1, excluded.out.lines().count());
    }

    @Test
    void spooledArchiveCanBeRevisitedForGzipHardlinkAlias() throws Exception {
        byte[] nested = zip("a", Bytes.utf8("A"), true);
        ByteArrayOutputStream gzip = new ByteArrayOutputStream();
        try (GZIPOutputStream out = new GZIPOutputStream(gzip)) {
            out.write(hardlinkArchive(nested, false, "target.bin"));
        }
        Path source = write("aliases.tgz", gzip.toByteArray());
        Invocation nar = invoke("--nar", "--recurse", "--strict", source.toString());
        assertEquals(0, nar.status, nar.err);
        assertEquals(3, nar.out.lines().count());
        Invocation h1 = invoke("--h1", "--recurse", source.toString());
        assertEquals(0, h1.status, h1.err);
        assertEquals(3, h1.out.lines().count());
    }

    @Test
    void forwardSequentialHardlinkArchivesShareTargetBytesAcrossIndependentDiscoveries() throws Exception {
        byte[] nested = zip("a", Bytes.utf8("A"), true);
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (GZIPOutputStream gzip = new GZIPOutputStream(bytes)) {
            gzip.write(hardlinkArchive(nested, true, "target.bin"));
        }
        Path source = write("forward-alias.tgz", bytes.toByteArray());
        Invocation result = invoke("--h1", "--gittree", "--strict", "--recurse", source.toString());
        assertEquals(0, result.status, result.err);
        assertEquals(6, result.out.lines().count());
        assertTrue(result.out.contains(h1(Map.of("a", Bytes.utf8("A")))));
        Invocation excluded = invoke("--h1", "--strict", "--recurse", "--exclude=target.bin",
                "--exclude=alias.zip!/a", source.toString());
        assertEquals(0, excluded.status, excluded.err);
        assertEquals(2, excluded.out.lines().count());
        assertTrue(excluded.out.contains(h1(Map.of())));
    }

    @Test
    void spooledArchiveCanRevisitDeferredZipSymlinkTarget() throws Exception {
        byte[] archive = framedZip(Bytes.utf8("link"), Bytes.utf8("."), new byte[0], new byte[0], 0120777);
        Path source = write("symlink-outer.zip", zip("inner.zip", archive, false));
        Invocation nar = invoke("--nar", "--strict", "--recurse", source.toString());
        assertEquals(0, nar.status, nar.err);
        assertEquals(2, nar.out.lines().count());
        Invocation h1 = invoke("--h1", "--strict", "--recurse", source.toString());
        assertEquals(0, h1.status, h1.err);
        assertEquals(2, h1.out.lines().count());
    }

    @Test
    void largeSparseParserConstraintIsAnExplicitRepresentationLimit() throws Exception {
        String value = "GNU.sparse.size=2147483648\n";
        int length = value.length() + 3;
        while (Integer.toString(length).length() + 1 + value.length() != length)
            length = Integer.toString(length).length() + 1 + value.length();
        byte[] record = Bytes.utf8(length + " " + value);
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (TarArchiveOutputStream out = new TarArchiveOutputStream(bytes)) {
            TarArchiveEntry pax = new TarArchiveEntry("PaxHeaders/sparse", (byte) 'x');
            pax.setSize(record.length);
            out.putArchiveEntry(pax);
            out.write(record);
            out.closeArchiveEntry();
            out.putArchiveEntry(new TarArchiveEntry("sparse"));
            out.closeArchiveEntry();
        }
        Path source = write("large-sparse.tar", bytes.toByteArray());
        Invocation result = invoke("--h1", source.toString());
        assertEquals(1, result.status, result.err);
        assertTrue(result.err.startsWith("LIMIT_EXCEEDED"));
        assertEquals("", result.out);
    }

    @Test
    void deferredNestedZipSupportsAllCommonSchemes() throws Exception {
        byte[] inner = zip("a", Bytes.utf8("bytes"), false);
        Path outer = write("outer.zip", zip("inner.zip", inner, false));
        for (String scheme : List.of("--h1", "--nar", "--gittree", "--swhid")) {
            Invocation r = invoke(scheme, "--recurse", "--strict", outer.toString());
            assertEquals(0, r.status, r.err);
            assertEquals(2, r.out.lines().count());
        }
    }

    @Test
    void seekableStoredZipAndTarMembersPreflightDeferredMetadataWithoutPayloadSpools() throws Exception {
        byte[] inner = zip("a", Bytes.utf8("A"), false);
        Path reference = write("reference.zip", inner);
        Invocation expected = invoke("--h1", "--gittree", "--nar", "--strict", reference.toString());
        assertEquals(0, expected.status, expected.err);
        List<String> values = expected.out.lines().map(line -> line.split("\t")[1]).toList();
        Path stored = write("stored-parent.zip", zip("inner.zip", inner, true));
        Path tar = write("tar-parent.tar", hardlinkArchive(inner, true, "target.bin"));
        for (Path source : List.of(stored, tar)) {
            Invocation result = invoke("--h1", "--gittree", "--nar", "--strict", "--recurse", source.toString());
            assertEquals(0, result.status, result.err);
            List<String> all = result.out.lines().map(line -> line.split("\t")[1]).toList();
            assertEquals(source.equals(stored) ? 6 : 9, all.size());
            assertEquals(values, all.subList(3, 6));
            if (source.equals(tar)) assertEquals(values, all.subList(6, 9));
        }
    }

    @Test
    void sparseSeekableViewsExposeOnlyTheirLogicalBytesAndPermitMetadataSeeks() throws Exception {
        Path source = write("sparse-data", Bytes.utf8("ABCXY"));
        Model.SeekableOpener physical = FilesInput.seekable(source, FilesInput.stamp(source));
        Model.SeekableOpener sparse = LogicalChannel.sparse(physical, 0, 16, List.of(
                new org.apache.commons.compress.archivers.tar.TarArchiveStructSparse(2, 3),
                new org.apache.commons.compress.archivers.tar.TarArchiveStructSparse(10, 2)));
        try (var channel = sparse.open()) {
            channel.position(10);
            java.nio.ByteBuffer value = java.nio.ByteBuffer.allocate(2);
            assertEquals(2, channel.read(value));
            assertArrayEquals(Bytes.utf8("XY"), value.array());
            channel.position(14);
            value.clear();
            assertEquals(2, channel.read(value));
            assertArrayEquals(new byte[2], value.array());
            assertEquals(-1, channel.read(java.nio.ByteBuffer.allocate(1)));
            channel.position(3);
            value.clear();
            assertEquals(2, channel.read(value));
            assertArrayEquals(Bytes.utf8("BC"), value.array());
        }
    }

    @Test
    void recursionPreservesParentRawBytesAndBoundaryExclusions() throws Exception {
        byte[] inner = zip("x", Bytes.utf8("X"), true);
        Path outer = write("outer.zip", zip("a!b.zip", inner, true));
        Invocation plain = invoke("--h1", outer.toString());
        Invocation recursive = invoke("--h1", "--recurse", "--exclude=a!!b.zip!/x", outer.toString());
        assertEquals(0, recursive.status, recursive.err);
        assertEquals(plain.out.lines().findFirst().orElseThrow(), recursive.out.lines().findFirst().orElseThrow());
        assertTrue(recursive.out.contains("!/a!!b.zip"));
        assertTrue(recursive.out.contains("h1:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="));
    }

    @Test
    void discoveryRequiresStructuralEvidenceRatherThanShortMagic() throws Exception {
        Map<String, byte[]> files = Map.of("zip.bin", new byte[] {'P', 'K', 3, 4},
                "gzip.bin", new byte[] {31, (byte) 139}, "zero.bin", new byte[512]);
        for (var file : files.entrySet()) Files.write(work.resolve(file.getKey()), file.getValue());
        Invocation r = invoke("--h1", "--recurse", work.toString());
        assertEquals(0, r.status, r.err);
        assertEquals(1, r.out.lines().count());
        assertTrue(r.out.contains(h1(files)));
    }

    @Test
    void extensionlessArchiveIsDiscoveredByStructure() throws Exception {
        Files.write(work.resolve("payload.bin"), zip("a", Bytes.utf8("A"), true));
        Invocation r = invoke("--h1", "--recurse", "--strict", work.toString());
        assertEquals(0, r.status, r.err);
        assertEquals(2, r.out.lines().count());
        assertTrue(r.out.contains(work.resolve("payload.bin").toString()));
        assertFalse(r.out.contains(work + "!/payload.bin"));
        assertTrue(r.out.contains(h1(Map.of("a", Bytes.utf8("A")))));
    }

    @Test
    void sparseTrailingHolesUseLogicalContent() throws Exception {
        byte[] header = new byte[512];
        TarArchiveEntry entry = new TarArchiveEntry("sparse", (byte) 'S');
        entry.setSize(5);
        entry.setMode(0644);
        entry.writeEntryHeader(header);
        System.arraycopy(new byte[] {'u', 's', 't', 'a', 'r', ' ', ' ', 0}, 0, header, 257, 8);
        TarUtils.formatLongOctalBytes(2, header, 386, 12);
        TarUtils.formatLongOctalBytes(3, header, 398, 12);
        TarUtils.formatLongOctalBytes(10, header, 410, 12);
        TarUtils.formatLongOctalBytes(2, header, 422, 12);
        TarUtils.formatLongOctalBytes(16, header, 483, 12);
        Arrays.fill(header, 148, 156, (byte) ' ');
        TarUtils.formatCheckSumOctalBytes(TarUtils.computeCheckSum(header), header, 148, 8);
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        bytes.write(header);
        bytes.write(Bytes.utf8("ABCXY"));
        bytes.write(new byte[507 + 1024]);
        Path source = write("sparse.tar", bytes.toByteArray());
        byte[] logical = {0, 0, 'A', 'B', 'C', 0, 0, 0, 0, 0, 'X', 'Y', 0, 0, 0, 0};
        Invocation r = invoke("--h1", "--nar", "--strict", source.toString());
        assertEquals(0, r.status, r.err);
        assertTrue(r.out.contains(h1(Map.of("sparse", logical))));
        byte[] surplus = bytes.toByteArray();
        TarUtils.formatLongOctalBytes(6, surplus, 124, 12);
        Arrays.fill(surplus, 148, 156, (byte) ' ');
        byte[] changedHeader = Arrays.copyOf(surplus, 512);
        TarUtils.formatCheckSumOctalBytes(TarUtils.computeCheckSum(changedHeader), surplus, 148, 8);
        Path invalid = write("surplus-sparse.tar", surplus);
        Invocation rejected = invoke("--h1", invalid.toString());
        assertEquals(1, rejected.status, rejected.err);
        assertEquals("", rejected.out);
    }

    @Test
    void namesUseUnsignedUtf8AndUnicode16FullCasefold() {
        assertTrue(Bytes.compare("\ue000", "\ud800\udc00") < 0);
        assertEquals(Names.fold("Straße"), Names.fold("STRASSE"));
        assertEquals(Names.fold("ς"), Names.fold("σ"));
        assertEquals(Names.fold("é"), Names.fold("e\u0301"));
        assertEquals(Names.fold("\u1c89"), Names.fold("\u1c8a"));
        assertEquals(Names.fold("\uac00"), Names.fold("\u1100\u1161"));
        assertEquals(com.ibm.icu.util.VersionInfo.getInstance(16, 0, 0, 0),
                com.ibm.icu.lang.UCharacter.getUnicodeVersion());
    }

    @Test
    void strictLinksDistinguishRepeatedFiniteTraversalFromCycles() {
        Model.Tree tree = new Model.Tree();
        tree.add(new Model.Node("d", Model.Type.DIRECTORY));
        Model.Node alias = new Model.Node("alias", Model.Type.SYMLINK);
        alias.target = Bytes.utf8("d");
        tree.add(alias);
        Model.Node link = new Model.Node("link", Model.Type.SYMLINK);
        link.target = Bytes.utf8("alias/../".repeat(30) + "d");
        tree.add(link);
        assertDoesNotThrow(() -> Names.links(tree.nodes));
        alias.target = Bytes.utf8("link");
        assertEquals("UNSAFE_SYMLINK", assertThrows(Failure.class, () -> Names.links(tree.nodes)).code);
    }

    @Test
    void deeplyNestedOrdinaryTreesDoNotUseCallStack() throws Exception {
        Model.Tree tree = new Model.Tree();
        String path = "";
        for (int i = 0; i < 1200; i++) {
            path = path.isEmpty() ? "d" : path + "/d";
            Model.Node node = new Model.Node(path, Model.Type.DIRECTORY);
            node.included = true;
            tree.add(node);
        }
        Options options = Options.parse(new String[] {"--h1", "--gittree", "--swhid", "--nar", work.toString()});
        assertEquals(4, Hashing.results(options, new Model.Root(List.of(), "directory", tree)).size());
    }
}
