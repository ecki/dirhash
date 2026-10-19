package dirhash;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.List;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.junit.jupiter.api.Test;

class PortableVectorTest {
    @Test
    void globalPaxPathSizeAndLinkpathApplyOnFreshAndRepeatedReads() throws Exception {
        for (String key : List.of("path", "size", "linkpath")) {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            String value = key.equals("path") ? "😀" : key.equals("size") ? "1" : "target";
            record(bytes, "GlobalPax", (byte) 'g', pax(key, value), -1, "");
            if (key.equals("linkpath")) {
                record(bytes, "target", (byte) '0', new byte[] {'x'}, 1, "");
                record(bytes, "link", (byte) '2', new byte[0], 0, "missing");
            } else record(bytes, key.equals("path") ? "?" : "a", (byte) '0', new byte[] {'x'},
                    key.equals("size") ? 0 : 1, "");
            bytes.write(new byte[1024]);
            for (int pass = 0; pass < 2; pass++) {
                Engine engine = new Engine(Options.parse(new String[] {"--h1", "--strict", "fixture"}));
                try (var input = new SparseTarInput(new TarPhysical(new ByteArrayInputStream(bytes.toByteArray()), engine))) {
                    TarArchiveEntry entry = input.getNextEntry();
                    assertNotNull(entry);
                    assertEquals(key.equals("path") ? "😀" : key.equals("size") ? "a" : "target", entry.getName());
                    assertEquals(1, entry.getSize());
                    assertArrayEquals(new byte[] {'x'}, input.readAllBytes());
                    if (key.equals("linkpath")) {
                        entry = input.getNextEntry();
                        assertNotNull(entry);
                        assertTrue(entry.isSymbolicLink());
                        assertEquals("target", entry.getLinkName());
                    }
                    assertNull(input.getNextEntry());
                }
            }
        }
    }

    @Test
    void anchoredGlobsDoNotCrossArchiveBoundariesAndStarsMatchScalars() {
        for (var vector : List.of(
                List.of("*.tmp", "", "a.tmp", "true"),
                List.of("*.tmp", "", "dir/a.tmp", "false"),
                List.of("**/*.tmp", "", "dir/a.tmp", "true"),
                List.of("**/*.tmp", "inner.zip", "a.tmp", "false"),
                List.of("a!!b.zip!/x*", "a!b.zip", "x😀", "true"),
                List.of("inner.zip!/cache/", "inner.zip", "cache/file", "true"))) {
            Options options = Options.parse(new String[] {"--h1", "--exclude=" + vector.get(0), "fixture"});
            List<String> archives = vector.get(1).isEmpty() ? List.of() : List.of(vector.get(1));
            assertEquals(Boolean.parseBoolean(vector.get(3)),
                    Exclusions.excluded(options, archives, vector.get(2), false), vector.toString());
        }
    }

    @Test
    void jsonEscapesControlCharactersButRetainsScalarUnicodeAndLiteralBackslashes() {
        assertEquals("\"a\\\\b\\n\\u0001\u2028😀\"", Bytes.json("a\\b\n\u0001\u2028😀"));
    }

    private static byte[] pax(String key, String value) {
        byte[] item = Bytes.utf8(key + "=" + value + "\n");
        int length = item.length + 2;
        while (Integer.toString(length).length() + 1 + item.length != length)
            length = Integer.toString(length).length() + 1 + item.length;
        return Bytes.utf8(length + " " + key + "=" + value + "\n");
    }

    private static void record(ByteArrayOutputStream bytes, String name, byte type, byte[] content,
                               long size, String link) throws Exception {
        TarArchiveEntry entry = new TarArchiveEntry(name, type);
        entry.setSize(size < 0 ? content.length : size);
        entry.setLinkName(link);
        byte[] header = new byte[512];
        entry.writeEntryHeader(header);
        bytes.write(header);
        bytes.write(content);
        bytes.write(new byte[(512 - content.length % 512) % 512]);
    }
}
