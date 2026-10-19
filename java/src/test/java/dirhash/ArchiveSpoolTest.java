package dirhash;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.AfterEach;

class ArchiveSpoolTest {
    private String temporaryDirectory;

    @BeforeEach
    void temporaryStorage() throws Exception {
        temporaryDirectory = System.getProperty("java.io.tmpdir");
        System.setProperty("java.io.tmpdir", Path.of("target").toRealPath().toString());
    }

    @AfterEach
    void restoreTemporaryStorage() {
        System.setProperty("java.io.tmpdir", temporaryDirectory);
    }

    private static InputStream source(long length, int chunk) {
        return new InputStream() {
            private long position;
            @Override public int read() {
                return position == length ? -1 : (int) (position++ & 255);
            }
            @Override public int read(byte[] bytes, int offset, int count) {
                if (position == length) return -1;
                int n = (int) Math.min(Math.min(count, chunk), length - position);
                for (int i = 0; i < n; i++) bytes[offset + i] = (byte) position++;
                return n;
            }
        };
    }

    private static List<String> files() throws IOException {
        try (var paths = Files.list(Path.of(System.getProperty("java.io.tmpdir")))) {
            return paths.map(path -> path.getFileName().toString())
                    .filter(name -> name.startsWith("dirhash-spool-")).sorted().toList();
        }
    }

    @Test
    void exactDecimalThresholdAndUnknownShortReadsChooseMemoryOrDisk() throws Exception {
        List<String> before = files();
        for (int length : List.of(ArchiveSpool.MEMORY_LIMIT - 1, ArchiveSpool.MEMORY_LIMIT,
                ArchiveSpool.MEMORY_LIMIT + 1)) {
            for (boolean known : List.of(false, true)) {
                var memory = new ArchiveSpool.MemoryBudget();
                try (ArchiveSpool spool = ArchiveSpool.copy(source(length, 37), known ? length : -1, memory)) {
                    assertEquals(length > ArchiveSpool.MEMORY_LIMIT, spool.onDisk());
                    assertTrue(memory.retained() <= ArchiveSpool.MEMORY_LIMIT);
                    try (var channel = spool.channel()) {
                        assertEquals(length, channel.size());
                        channel.position(length - 2);
                        ByteBuffer bytes = ByteBuffer.allocate(3);
                        assertEquals(2, channel.read(bytes));
                        assertEquals((byte) (length - 2), bytes.get(0));
                        assertEquals((byte) (length - 1), bytes.get(1));
                        assertEquals(-1, channel.read(bytes));
                    }
                    try (InputStream reopened = spool.open()) { assertEquals(0, reopened.read()); }
                }
                assertEquals(0, memory.retained());
                assertEquals(before, files());
            }
        }
    }

    @Test
    void aggregateRetainedMemoryIsBoundedAcrossSiblingArchives() throws Exception {
        var memory = new ArchiveSpool.MemoryBudget();
        try (ArchiveSpool first = ArchiveSpool.copy(source(6_000_000, 65536), -1, memory);
             ArchiveSpool second = ArchiveSpool.copy(source(6_000_000, 65536), -1, memory)) {
            assertFalse(first.onDisk());
            assertTrue(second.onDisk());
            assertTrue(memory.retained() <= ArchiveSpool.MEMORY_LIMIT);
        }
        assertEquals(0, memory.retained());
    }

    @Test
    void temporaryStorageCannotBeInsideSelectedRoot() throws Exception {
        var memory = new ArchiveSpool.MemoryBudget();
        Path root = Path.of(System.getProperty("java.io.tmpdir")).toRealPath().getRoot();
        memory.selectedRoot(root);
        try {
            Path selected = memory.externalDirectory();
            assertFalse(selected.startsWith(root));
        } catch (IOException expected) {
            assertTrue(expected.getMessage().contains("outside selected input root"));
        }
    }

    @Test
    void ordinaryDirectoryMutationDetectionRetainsCompleteStampChecks() throws Exception {
        Path directory = Files.createDirectory(Path.of("target", "stamp-" + java.util.UUID.randomUUID()));
        try {
            FilesInput.Stamp stamp = FilesInput.stamp(directory);
            Files.setLastModifiedTime(directory, java.nio.file.attribute.FileTime.fromMillis(
                    stamp.modified().toMillis() + 5000));
            Failure failure = assertThrows(Failure.class, () -> FilesInput.verify(directory, stamp));
            assertEquals("INPUT_CHANGED", failure.code);
        } finally { Files.delete(directory); }
    }

    @Test
    void shortAndExcessClaimsRejectMemoryAndDiskCopiesWithCleanup() throws Exception {
        List<String> before = files();
        for (long expected : List.of(100L, ArchiveSpool.MEMORY_LIMIT + 2L)) {
            for (long actual : List.of(expected - 1, expected + 1)) {
                var memory = new ArchiveSpool.MemoryBudget();
                Failure error = assertThrows(Failure.class,
                        () -> ArchiveSpool.copy(source(actual, 65536), expected, memory));
                assertEquals("ARCHIVE_INTEGRITY", error.code);
                assertEquals(0, memory.retained());
                assertEquals(before, files());
            }
        }
    }

    @Test
    void expansionBudgetRejectsBeforeSpillWriteAndCleansUp() throws Exception {
        List<String> before = files();
        for (long limit : List.of(10_000_000L, 10_100_000L)) {
            var memory = new ArchiveSpool.MemoryBudget();
            Options options = Options.parse(new String[] {"--h1", "--max-expanded-bytes=" + limit, "."});
            Payload input = new Payload(source(limit + 1, 65536), new Engine(options), -1, true, false);
            Failure error = assertThrows(Failure.class, () -> ArchiveSpool.copy(input, -1, memory));
            assertEquals("LIMIT_EXCEEDED", error.code);
            assertEquals(0, memory.retained());
            assertEquals(before, files());
        }
    }

    @Test
    void inputFailureAndCancellationReleaseMemoryAndDisk() throws Exception {
        List<String> before = files();
        for (long length : List.of(100L, ArchiveSpool.MEMORY_LIMIT + 1L)) {
            var memory = new ArchiveSpool.MemoryBudget();
            InputStream broken = new java.io.FilterInputStream(source(length, 65536)) {
                @Override public int read(byte[] bytes, int offset, int count) throws IOException {
                    int n = in.read(bytes, offset, count);
                    if (n < 0) throw new IOException("injected read failure");
                    return n;
                }
            };
            assertThrows(IOException.class, () -> ArchiveSpool.copy(broken, -1, memory));
            assertEquals(0, memory.retained());
            assertEquals(before, files());
        }
        var memory = new ArchiveSpool.MemoryBudget();
        Thread.currentThread().interrupt();
        try {
            assertThrows(java.io.InterruptedIOException.class,
                    () -> ArchiveSpool.copy(source(1, 1), -1, memory));
        } finally { Thread.interrupted(); }
        assertEquals(0, memory.retained());
        assertEquals(before, files());
    }
}
