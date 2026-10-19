package dirhash;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

final class ArchiveSpool implements AutoCloseable {
    static final int MEMORY_LIMIT = 10_000_000;
    private static final int BLOCK = 65536;
    static final class MemoryBudget {
        private long retained;
        private Path selectedRoot;
        synchronized boolean reserve(long n) {
            if (n > MEMORY_LIMIT - retained) return false;
            retained += n;
            return true;
        }
        synchronized void release(long n) { retained -= n; }
        synchronized long retained() { return retained; }
        void selectedRoot(Path root) { selectedRoot = root; }

        Path externalDirectory() throws IOException {
            var candidates = new java.util.LinkedHashSet<String>();
            candidates.add(System.getProperty("java.io.tmpdir"));
            candidates.add(System.getenv("TEMP"));
            candidates.add(System.getenv("TMP"));
            for (String candidate : candidates) {
                if (candidate == null || candidate.isBlank()) continue;
                Path directory;
                try { directory = Path.of(candidate).toRealPath(); }
                catch (IOException | RuntimeException ignored) { continue; }
                if (Files.isDirectory(directory) && (selectedRoot == null || !directory.startsWith(selectedRoot)))
                    return directory;
            }
            throw new IOException("no private temporary storage outside selected input root");
        }
    }
    private final List<byte[]> blocks = new ArrayList<>();
    private final MemoryBudget memory;
    private long capacity;
    private Path file;
    private Model.Opener diskOpener;
    private Model.SeekableOpener diskSeekable;
    private long length;
    private boolean closed;

    private ArchiveSpool(MemoryBudget memory) { this.memory = memory; }

    static ArchiveSpool copy(InputStream input, long expected, MemoryBudget memory) throws IOException {
        ArchiveSpool spool = new ArchiveSpool(memory);
        boolean complete = false;
        OutputStream output = null;
        try {
            if (expected > MEMORY_LIMIT) output = spool.spill();
            byte[] buffer = new byte[BLOCK];
            int n;
            while ((n = input.read(buffer)) >= 0) {
                if (Thread.currentThread().isInterrupted())
                    throw new java.io.InterruptedIOException("nested archive materialization interrupted");
                if (n == 0) continue;
                if (expected >= 0 && n > expected - spool.length)
                    throw Failure.invalid("ARCHIVE_INTEGRITY", "nested archive exceeds its declared entry length");
                if (output == null && !spool.reserve(n)) output = spool.spill();
                if (output == null) spool.append(buffer, n);
                else output.write(buffer, 0, n);
                spool.length += n;
            }
            if (expected >= 0 && spool.length != expected)
                throw Failure.invalid("ARCHIVE_INTEGRITY", "nested archive is shorter than its declared entry length");
            if (output != null) {
                output.close();
                output = null;
                FilesInput.Stamp stamp = FilesInput.stamp(spool.file);
                spool.diskOpener = FilesInput.opener(spool.file, stamp);
                spool.diskSeekable = FilesInput.seekable(spool.file, stamp);
            }
            complete = true;
            return spool;
        } finally {
            try {
                if (output != null) output.close();
            } finally {
                if (!complete) spool.close();
            }
        }
    }

    private boolean reserve(int count) {
        if (count > MEMORY_LIMIT - length) return false;
        long needed = Math.min(MEMORY_LIMIT, ((length + count + BLOCK - 1) / BLOCK) * BLOCK);
        if (!memory.reserve(needed - capacity)) return false;
        capacity = needed;
        return true;
    }

    private void append(byte[] bytes, int count) {
        int copied = 0;
        while (copied < count) {
            int blockIndex = (int) ((length + copied) / BLOCK);
            int offset = (int) ((length + copied) % BLOCK);
            if (blockIndex == blocks.size())
                blocks.add(new byte[Math.min(BLOCK, MEMORY_LIMIT - blockIndex * BLOCK)]);
            byte[] block = blocks.get(blockIndex);
            int n = Math.min(count - copied, block.length - offset);
            System.arraycopy(bytes, copied, block, offset, n);
            copied += n;
        }
    }

    private OutputStream spill() throws IOException {
        file = Download.createPrivateTemp(memory.externalDirectory(), "dirhash-spool-");
        OutputStream output = Files.newOutputStream(file);
        try {
            long remaining = length;
            for (byte[] block : blocks) {
                int n = (int) Math.min(block.length, remaining);
                output.write(block, 0, n);
                remaining -= n;
            }
            blocks.clear();
            memory.release(capacity);
            capacity = 0;
            return output;
        } catch (IOException | RuntimeException failure) {
            output.close();
            throw failure;
        }
    }

    boolean onDisk() { return file != null; }

    InputStream open() throws IOException {
        if (closed) throw new IOException("archive materialization is closed");
        return diskOpener == null ? Channels.newInputStream(channel()) : diskOpener.open();
    }

    SeekableByteChannel channel() throws IOException {
        if (closed) throw new IOException("archive materialization is closed");
        if (diskSeekable != null) return diskSeekable.open();
        return new SeekableByteChannel() {
            private long position;
            private boolean open = true;
            private void check() throws IOException {
                if (!open || closed) throw new java.nio.channels.ClosedChannelException();
            }
            @Override public int read(ByteBuffer target) throws IOException {
                check();
                if (!target.hasRemaining()) return 0;
                if (position >= length) return -1;
                int count = (int) Math.min(target.remaining(), length - position);
                int remaining = count;
                while (remaining > 0) {
                    byte[] block = blocks.get((int) (position / BLOCK));
                    int offset = (int) (position % BLOCK);
                    int n = Math.min(remaining, block.length - offset);
                    target.put(block, offset, n);
                    remaining -= n;
                    position += n;
                }
                return count;
            }
            @Override public int write(ByteBuffer source) { throw new java.nio.channels.NonWritableChannelException(); }
            @Override public long position() throws IOException { check(); return position; }
            @Override public SeekableByteChannel position(long value) throws IOException {
                check();
                if (value < 0) throw new IllegalArgumentException("negative position");
                position = value;
                return this;
            }
            @Override public long size() throws IOException { check(); return length; }
            @Override public SeekableByteChannel truncate(long size) { throw new java.nio.channels.NonWritableChannelException(); }
            @Override public boolean isOpen() { return open && !closed; }
            @Override public void close() { open = false; }
        };
    }

    @Override public void close() throws IOException {
        closed = true;
        blocks.clear();
        memory.release(capacity);
        capacity = 0;
        Download.delete(file);
    }
}
