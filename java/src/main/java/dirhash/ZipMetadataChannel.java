package dirhash;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.NonWritableChannelException;
import java.nio.channels.SeekableByteChannel;
import java.util.ArrayList;
import java.util.List;

final class ZipMetadataChannel implements SeekableByteChannel {
    private final SeekableByteChannel source;
    private final List<Long> masked;

    static SeekableByteChannel open(Model.SeekableOpener opener) throws IOException {
        SeekableByteChannel source = opener.open();
        try {
            long end = ZipPhysical.endOffset(source);
            long start = end + 22;
            ByteBuffer comment = ByteBuffer.allocate((int) Math.min(65535, source.size() - start));
            source.position(start);
            while (comment.hasRemaining() && source.read(comment) >= 0) {}
            List<Long> masked = new ArrayList<>();
            byte[] bytes = comment.array();
            for (int i = 0; i + 4 <= comment.position(); i++)
                if (ZipPhysical.u32(bytes, i) == 0x06054b50L) masked.add(start + i);
            source.position(0);
            return new ZipMetadataChannel(source, masked);
        } catch (IOException | RuntimeException failure) {
            source.close();
            throw failure;
        }
    }

    private ZipMetadataChannel(SeekableByteChannel source, List<Long> masked) {
        this.source = source;
        this.masked = masked;
    }

    @Override public int read(ByteBuffer target) throws IOException {
        long start = source.position();
        int offset = target.position();
        int count = source.read(target);
        for (long signature : masked)
            if (signature >= start && signature - start < count)
                target.put(offset + (int) (signature - start), (byte) 0);
        return count;
    }
    @Override public long position() throws IOException { return source.position(); }
    @Override public SeekableByteChannel position(long position) throws IOException { source.position(position); return this; }
    @Override public long size() throws IOException { return source.size(); }
    @Override public boolean isOpen() { return source.isOpen(); }
    @Override public void close() throws IOException { source.close(); }
    @Override public int write(ByteBuffer bytes) { throw new NonWritableChannelException(); }
    @Override public SeekableByteChannel truncate(long size) { throw new NonWritableChannelException(); }
}
