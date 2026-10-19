package dirhash;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.NonWritableChannelException;
import java.nio.channels.SeekableByteChannel;
import java.util.List;
import org.apache.commons.compress.archivers.tar.TarArchiveStructSparse;

final class LogicalChannel implements SeekableByteChannel {
    private final SeekableByteChannel source;
    private final long dataOffset;
    private final long size;
    private final List<TarArchiveStructSparse> extents;
    private final long[] physical;
    private long position;

    static Model.SeekableOpener range(Model.SeekableOpener source, long offset, long size) {
        return sparse(source, offset, size, List.of(new TarArchiveStructSparse(0, size)));
    }

    static Model.SeekableOpener sparse(Model.SeekableOpener source, long offset, long size,
                                      List<TarArchiveStructSparse> extents) {
        return () -> new LogicalChannel(source.open(), offset, size, extents);
    }

    private LogicalChannel(SeekableByteChannel source, long dataOffset, long size,
                           List<TarArchiveStructSparse> extents) {
        this.source = source;
        this.dataOffset = dataOffset;
        this.size = size;
        this.extents = extents;
        physical = new long[extents.size()];
        long offset = dataOffset;
        for (int i = 0; i < physical.length; i++) {
            physical[i] = offset;
            offset += extents.get(i).getNumbytes();
        }
    }

    @Override public int read(ByteBuffer target) throws IOException {
        if (!target.hasRemaining()) return 0;
        if (position == size) return -1;
        int index = 0;
        while (index < extents.size()
                && extents.get(index).getOffset() + extents.get(index).getNumbytes() <= position) index++;
        boolean hole = index == extents.size() || position < extents.get(index).getOffset();
        long end = index == extents.size() ? size : hole ? extents.get(index).getOffset()
                : extents.get(index).getOffset() + extents.get(index).getNumbytes();
        int length = (int) Math.min(target.remaining(), end - position);
        int count = length;
        if (hole) for (int i = 0; i < length; i++) target.put((byte) 0);
        else {
            source.position(physical[index] + position - extents.get(index).getOffset());
            int limit = target.limit();
            target.limit(target.position() + length);
            try { count = source.read(target); } finally { target.limit(limit); }
            if (count < 0) throw Failure.invalid("INPUT_CHANGED", "seekable archive extent disappeared");
        }
        position += count;
        return count;
    }

    @Override public long position() { return position; }
    @Override public SeekableByteChannel position(long value) {
        if (value < 0 || value > size) throw new IllegalArgumentException("position outside logical extent");
        position = value;
        return this;
    }
    @Override public long size() { return size; }
    @Override public boolean isOpen() { return source.isOpen(); }
    @Override public void close() throws IOException { source.close(); }
    @Override public int write(ByteBuffer bytes) { throw new NonWritableChannelException(); }
    @Override public SeekableByteChannel truncate(long length) { throw new NonWritableChannelException(); }
}
