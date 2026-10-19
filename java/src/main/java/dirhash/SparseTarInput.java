package dirhash;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;

final class SparseTarInput extends TarArchiveInputStream {
    private long logicalSize = -1;
    private long extentEnd;
    private long position;
    private final TarPhysical physical;

    SparseTarInput(InputStream input) {
        super(input, 512, 512, "UTF-8");
        physical = input instanceof TarPhysical checked ? checked : null;
    }

    @Override
    public TarArchiveEntry getNextEntry() throws IOException {
        if (logicalSize >= 0) {
            byte[] buffer = new byte[8192];
            while (read(buffer) >= 0) {}
        }
        logicalSize = -1;
        TarArchiveEntry entry = super.getNextEntry();
        if (entry != null && entry.isSparse()) {
            long end = 0;
            long represented = 0;
            for (var extent : entry.getOrderedSparseHeaders()) {
                if (extent.getOffset() < end || extent.getNumbytes() < 0
                        || extent.getOffset() > entry.getRealSize()
                        || extent.getNumbytes() > entry.getRealSize() - extent.getOffset())
                    throw Failure.invalid("ARCHIVE_INTEGRITY", "invalid sparse extent");
                end = extent.getOffset() + extent.getNumbytes();
                represented = Math.addExact(represented, extent.getNumbytes());
            }
            if (physical != null && represented != physical.payloadRemaining())
                throw Failure.invalid("ARCHIVE_INTEGRITY", "sparse extents do not account for physical payload");
            logicalSize = entry.getRealSize();
            extentEnd = end;
            position = 0;
            if (end < logicalSize) {
                // Commons 1.28 reconstructs inter-extent holes but omits the final hole.
                // Bound its logical reader at the final extent; supply only the trailing zeros.
                long representedEnd = end;
                TarArchiveEntry bounded = new TarArchiveEntry(entry.getName()) {
                    @Override public long getRealSize() { return representedEnd; }
                    @Override public boolean isSparse() { return true; }
                };
                bounded.setSize(entry.getSize());
                setCurrentEntry(bounded);
            }
        }
        return entry;
    }

    @Override
    public int read(byte[] bytes, int offset, int length) throws IOException {
        if (logicalSize < 0) return super.read(bytes, offset, length);
        if (length == 0) return 0;
        if (position == logicalSize) return -1;
        int n;
        if (position < extentEnd) {
            n = super.read(bytes, offset, (int) Math.min(length, extentEnd - position));
            if (n < 0) throw Failure.invalid("ARCHIVE_INTEGRITY", "truncated sparse content");
        } else {
            n = (int) Math.min(length, logicalSize - position);
            Arrays.fill(bytes, offset, offset + n, (byte) 0);
        }
        position += n;
        return n;
    }

    @Override
    public long skip(long length) throws IOException {
        long count = 0;
        byte[] buffer = new byte[8192];
        while (count < length) {
            int n = read(buffer, 0, (int) Math.min(buffer.length, length - count));
            if (n < 0) break;
            count += n;
        }
        return count;
    }
}
