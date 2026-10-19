package dirhash;

import java.io.IOException;
import java.io.InputStream;
import java.io.PushbackInputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;
import org.apache.commons.compress.compressors.bzip2.BZip2CompressorInputStream;
import org.apache.commons.compress.compressors.deflate64.Deflate64CompressorInputStream;
import org.apache.commons.compress.compressors.xz.XZCompressorInputStream;
import org.apache.commons.compress.compressors.zstandard.ZstdCompressorInputStream;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;

final class StreamingZip {
    interface Consumer {
        Model.Node consume(String name, byte[] rawName, long size, ZipMetadata.Unix unix,
                           InputStream bytes, int index) throws IOException;
    }
    interface Reconciler {
        void accept(Model.Node node, String name, ZipMetadata.Unix unix) throws IOException;
    }

    private final Counting in;
    private final boolean strict;
    private final Consumer consumer;
    private final Reconciler reconciler;
    private final boolean targetsRequired;
    private final Map<String, ZipArchiveEntry> metadata;
    private final Map<Long, Local> locals = new HashMap<>();
    private final List<Local> central = new ArrayList<>();

    private static final class Local {
        final long offset;
        final int flags;
        final int method;
        final String name;
        final byte[] raw;
        final Model.Node node;
        final long crc;
        final long compressed;
        final long size;
        final byte[] extra;

        Local(long offset, int flags, int method, String name, byte[] raw, Model.Node node,
              long crc, long compressed, long size, byte[] extra) {
            this.offset = offset;
            this.flags = flags;
            this.method = method;
            this.name = name;
            this.raw = raw;
            this.node = node;
            this.crc = crc;
            this.compressed = compressed;
            this.size = size;
            this.extra = extra;
        }
    }

    StreamingZip(InputStream input, boolean strict, boolean targetsRequired,
                 Map<String, ZipArchiveEntry> metadata, Consumer consumer, Reconciler reconciler) {
        in = new Counting(input);
        this.strict = strict;
        this.consumer = consumer;
        this.reconciler = reconciler;
        this.targetsRequired = targetsRequired;
        this.metadata = metadata;
    }

    void read() throws IOException {
        long signature = signature();
        int index = 0;
        while (signature == 0x04034b50L) {
            long offset = in.position - 4;
            byte[] header = bytes(26);
            int flags = ZipPhysical.u16(header, 2), method = ZipPhysical.u16(header, 4);
            flags(flags);
            if (!java.util.Set.of(0, 8, 9, 12, 20, 93, 95).contains(method))
                throw Failure.unsupported("UNSUPPORTED_METHOD", "ZIP method " + method);
            byte[] name = bytes(ZipPhysical.u16(header, 22));
            byte[] extra = bytes(ZipPhysical.u16(header, 24));
            String decoded = ZipPhysical.decode(name, flags, extra);
            ZipMetadata.Unix unix = ZipMetadata.unix(0, 0, extra, new byte[0]);
            long crc = ZipPhysical.u32(header, 10), compressed = ZipPhysical.u32(header, 14),
                    size = ZipPhysical.u32(header, 18);
            boolean wide = compressed == 0xffffffffL || size == 0xffffffffL || ZipPhysical.hasExtra(extra, 1);
            long[] z64 = sizes(extra, size == 0xffffffffL, compressed == 0xffffffffL, false);
            if (size == 0xffffffffL) size = z64[0];
            if (compressed == 0xffffffffL) compressed = z64[1];
            boolean descriptor = (flags & 8) != 0;
            long knownCompressed = descriptor && compressed == 0 ? -1 : compressed;
            long knownSize = descriptor && size == 0 ? -1 : size;
            ZipArchiveEntry known = metadata.get(Bytes.hex(name));
            if (known != null) {
                knownCompressed = known.getCompressedSize();
                knownSize = known.getSize();
                wide |= knownCompressed > 0xffffffffL || knownSize > 0xffffffffL;
            }
            if (knownCompressed < 0 && !java.util.Set.of(8, 9, 12, 95).contains(method))
                throw Failure.unsupported("UNSUPPORTED_STREAMING", "ZIP compressed length is deferred for this codec");
            long start = in.position;
            Bounded bounded = knownCompressed < 0 ? null : new Bounded(in, knownCompressed);
            InputStream source = bounded == null && method != 8 ? new InputStream() {
                @Override public int read(byte[] b, int offset, int length) throws IOException {
                    return length == 0 ? 0 : in.read(b, offset, 1);
                }
                @Override public int read() throws IOException { return in.read(); }
            } : bounded == null ? in : bounded;
            Inflated deflate = null;
            InputStream payload = switch (method) {
                case 0 -> source;
                case 8 -> deflate = new Inflated(source, bounded == null ? in : null);
                case 9 -> new Deflate64CompressorInputStream(source);
                case 12 -> new BZip2CompressorInputStream(source, false);
                case 20, 93 -> new ZstdCompressorInputStream(source);
                case 95 -> new XZCompressorInputStream(source, false);
                default -> throw new AssertionError();
            };
            CrcInput checked = new CrcInput(payload);
            Model.Node node;
            try {
                node = consumer.consume(decoded, name, knownSize, unix, checked, index++);
                Engine.drain(checked);
                if (bounded != null && bounded.remaining != 0)
                    throw Failure.invalid("ARCHIVE_INTEGRITY", "ZIP decoder ended before compressed extent");
                if (deflate != null && !deflate.finished)
                    throw Failure.invalid("ARCHIVE_INTEGRITY", "DEFLATE stream did not terminate");
            } finally {
                if (deflate != null) deflate.end();
                else payload.close();
            }
            long actualCompressed = in.position - start;
            if (descriptor) {
                long first = signature();
                byte[] lengths = bytes(wide ? 16 : 8);
                boolean unsignedMatch = first == checked.crc.getValue()
                        && (wide ? ZipPhysical.u64(lengths, 0) : ZipPhysical.u32(lengths, 0)) == actualCompressed
                        && (wide ? ZipPhysical.u64(lengths, 8) : ZipPhysical.u32(lengths, 4)) == checked.count;
                long statedCrc = first;
                if (first == 0x08074b50L && !unsignedMatch) {
                    statedCrc = ZipPhysical.u32(lengths, 0);
                    byte[] shifted = new byte[lengths.length];
                    System.arraycopy(lengths, 4, shifted, 0, lengths.length - 4);
                    System.arraycopy(bytes(4), 0, shifted, lengths.length - 4, 4);
                    lengths = shifted;
                }
                long statedCompressed = wide ? ZipPhysical.u64(lengths, 0) : ZipPhysical.u32(lengths, 0);
                long statedSize = wide ? ZipPhysical.u64(lengths, 8) : ZipPhysical.u32(lengths, 4);
                if (statedCrc != checked.crc.getValue() || statedCompressed != actualCompressed || statedSize != checked.count)
                    throw Failure.invalid("ARCHIVE_INTEGRITY", "ZIP data descriptor mismatch");
                if (crc != 0 && crc != statedCrc || compressed != 0 && compressed != statedCompressed
                        || size != 0 && size != statedSize)
                    throw Failure.invalid("ARCHIVE_LAYOUT", "ZIP local descriptor placeholders contradict payload");
                crc = statedCrc;
                compressed = statedCompressed;
                size = statedSize;
            }
            if (crc != checked.crc.getValue() || size != checked.count || compressed != actualCompressed)
                throw Failure.invalid("ARCHIVE_INTEGRITY", "ZIP payload size or CRC mismatch");
            node.size = node.target != null ? node.target.length : size;
            locals.put(offset, new Local(offset, flags, method, decoded, name, node, crc, compressed, size, extra));
            signature = signature();
        }
        long cdStart = in.position - 4;
        while (signature == 0x02014b50L) {
            byte[] h = bytes(42);
            int flags = ZipPhysical.u16(h, 4), method = ZipPhysical.u16(h, 6);
            flags(flags);
            byte[] raw = bytes(ZipPhysical.u16(h, 24)), extra = bytes(ZipPhysical.u16(h, 26));
            bytes(ZipPhysical.u16(h, 28));
            if (ZipPhysical.u16(h, 30) != 0)
                throw Failure.unsupported("UNSUPPORTED_FORMAT", "split ZIP");
            long compressed = ZipPhysical.u32(h, 16), size = ZipPhysical.u32(h, 20),
                    offset = ZipPhysical.u32(h, 38);
            long[] z64 = sizes(extra, size == 0xffffffffL, compressed == 0xffffffffL, offset == 0xffffffffL);
            if (size == 0xffffffffL) size = z64[0];
            if (compressed == 0xffffffffL) compressed = z64[1];
            if (offset == 0xffffffffL) offset = z64[2];
            Local local = locals.remove(offset);
            if (local == null || local.flags != flags || local.method != method || !Arrays.equals(local.raw, raw)
                    || local.crc != ZipPhysical.u32(h, 12) || local.size != size || local.compressed != compressed)
                throw Failure.invalid("ARCHIVE_LAYOUT", "ZIP central/local entry mismatch");
            String name = ZipPhysical.decode(raw, flags, extra);
            if (!ZipPhysical.hasExtra(extra, 0x7075) && ZipPhysical.hasExtra(local.extra, 0x7075))
                name = local.node.storedName;
            int platform = h[1] & 255;
            int external = platform == 3 || platform == 19
                    ? (int) (ZipPhysical.u32(h, 34) >>> 16) : 0;
            ZipMetadata.Unix unix;
            try {
                ZipMetadata.reconcile(local.extra, extra);
                unix = ZipMetadata.unix(external, platform, local.extra, extra);
            } catch (Failure failure) {
                throw failure.at(name);
            }
            int mode = unix.mode();
            int type = mode & 0170000;
            if (type != 0 && type != 0100000 && type != 0040000 && type != 0120000) {
                if (ZipMetadata.directoryModeCompatibility(unix, name, local.node.size, strict)) type = 0040000;
                else throw Failure.invalid("SPECIAL_FILE", ZipMetadata.modeDescription(mode)
                        + " for entry " + Bytes.textPath(name)).at(name);
            }
            reconciler.accept(local.node, name, unix);
            local.node.mode = mode;
            if (type == 0120000) {
                local.node.type = Model.Type.SYMLINK;
                if (targetsRequired && local.node.target == null)
                    throw Failure.unsupported("UNSUPPORTED_STREAMING", "ZIP symlink target type is deferred until central directory");
            } else if ((type == 0040000) != (local.node.type == Model.Type.DIRECTORY) && type != 0)
                throw Failure.invalid("ARCHIVE_LAYOUT", "ZIP name and directory mode disagree");
            central.add(local);
            signature = signature();
        }
        long cdSize = in.position - 4 - cdStart;
        long count = central.size();
        long cdOffset = cdStart;
        boolean zip64 = signature == 0x06064b50L;
        if (zip64) {
            long zip64Offset = in.position - 4;
            byte[] z = bytes(52);
            long recordSize = ZipPhysical.u64(z, 0);
            if (recordSize < 44 || ZipPhysical.u32(z, 12) != 0 || ZipPhysical.u32(z, 16) != 0
                    || ZipPhysical.u64(z, 20) != count || ZipPhysical.u64(z, 28) != count
                    || ZipPhysical.u64(z, 36) != cdSize || ZipPhysical.u64(z, 44) != cdOffset)
                throw Failure.invalid("ARCHIVE_LAYOUT", "invalid streamed ZIP64 end");
            long remaining = recordSize - 44;
            while (remaining > 0) {
                if (remaining < 6)
                    throw Failure.invalid("ARCHIVE_LAYOUT", "truncated ZIP64 extensible-sector header");
                byte[] header = bytes(6);
                long size = ZipPhysical.u32(header, 2);
                if (size > remaining - 6)
                    throw Failure.invalid("ARCHIVE_LAYOUT", "ZIP64 extensible sector exceeds end record");
                if (size != 25)
                    ZipPhysical.zip64Sector(ZipPhysical.u16(header, 0), new byte[0], size);
                ZipPhysical.zip64Sector(ZipPhysical.u16(header, 0), bytes(25), size);
                remaining -= 6 + size;
            }
            if (signature() != 0x07064b50L) throw Failure.invalid("ARCHIVE_LAYOUT", "ZIP64 locator missing");
            byte[] locator = bytes(16);
            if (ZipPhysical.u32(locator, 0) != 0 || ZipPhysical.u64(locator, 4) != zip64Offset
                    || ZipPhysical.u32(locator, 12) != 1)
                throw Failure.invalid("ARCHIVE_LAYOUT", "invalid streamed ZIP64 locator");
            signature = signature();
        }
        if (signature != 0x06054b50L)
            throw Failure.invalid("ARCHIVE_LAYOUT", "ZIP end record missing");
        byte[] end = bytes(18);
        if (!zip64 && (ZipPhysical.u16(end, 4) == 65535 || ZipPhysical.u16(end, 6) == 65535
                || ZipPhysical.u32(end, 8) == 0xffffffffL || ZipPhysical.u32(end, 12) == 0xffffffffL))
            throw Failure.invalid("ARCHIVE_LAYOUT", "ZIP64 sentinel requires complete ZIP64 end chain");
        if (ZipPhysical.u16(end, 0) != 0 || ZipPhysical.u16(end, 2) != 0
                || ZipPhysical.u16(end, 4) != ZipPhysical.u16(end, 6)
                || ZipPhysical.u16(end, 6) != 65535 && ZipPhysical.u16(end, 6) != count
                || ZipPhysical.u32(end, 8) != 0xffffffffL && ZipPhysical.u32(end, 8) != cdSize
                || ZipPhysical.u32(end, 12) != 0xffffffffL && ZipPhysical.u32(end, 12) != cdOffset
                || !locals.isEmpty())
            throw Failure.invalid("ARCHIVE_LAYOUT", "inconsistent streamed ZIP directory extent/count");
        bytes(ZipPhysical.u16(end, 16));
        if (strict && in.read() != -1)
            throw Failure.invalid("ARCHIVE_LAYOUT", "data after streamed ZIP end");
        Engine.drain(in);
    }

    private static void flags(int flags) {
        if ((flags & ~0x080e) != 0)
            throw Failure.unsupported("UNSUPPORTED_FORMAT", "encrypted/unsupported ZIP flags");
    }

    private byte[] bytes(int length) throws IOException {
        byte[] value = in.readNBytes(length);
        if (value.length != length) throw Failure.invalid("ARCHIVE_INTEGRITY", "truncated ZIP structure");
        return value;
    }

    private long signature() throws IOException {
        return ZipPhysical.u32(bytes(4), 0);
    }

    private static long[] sizes(byte[] extra, boolean size, boolean compressed, boolean offset) {
        if (!size && !compressed && !offset) return new long[3];
        for (int p = 0; p + 4 <= extra.length;) {
            int id = ZipPhysical.u16(extra, p), length = ZipPhysical.u16(extra, p + 2);
            p += 4;
            if (length > extra.length - p) break;
            if (id == 1) {
                int needed = (size ? 8 : 0) + (compressed ? 8 : 0) + (offset ? 8 : 0);
                if (length < needed) break;
                long a = size ? ZipPhysical.u64(extra, p) : 0;
                if (size) p += 8;
                long b = compressed ? ZipPhysical.u64(extra, p) : 0;
                if (compressed) p += 8;
                long c = offset ? ZipPhysical.u64(extra, p) : 0;
                return new long[] {a, b, c};
            }
            p += length;
        }
        throw Failure.invalid("ARCHIVE_INTEGRITY", "missing ZIP64 extra field");
    }

    private static final class Counting extends PushbackInputStream {
        long position;
        Counting(InputStream input) { super(input, 65536); }
        @Override public int read(byte[] b, int o, int l) throws IOException {
            int n = super.read(b, o, l);
            if (n > 0) position += n;
            return n;
        }
        @Override public int read() throws IOException {
            int n = super.read();
            if (n >= 0) position++;
            return n;
        }
        @Override public void unread(byte[] b, int o, int l) throws IOException {
            super.unread(b, o, l);
            position -= l;
        }
    }

    private static final class Bounded extends InputStream {
        final InputStream input;
        long remaining;
        Bounded(InputStream input, long remaining) { this.input = input; this.remaining = remaining; }
        @Override public int read(byte[] b, int o, int l) throws IOException {
            if (l == 0) return 0;
            if (remaining == 0) return -1;
            int n = input.read(b, o, (int) Math.min(l, remaining));
            if (n < 0) throw Failure.invalid("ARCHIVE_INTEGRITY", "truncated ZIP payload");
            remaining -= n;
            return n;
        }
        @Override public int read() throws IOException {
            byte[] b = new byte[1];
            return read(b, 0, 1) < 0 ? -1 : b[0] & 255;
        }
    }

    private static final class CrcInput extends InputStream {
        final InputStream input;
        final java.util.zip.CRC32 crc = new java.util.zip.CRC32();
        long count;
        CrcInput(InputStream input) { this.input = input; }
        @Override public int read(byte[] b, int o, int l) throws IOException {
            int n = input.read(b, o, l);
            if (n > 0) { crc.update(b, o, n); count += n; }
            return n;
        }
        @Override public int read() throws IOException {
            byte[] b = new byte[1];
            return read(b, 0, 1) < 0 ? -1 : b[0] & 255;
        }
    }

    static final class Inflated extends InputStream {
        final InputStream source;
        final Counting pushback;
        final Inflater inflater = new Inflater(true);
        final byte[] input = new byte[65536];
        int lastInput;
        boolean finished;

        Inflated(InputStream source, Counting pushback) { this.source = source; this.pushback = pushback; }

        @Override public int read(byte[] b, int offset, int length) throws IOException {
            if (length == 0) return 0;
            if (finished) return -1;
            while (true) {
                try {
                    int n = inflater.inflate(b, offset, length);
                    if (inflater.finished()) {
                        int remaining = inflater.getRemaining();
                        if (remaining != 0) {
                            if (pushback == null)
                                throw Failure.invalid("ARCHIVE_INTEGRITY", "bytes after DEFLATE stream inside ZIP extent");
                            pushback.unread(input, lastInput - remaining, remaining);
                        }
                        finished = true;
                        return n == 0 ? -1 : n;
                    }
                    if (n > 0) return n;
                    if (inflater.needsDictionary()) throw new IOException("DEFLATE dictionary not supported");
                    if (!inflater.needsInput()) throw new IOException("DEFLATE decoder made no progress");
                    lastInput = source.read(input);
                    if (lastInput < 0) throw Failure.invalid("ARCHIVE_INTEGRITY", "truncated DEFLATE stream");
                    inflater.setInput(input, 0, lastInput);
                } catch (DataFormatException e) {
                    throw Failure.invalid("ARCHIVE_INTEGRITY", "invalid DEFLATE payload");
                }
            }
        }

        @Override public int read() throws IOException {
            byte[] b = new byte[1];
            return read(b, 0, 1) < 0 ? -1 : b[0] & 255;
        }
        void end() { inflater.end(); }
        long compressedCount() { return inflater.getBytesRead(); }
        @Override public void close() throws IOException {
            try { end(); } finally { source.close(); }
        }
    }
}
