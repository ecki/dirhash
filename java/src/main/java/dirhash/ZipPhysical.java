package dirhash;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.zip.CRC32;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;

final class ZipPhysical {
    record Metadata(String name, ZipMetadata.Unix unix) {}
    static String decode(byte[] raw, int flags, byte[] extras) {
        String unicode = null;
        for (int p = 0; p < extras.length;) {
            if (extras.length - p < 4) throw Failure.invalid("ARCHIVE_INTEGRITY", "truncated ZIP extra field");
            int id = u16(extras, p), length = u16(extras, p + 2);
            p += 4;
            if (length > extras.length - p)
                throw Failure.invalid("ARCHIVE_INTEGRITY", "truncated ZIP extra payload");
            if (id == 0x7075) {
                if (unicode != null || length < 5 || extras[p] != 1)
                    throw Failure.invalid("INVALID_ENCODING", "malformed ZIP Unicode Path field");
                CRC32 crc = new CRC32();
                crc.update(raw);
                if (crc.getValue() != u32(extras, p + 1))
                    throw Failure.invalid("INVALID_ENCODING", "ZIP Unicode Path name CRC mismatch");
                unicode = Bytes.decode(Arrays.copyOfRange(extras, p + 5, p + length));
            }
            p += length;
        }
        String result = (flags & 0x800) != 0 ? Bytes.decode(raw)
                : unicode != null ? unicode : new String(raw, Charset.forName("IBM437"));
        if (unicode != null && (flags & 0x800) != 0 && !unicode.equals(result))
            throw Failure.invalid("INVALID_ENCODING", "contradictory ZIP Unicode names");
        return result;
    }

    static Map<Long, Metadata> check(Model.SeekableOpener source, List<ZipArchiveEntry> entries, boolean strict) throws IOException {
        Map<Long, Metadata> metadata = new HashMap<>();
        try (ChannelFile file = new ChannelFile(source.open())) {
            long end = findEnd(file);
            byte[] eocd = read(file, end, 22);
            if (u16(eocd, 4) != 0 || u16(eocd, 6) != 0 || u16(eocd, 8) != u16(eocd, 10))
                throw Failure.unsupported("UNSUPPORTED_FORMAT", "split/multi-disk ZIP");
            long count = u16(eocd, 10), cdSize = u32(eocd, 12), cd = u32(eocd, 16);
            long endOfDirectory = end;
            boolean locatorPresent = end >= 20 && u32(read(file, end - 20, 4), 0) == 0x07064b50L;
            if (count == 65535 || cdSize == 0xffffffffL || cd == 0xffffffffL || locatorPresent) {
                byte[] locator = read(file, end - 20, 20);
                if (u32(locator, 0) != 0x07064b50L || u32(locator, 4) != 0 || u32(locator, 16) != 1)
                    throw Failure.invalid("ARCHIVE_LAYOUT", "invalid ZIP64 locator");
                long zip64Offset = u64(locator, 8);
                byte[] zip64 = read(file, zip64Offset, 56);
                long recordSize = u64(zip64, 4);
                if (u32(zip64, 0) != 0x06064b50L || recordSize < 44
                        || u32(zip64, 16) != 0 || u32(zip64, 20) != 0
                        || u64(zip64, 24) != u64(zip64, 32)
                        || zip64Offset > end - 32 || recordSize != end - 32 - zip64Offset)
                    throw Failure.unsupported("UNSUPPORTED_FORMAT", "unsupported ZIP64 end structure");
                if (count != 65535 && count != u64(zip64, 32)
                        || cdSize != 0xffffffffL && cdSize != u64(zip64, 40)
                        || cd != 0xffffffffL && cd != u64(zip64, 48))
                    throw Failure.invalid("ARCHIVE_LAYOUT", "ZIP64 and classic end fields disagree");
                long sector = zip64Offset + 56, sectorEnd = end - 20;
                while (sector < sectorEnd) {
                    if (sectorEnd - sector < 6)
                        throw Failure.invalid("ARCHIVE_LAYOUT", "truncated ZIP64 extensible-sector header");
                    byte[] header = read(file, sector, 6);
                    long size = u32(header, 2);
                    if (size > sectorEnd - sector - 6)
                        throw Failure.invalid("ARCHIVE_LAYOUT", "ZIP64 extensible sector exceeds end record");
                    zip64Sector(u16(header, 0), read(file, sector + 6, (int) Math.min(size, 25)), size);
                    sector += 6 + size;
                }
                count = u64(zip64, 32);
                cdSize = u64(zip64, 40);
                cd = u64(zip64, 48);
                endOfDirectory = zip64Offset;
            }

            if (count != entries.size() || cd < 0 || cdSize < 0 || cd > endOfDirectory
                    || cdSize != endOfDirectory - cd)
                throw Failure.invalid("ARCHIVE_LAYOUT", "inconsistent ZIP central-directory extent/count");
            long position = cd;
            Map<Long, byte[]> centralExtras = new HashMap<>();
            Map<Long, Integer> centralPlatforms = new HashMap<>();
            Map<Long, Integer> externalModes = new HashMap<>();
            for (int i = 0; i < entries.size(); i++) {
                byte[] central = read(file, position, 46);
                if (u32(central, 0) != 0x02014b50L)
                    throw Failure.invalid("ARCHIVE_LAYOUT", "invalid ZIP central-directory record");
                byte[] extra = read(file, position + 46 + u16(central, 28), u16(central, 30));
                ZipMetadata.fields(extra);
                centralExtras.put(entries.get(i).getLocalHeaderOffset(), extra);
                centralPlatforms.put(entries.get(i).getLocalHeaderOffset(), central[5] & 255);
                externalModes.put(entries.get(i).getLocalHeaderOffset(),
                        (int) (u32(central, 38) >>> 16));
                position += 46L + u16(central, 28) + u16(central, 30) + u16(central, 32);
                if (position > cd + cdSize)
                    throw Failure.invalid("ARCHIVE_LAYOUT", "central-directory record exceeds extent");
            }
            if (position != cd + cdSize)
                throw Failure.invalid("ARCHIVE_LAYOUT", "unaccounted central-directory bytes");
            List<ZipArchiveEntry> physical = new ArrayList<>(entries);
            physical.sort(Comparator.comparingLong(ZipArchiveEntry::getLocalHeaderOffset));
            long previous = 0;
            for (ZipArchiveEntry e : physical) {
                long offset = e.getLocalHeaderOffset();
                if (offset < previous || strict && offset != previous)
                    throw Failure.invalid("ARCHIVE_LAYOUT", "ZIP overlap, prefix, hidden local entry or gap");
                byte[] local = read(file, offset, 30);
                if (u32(local, 0) != 0x04034b50L)
                    throw Failure.invalid("ARCHIVE_LAYOUT", "missing ZIP local header");
                int flags = u16(local, 6);
                if ((flags & ~0x080e) != 0 || e.getGeneralPurposeBit().usesEncryption())
                    throw Failure.unsupported("UNSUPPORTED_FORMAT", "encrypted or unsupported ZIP flags");
                if (flags != e.getRawFlag() || u16(local, 8) != e.getMethod())
                    throw Failure.invalid("ARCHIVE_LAYOUT", "ZIP local/central method or flags mismatch");
                byte[] raw = read(file, offset + 30, u16(local, 26));
                byte[] extras = read(file, offset + 30 + raw.length, u16(local, 28));
                byte[] centralExtra = centralExtras.get(offset);
                String centralName = decode(raw, flags, centralExtra);
                String localName = decode(raw, flags, extras);
                String effective = hasUnicode(centralExtra) ? centralName : localName;
                ZipMetadata.Unix unix;
                try {
                    ZipMetadata.reconcile(extras, centralExtra);
                    int creatorPlatform = centralPlatforms.get(offset);
                    int externalMode = creatorPlatform == 3 || creatorPlatform == 19
                            ? externalModes.get(offset) : e.getUnixMode();
                    unix = ZipMetadata.unix(externalMode, creatorPlatform, extras, centralExtra);
                } catch (Failure failure) {
                    throw failure.at(effective);
                }
                metadata.put(offset, new Metadata(effective, unix));
                if (!Arrays.equals(raw, e.getRawName())
                        || hasUnicode(extras) && !localName.equals(effective))
                    throw Failure.invalid("ARCHIVE_LAYOUT", "ZIP local/central names disagree");
                long data = offset + 30 + raw.length + extras.length;
                if (data != e.getDataOffset() || e.getCompressedSize() < 0 || e.getSize() < 0
                        || data > cd || e.getCompressedSize() > cd - data)
                    throw Failure.invalid("ARCHIVE_LAYOUT", "invalid ZIP data extent");
                long localCompressed = u32(local, 18), localSize = u32(local, 22);
                if (localCompressed == 0xffffffffL || localSize == 0xffffffffL) {
                    long[] sizes = zip64Sizes(extras, localSize == 0xffffffffL, localCompressed == 0xffffffffL);
                    if (localSize == 0xffffffffL) localSize = sizes[0];
                    if (localCompressed == 0xffffffffL) localCompressed = sizes[1];
                }
                if ((flags & 8) == 0) {
                    if (u32(local, 14) != e.getCrc() || localCompressed != e.getCompressedSize()
                            || localSize != e.getSize())
                        throw Failure.invalid("ARCHIVE_LAYOUT", "ZIP local/central size or CRC mismatch");
                } else if ((u32(local, 14) != 0 && u32(local, 14) != e.getCrc())
                        || localCompressed != 0 && localCompressed != e.getCompressedSize()
                        || localSize != 0 && localSize != e.getSize())
                    throw Failure.invalid("ARCHIVE_LAYOUT", "invalid ZIP descriptor placeholders");
                previous = data + e.getCompressedSize();
                if ((flags & 8) != 0) {
                    byte[] first = read(file, previous, 4);
                    boolean wide = u32(local, 18) == 0xffffffffL || u32(local, 22) == 0xffffffffL
                            || hasExtra(extras, 1) || e.getCompressedSize() > 0xffffffffL || e.getSize() > 0xffffffffL;
                    byte[] unsigned = read(file, previous, wide ? 20 : 12);
                    boolean unsignedMatch = u32(unsigned, 0) == e.getCrc()
                            && (wide ? u64(unsigned, 4) : u32(unsigned, 4)) == e.getCompressedSize()
                            && (wide ? u64(unsigned, 12) : u32(unsigned, 8)) == e.getSize();
                    boolean signature = !unsignedMatch && u32(first, 0) == 0x08074b50L;
                    long descriptor = previous + (signature ? 4 : 0);
                    byte[] values = read(file, descriptor, wide ? 20 : 12);
                    if (u32(values, 0) != e.getCrc()
                            || (wide ? u64(values, 4) : u32(values, 4)) != e.getCompressedSize()
                            || (wide ? u64(values, 12) : u32(values, 8)) != e.getSize())
                        throw Failure.invalid("ARCHIVE_INTEGRITY", "ZIP data descriptor mismatch");
                    previous = descriptor + values.length;
                }
                if (previous > cd) throw Failure.invalid("ARCHIVE_LAYOUT", "ZIP entry overlaps directory");
            }
            if (strict && previous != cd)
                throw Failure.invalid("ARCHIVE_LAYOUT", "unaccounted bytes before ZIP central directory");
        }
        return metadata;
    }

    static long endOffset(java.nio.channels.SeekableByteChannel channel) throws IOException {
        return findEnd(new ChannelFile(channel));
    }

    private static long findEnd(ChannelFile file) throws IOException {
        long length = file.length();
        for (long candidate = length - 22; candidate >= Math.max(0, length - 65557); candidate--) {
            if (u32(read(file, candidate, 4), 0) != 0x06054b50L) continue;
            byte[] end = read(file, candidate, 22);
            if (candidate + 22 + u16(end, 20) > length) continue;
            if (candidate + 22 + u16(end, 20) != length) continue;
            long size = u32(end, 12), offset = u32(end, 16), count = u16(end, 10);
            long directoryEnd = candidate;
            if (candidate >= 20 && u32(read(file, candidate - 20, 4), 0) == 0x07064b50L) {
                byte[] locator = read(file, candidate - 20, 20);
                long z = u64(locator, 8);
                if (z > candidate - 76) continue;
                byte[] record = read(file, z, 56);
                if (u32(record, 0) != 0x06064b50L) continue;
                offset = u64(record, 48);
                size = u64(record, 40);
                count = u64(record, 32);
                directoryEnd = z;
            }
            if (offset > directoryEnd || size != directoryEnd - offset || count > size / 46) continue;
            long position = offset;
            boolean valid = true;
            for (long entry = 0; entry < count; entry++) {
                if (directoryEnd - position < 46) { valid = false; break; }
                byte[] record = read(file, position, 46);
                if (u32(record, 0) != 0x02014b50L) { valid = false; break; }
                position += 46L + u16(record, 28) + u16(record, 30) + u16(record, 32);
            }
            if (valid && position == directoryEnd) return candidate;
        }
        throw Failure.invalid("ARCHIVE_LAYOUT", "ZIP end record is missing or followed by data");
    }

    static void zip64Sector(int id, byte[] bytes, long size) {
        if (id != 0x0065)
            throw Failure.unsupported("UNSUPPORTED_FORMAT", "unsupported ZIP64 extensible-sector feature");
        if (size != 25 || bytes.length != 25 || u32(bytes, 0) != 0xf0f9f3e9L)
            throw Failure.invalid("ARCHIVE_LAYOUT", "invalid ZIP64 Z390 tape metadata");
    }

    private static long[] zip64Sizes(byte[] extra, boolean size, boolean compressed) {
        for (int p = 0; p + 4 <= extra.length;) {
            int id = u16(extra, p), len = u16(extra, p + 2);
            p += 4;
            if (p + len > extra.length) break;
            if (id == 1) {
                int need = (size ? 8 : 0) + (compressed ? 8 : 0);
                if (len < need) break;
                return new long[] {size ? u64(extra, p) : 0, compressed ? u64(extra, p + (size ? 8 : 0)) : 0};
            }
            p += len;
        }
        throw Failure.invalid("ARCHIVE_INTEGRITY", "missing ZIP64 size field");
    }

    static int u16(byte[] b, int p) {
        return (b[p] & 255) | (b[p + 1] & 255) << 8;
    }

    private static boolean hasUnicode(byte[] extras) {
        return hasExtra(extras, 0x7075);
    }

    static boolean hasExtra(byte[] extras, int id) {
        for (int p = 0; p + 4 <= extras.length;) {
            int length = u16(extras, p + 2);
            if (u16(extras, p) == id) return true;
            p += 4;
            if (length > extras.length - p) return false;
            p += length;
        }
        return false;
    }

    static long u32(byte[] b, int p) {
        return Integer.toUnsignedLong((b[p] & 255) | (b[p + 1] & 255) << 8
                | (b[p + 2] & 255) << 16 | (b[p + 3] & 255) << 24);
    }

    static long u64(byte[] b, int p) {
        long n = u32(b, p) | u32(b, p + 4) << 32;
        if (n < 0) throw Failure.invalid("ARCHIVE_INTEGRITY", "ZIP size exceeds supported representation");
        return n;
    }

    private static byte[] read(ChannelFile file, long offset, int length) throws IOException {
        if (offset < 0 || offset > file.length() || length > file.length() - offset)
            throw Failure.invalid("ARCHIVE_INTEGRITY", "truncated ZIP structure");
        byte[] value = new byte[length];
        file.seek(offset);
        file.readFully(value);
        return value;
    }

    private static final class ChannelFile implements AutoCloseable {
        final java.nio.channels.SeekableByteChannel channel;
        ChannelFile(java.nio.channels.SeekableByteChannel channel) { this.channel = channel; }
        long length() throws IOException { return channel.size(); }
        void seek(long offset) throws IOException { channel.position(offset); }
        void readFully(byte[] bytes) throws IOException {
            var buffer = java.nio.ByteBuffer.wrap(bytes);
            while (buffer.hasRemaining()) if (channel.read(buffer) < 0)
                throw Failure.invalid("ARCHIVE_INTEGRITY", "truncated ZIP structure");
        }
        @Override public void close() throws IOException { channel.close(); }
    }
}
