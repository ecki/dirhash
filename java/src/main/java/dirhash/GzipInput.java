package dirhash;

import java.io.IOException;
import java.io.InputStream;
import java.io.PushbackInputStream;
import java.util.zip.CRC32;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

final class GzipInput extends InputStream {
    private final PushbackInputStream source;
    private final boolean strict;
    private final CRC32 payloadCrc = new CRC32();
    private Member member;
    private long count;
    private int members;
    private boolean ended;

    GzipInput(InputStream source, boolean strict) {
        this.source = new PushbackInputStream(source, 65536);
        this.strict = strict;
    }

    private int octet() throws IOException {
        int value = source.read();
        if (value < 0) throw Failure.invalid("ARCHIVE_INTEGRITY", "truncated gzip framing");
        return value;
    }

    private long little32() throws IOException {
        return (long) octet() | (long) octet() << 8 | (long) octet() << 16 | (long) octet() << 24;
    }

    private static final class Header {
        final CRC32 crc = new CRC32();
        int size;
    }

    private int headerByte(Header header) throws IOException {
        if (++header.size > 16 * 1024 * 1024)
            throw Failure.invalid("LIMIT_EXCEEDED", "gzip header exceeds metadata representation limit");
        int value = octet();
        header.crc.update(value);
        return value;
    }

    private boolean next() throws IOException {
        int first = source.read();
        if (first < 0) {
            if (members == 0) throw Failure.invalid("ARCHIVE_INTEGRITY", "missing gzip member");
            ended = true;
            return false;
        }
        if (strict && members != 0)
            throw Failure.invalid("ARCHIVE_LAYOUT", "strict gzip permits one member and no trailing bytes");
        Header header = new Header();
        header.crc.update(first);
        header.size = 1;
        if (first != 31 || headerByte(header) != 139 || headerByte(header) != 8)
            throw Failure.invalid("ARCHIVE_INTEGRITY", "invalid gzip member header");
        int flags = headerByte(header);
        if ((flags & 0xe0) != 0)
            throw Failure.invalid("ARCHIVE_INTEGRITY", "reserved gzip header flags");
        for (int i = 0; i < 6; i++) headerByte(header);
        if ((flags & 4) != 0) {
            int remaining = headerByte(header) | headerByte(header) << 8;
            while (remaining > 0) {
                if (remaining < 4)
                    throw Failure.invalid("ARCHIVE_INTEGRITY", "truncated gzip extra subfield");
                headerByte(header);
                headerByte(header);
                int length = headerByte(header) | headerByte(header) << 8;
                if (length > remaining - 4)
                    throw Failure.invalid("ARCHIVE_INTEGRITY", "gzip extra subfield exceeds header extent");
                for (int i = 0; i < length; i++) headerByte(header);
                remaining -= 4 + length;
            }
        }
        if ((flags & 8) != 0) while (headerByte(header) != 0) {}
        if ((flags & 16) != 0) while (headerByte(header) != 0) {}
        if ((flags & 2) != 0 && (octet() | octet() << 8) != (header.crc.getValue() & 0xffff))
            throw Failure.invalid("ARCHIVE_INTEGRITY", "gzip header CRC mismatch");
        members++;
        payloadCrc.reset();
        count = 0;
        member = new Member(source);
        return true;
    }

    @Override public int read(byte[] bytes, int offset, int length) throws IOException {
        if (length == 0) return 0;
        while (!ended) {
            if (member == null && !next()) return -1;
            int n = member.read(bytes, offset, length);
            if (n > 0) {
                payloadCrc.update(bytes, offset, n);
                count += n;
                return n;
            }
            member.finish();
            member = null;
            if (little32() != payloadCrc.getValue() || little32() != (count & 0xffffffffL))
                throw Failure.invalid("ARCHIVE_INTEGRITY", "gzip payload CRC or size mismatch");
        }
        return -1;
    }

    @Override public int read() throws IOException {
        byte[] value = new byte[1];
        return read(value, 0, 1) < 0 ? -1 : value[0] & 255;
    }

    @Override public void close() throws IOException {
        try { if (member != null) member.infEnd(); } finally { source.close(); }
    }

    private static final class Member extends InflaterInputStream {
        private final PushbackInputStream source;
        Member(PushbackInputStream source) {
            super(source, new Inflater(true), 65536);
            this.source = source;
        }
        void finish() throws IOException {
            try {
                if (!inf.finished())
                    throw Failure.invalid("ARCHIVE_INTEGRITY", "gzip DEFLATE payload did not terminate");
                int remaining = inf.getRemaining();
                if (remaining != 0) source.unread(buf, len - remaining, remaining);
            } finally { inf.end(); }
        }
        void infEnd() { inf.end(); }
    }
}
