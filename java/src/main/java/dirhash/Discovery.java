package dirhash;

import java.io.IOException;
import java.io.InputStream;
import java.io.PushbackInputStream;
import java.io.ByteArrayInputStream;
import java.io.SequenceInputStream;
import java.util.Locale;
import java.util.zip.GZIPInputStream;

final class Discovery {
    private static final int MAX_GZIP_PEEK_BYTES = 65_536;
    record Probe(InputStream stream, String type) {}

    static Probe probe(InputStream input, String name, boolean required) throws IOException {
        PushbackInputStream in = new PushbackInputStream(input, 131100);
        byte[] header = in.readNBytes(512);
        String type = null;
        boolean gzipProbed = false;
        if (header.length == 512 && !allZero(header) && validTar(header)) {
            type = "tar";
        } else if (plausibleZip(header)) {
            type = "zip";
        } else if (header.length >= 10 && (header[0] & 255) == 31 && (header[1] & 255) == 139
                && header[2] == 8 && (header[3] & 0xe0) == 0) {
            in.unread(header);
            GzipProbe probe = gzipTar(in);
            if (probe.type()) type = "tar.gz";
            in = new PushbackInputStream(probe.replay(), 131100);
            gzipProbed = true;
        } else if (header.length == 512 && allZero(header)) {
            header = extend(in, header, 1024);
            if (header.length == 1024 && allZero(header)) type = "tar";
        }
        if (!gzipProbed) in.unread(header);
        String suffix = suffix(name);
        if (suffix != null && !suffix.equals(type))
            throw Failure.invalid("ARCHIVE_INTEGRITY", "archive suffix does not match supported content");
        if (required && type == null)
            throw Failure.unsupported("UNSUPPORTED_FORMAT", "input is not a supported archive");
        return new Probe(in, type);
    }

    private record GzipProbe(boolean type, InputStream replay) {}

    private static GzipProbe gzipTar(InputStream input) throws IOException {
        PrefixCapture captured = new PrefixCapture(input, MAX_GZIP_PEEK_BYTES);
        boolean valid = false;
        try {
            GZIPInputStream decoded = new GZIPInputStream(captured, 8192);
            byte[] header = decoded.readNBytes(512);
            if (header.length == 512) {
                if (allZero(header)) {
                    byte[] end = decoded.readNBytes(512);
                    valid = end.length == 512 && allZero(end);
                }
                else valid = validTar(header);
            }
        } catch (IOException malformedGzip) {
            if (captured.sourceFailure != null) throw captured.sourceFailure;
        }
        return new GzipProbe(valid, new SequenceInputStream(
                new ByteArrayInputStream(captured.captured()), input));
    }

    private static final class PrefixCapture extends InputStream {
        private final InputStream source;
        private final int limit;
        private final java.io.ByteArrayOutputStream bytes = new java.io.ByteArrayOutputStream();
        private IOException sourceFailure;

        PrefixCapture(InputStream source, int limit) {
            this.source = source;
            this.limit = limit;
        }

        byte[] captured() { return bytes.toByteArray(); }

        @Override public int read() throws IOException {
            if (bytes.size() == limit) return -1;
            int value;
            try { value = source.read(); }
            catch (IOException failure) { sourceFailure = failure; throw failure; }
            if (value >= 0) bytes.write(value);
            return value;
        }

        @Override public int read(byte[] buffer, int offset, int length) throws IOException {
            if (length == 0) return 0;
            int remaining = limit - bytes.size();
            if (remaining == 0) return -1;
            int count;
            try { count = source.read(buffer, offset, Math.min(length, remaining)); }
            catch (IOException failure) { sourceFailure = failure; throw failure; }
            if (count > 0) bytes.write(buffer, offset, count);
            return count;
        }
    }

    private static boolean plausibleZip(byte[] header) {
        if (header.length >= 30 && ZipPhysical.u32(header, 0) == 0x04034b50L)
            return ZipPhysical.u16(header, 4) >= 10 && ZipPhysical.u16(header, 26) != 0;
        if (header.length >= 22 && ZipPhysical.u32(header, 0) == 0x06054b50L)
            return ZipPhysical.u16(header, 4) == 0 && ZipPhysical.u16(header, 6) == 0
                    && ZipPhysical.u16(header, 8) == 0 && ZipPhysical.u16(header, 10) == 0
                    && ZipPhysical.u32(header, 12) == 0 && ZipPhysical.u32(header, 16) == 0;
        return header.length >= 56 && ZipPhysical.u32(header, 0) == 0x06064b50L
                && ZipPhysical.u32(header, 8) == 0 && ZipPhysical.u32(header, 4) >= 44
                && ZipPhysical.u32(header, 24) == 0 && ZipPhysical.u32(header, 28) == 0
                && ZipPhysical.u32(header, 32) == 0 && ZipPhysical.u32(header, 36) == 0
                && ZipPhysical.u32(header, 40) == 0 && ZipPhysical.u32(header, 44) == 0
                && ZipPhysical.u32(header, 48) == 0 && ZipPhysical.u32(header, 52) == 0;
    }

    private static boolean allZero(byte[] bytes) {
        for (byte b : bytes) if (b != 0) return false;
        return true;
    }

    private static byte[] extend(InputStream in, byte[] prefix, int target) throws IOException {
        byte[] rest = in.readNBytes(target - prefix.length);
        byte[] joined = java.util.Arrays.copyOf(prefix, prefix.length + rest.length);
        System.arraycopy(rest, 0, joined, prefix.length, rest.length);
        return joined;
    }

    private static boolean validTar(byte[] header) {
        boolean zero = true;
        for (byte b : header) zero &= b == 0;
        if (zero) return true;
        long expected = 0;
        for (int i = 148; i < 156; i++) {
            int c = header[i] & 255;
            if (c == 0 || c == 32) continue;
            if (c < '0' || c > '7') return false;
            expected = expected * 8 + c - '0';
        }
        long sum = 0;
        for (int i = 0; i < header.length; i++)
            sum += i >= 148 && i < 156 ? 32 : header[i] & 255;
        return expected == sum;
    }

    static String suffix(String name) {
        String n = name.toLowerCase(Locale.ROOT);
        if (n.endsWith(".zip") || n.endsWith(".jar") || n.endsWith(".war") || n.endsWith(".ear"))
            return "zip";
        if (n.endsWith(".tar.gz") || n.endsWith(".tgz")) return "tar.gz";
        if (n.endsWith(".tar")) return "tar";
        return null;
    }
}
