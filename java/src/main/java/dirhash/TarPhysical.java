package dirhash;

import java.io.IOException;
import java.io.InputStream;
import org.apache.commons.compress.archivers.tar.TarUtils;

final class TarPhysical extends InputStream {
    private final InputStream in;
    private final Engine engine;
    private final boolean strict;
    private final byte[] block = new byte[512];
    private int offset = 512;
    private int available;
    private int payloadEnd;
    private long remaining;
    private int zeroHeaders;
    private boolean ended;
    private boolean sparseExtension;
    private boolean metadata;
    private long headers;
    private java.nio.charset.CharsetDecoder decoder;
    private java.io.ByteArrayOutputStream control;
    private int controlType;
    private Long globalSize;
    private Long localSize;
    private String globalName;
    private String localName;
    private boolean localNamePresent;
    private boolean longName;
    private long position;

    long position() {
        return position;
    }

    long payloadRemaining() {
        return remaining + Math.max(0, payloadEnd - offset);
    }

    TarPhysical(InputStream in, Engine engine) {
        this.in = in;
        this.engine = engine;
        strict = engine.options.strict;
    }

    private boolean block() throws IOException {
        int n = in.readNBytes(block, 0, 512);
        if (n == 0) {
            if ((strict && (!ended || remaining != 0)) || !ended && headers == 0)
                throw Failure.invalid("ARCHIVE_INTEGRITY", "TAR requires two complete zero end blocks");
            return false;
        }
        if (n != 512)
            throw Failure.invalid("ARCHIVE_INTEGRITY", "truncated TAR record");
        boolean zero = true;
        for (byte b : block) zero &= b == 0;
        payloadEnd = 0;
        if (ended) {
            if (strict && !zero) throw Failure.invalid("ARCHIVE_LAYOUT", "nonzero data after TAR end");
        } else if (sparseExtension) {
            engine.entry();
            sparseExtension = block[504] != 0;
        } else if (remaining > 0) {
            int logical = (int) Math.min(remaining, 512);
            payloadEnd = logical;
            if (metadata) validateMetadata(block, logical, remaining <= 512);
            if (strict) for (int i = logical; i < 512; i++)
                if (block[i] != 0) throw Failure.invalid("ARCHIVE_LAYOUT", "nonzero TAR entry padding");
            remaining -= logical;
        } else if (zero) {
            if (++zeroHeaders == 2) ended = true;
        } else {
            if (zeroHeaders != 0) throw Failure.invalid("ARCHIVE_INTEGRITY", "incomplete TAR end marker");
            if (!TarUtils.verifyCheckSum(block))
                throw Failure.invalid("ARCHIVE_INTEGRITY", "invalid TAR header checksum");
            String rawName = string(block, 0, 100);
            headers++;
            string(block, 157, 100);
            if (block[257] == 'u' && block[258] == 's' && block[262] == 0) {
                String prefix = string(block, 345, 155);
                if (!prefix.isEmpty()) rawName = prefix + "/" + rawName;
            }
            remaining = TarUtils.parseOctalOrBinary(block, 124, 12);
            if (remaining < 0) throw Failure.invalid("ARCHIVE_INTEGRITY", "negative TAR size");
            int type = block[156] & 255;
            metadata = type == 'x' || type == 'g' || type == 'L' || type == 'K';
            if (metadata) {
                engine.entry();
                decoder = java.nio.charset.StandardCharsets.UTF_8.newDecoder()
                        .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                        .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT);
                carry = new byte[0];
                control = new java.io.ByteArrayOutputStream();
                controlType = type;
            } else {
                String effectiveName = localNamePresent ? localName : globalName;
                if (effectiveName == null && !longName)
                    Names.path(rawName, type == '5' || rawName.endsWith("/"), engine.options);
                localName = null;
                localNamePresent = false;
                longName = false;
                if (localSize != null || globalSize != null)
                    remaining = localSize != null ? localSize : globalSize;
                localSize = null;
            }
            sparseExtension = type == 'S' && block[482] != 0;
        }
        offset = 0;
        available = 512;
        return true;
    }

    private byte[] carry = new byte[0];

    private void validateMetadata(byte[] value, int size, boolean last) {
        if (control.size() > 16 * 1024 * 1024 - size)
            throw Failure.invalid("LIMIT_EXCEEDED", "TAR control record exceeds metadata representation limit");
        control.write(value, 0, size);
        byte[] bytes = new byte[carry.length + size];
        System.arraycopy(carry, 0, bytes, 0, carry.length);
        System.arraycopy(value, 0, bytes, carry.length, size);
        java.nio.ByteBuffer input = java.nio.ByteBuffer.wrap(bytes);
        java.nio.CharBuffer output = java.nio.CharBuffer.allocate(1024);
        var result = decoder.decode(input, output, last);
        if (result.isError()) throw Failure.invalid("INVALID_ENCODING", "invalid UTF-8 TAR metadata");
        carry = new byte[input.remaining()];
        input.get(carry);
        if (last && carry.length != 0)
            throw Failure.invalid("INVALID_ENCODING", "incomplete UTF-8 TAR metadata");
        if (last) control();
    }

    private void control() {
        byte[] bytes = control.toByteArray();
        if (controlType == 'L') {
            int end = bytes.length;
            while (end > 0 && bytes[end - 1] == 0) end--;
            Names.path(Bytes.decode(java.util.Arrays.copyOf(bytes, end)), true, engine.options);
            longName = true;
        } else if (controlType == 'x' || controlType == 'g') {
            for (int position = 0; position < bytes.length;) {
                int space = position;
                while (space < bytes.length && bytes[space] != ' ') space++;
                if (space == bytes.length) throw Failure.invalid("ARCHIVE_INTEGRITY", "invalid PAX record length");
                int length;
                try {
                    String text = new String(bytes, position, space - position, java.nio.charset.StandardCharsets.US_ASCII);
                    if (!text.matches("[0-9]+")) throw new NumberFormatException();
                    length = Integer.parseInt(text);
                } catch (NumberFormatException e) {
                    throw Failure.invalid("ARCHIVE_INTEGRITY", "invalid PAX record length");
                }
                if (length <= space - position + 2 || length > bytes.length - position || bytes[position + length - 1] != '\n')
                    throw Failure.invalid("ARCHIVE_INTEGRITY", "invalid PAX record extent");
                String item = Bytes.decode(java.util.Arrays.copyOfRange(bytes, space + 1, position + length - 1));
                int equals = item.indexOf('=');
                if (equals < 1) throw Failure.invalid("ARCHIVE_INTEGRITY", "invalid PAX key/value");
                String key = item.substring(0, equals), val = item.substring(equals + 1);
                if (key.equals("GNU.sparse.size") || key.equals("GNU.sparse.realsize")) {
                    try {
                        if (!val.matches("[0-9]+")) throw new NumberFormatException();
                        long size = Long.parseLong(val);
                        if (size > Integer.MAX_VALUE) throw Failure.invalid("LIMIT_EXCEEDED",
                                "PAX sparse real size exceeds decoder metadata representation");
                    } catch (NumberFormatException e) {
                        throw Failure.invalid("ARCHIVE_INTEGRITY", "invalid PAX sparse real size");
                    }
                }
                if (!val.isEmpty() && (key.equals("path") || key.equals("GNU.sparse.name")))
                    Names.path(val, true, engine.options);
                if (key.equals("path") || key.equals("GNU.sparse.name")) {
                    if (controlType == 'g') globalName = val.isEmpty() ? null : val;
                    else {
                        localNamePresent = true;
                        localName = val.isEmpty() ? null : val;
                    }
                }
                if (key.equals("size")) {
                    Long parsed = null;
                    if (!val.isEmpty()) try {
                        if (!val.matches("[0-9]+")) throw new NumberFormatException();
                        parsed = Long.parseLong(val);
                    } catch (NumberFormatException e) {
                        throw Failure.invalid("ARCHIVE_INTEGRITY", "invalid PAX payload size");
                    }
                    if (controlType == 'g') globalSize = parsed;
                    else localSize = parsed;
                }
                position += length;
            }
        }
    }

    private static String string(byte[] bytes, int start, int length) {
        int end = start;
        while (end < start + length && bytes[end] != 0) end++;
        return Bytes.decode(java.util.Arrays.copyOfRange(bytes, start, end));
    }

    @Override
    public int read(byte[] bytes, int start, int length) throws IOException {
        if (length == 0) return 0;
        if (offset >= available && !block()) return -1;
        int n = Math.min(length, available - offset);
        System.arraycopy(block, offset, bytes, start, n);
        offset += n;
        position += n;
        return n;
    }

    @Override
    public int read() throws IOException {
        byte[] b = new byte[1];
        return read(b, 0, 1) < 0 ? -1 : b[0] & 255;
    }

    @Override
    public void close() throws IOException {
        in.close();
    }
}
