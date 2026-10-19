package dirhash;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;

final class Bytes {
    static byte[] utf8(String value) {
        scalar(value);
        return value.getBytes(StandardCharsets.UTF_8);
    }

    static void scalar(String value) {
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (Character.isHighSurrogate(c)) {
                if (++i >= value.length() || !Character.isLowSurrogate(value.charAt(i)))
                    throw Failure.invalid("INVALID_ENCODING", "unpaired Unicode surrogate");
            } else if (Character.isLowSurrogate(c))
                throw Failure.invalid("INVALID_ENCODING", "unpaired Unicode surrogate");
        }
    }

    static String decode(byte[] value) {
        try {
            return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(value)).toString();
        } catch (CharacterCodingException e) {
            throw Failure.invalid("INVALID_ENCODING", "invalid UTF-8");
        }
    }

    static int compare(String a, String b) {
        return Arrays.compareUnsigned(utf8(a), utf8(b));
    }

    static String hex(byte[] value) {
        return HexFormat.of().formatHex(value);
    }

    static String json(String value) {
        return escapedPath(value, true);
    }

    static String textPath(String value) {
        return escapedPath(value, false);
    }

    private static String escapedPath(String value, boolean quoted) {
        scalar(value);
        StringBuilder b = new StringBuilder();
        if (quoted) b.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"', '\\' -> {
                    if (quoted) b.append('\\');
                    b.append(c);
                }
                case '\b' -> b.append("\\b");
                case '\f' -> b.append("\\f");
                case '\n' -> b.append("\\n");
                case '\r' -> b.append("\\r");
                case '\t' -> b.append("\\t");
                default -> {
                    if (c < 32) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
                }
            }
        }
        if (quoted) b.append('"');
        return b.toString();
    }

    static String diagnostic(String value) {
        StringBuilder b = new StringBuilder();
        value.codePoints().forEach(c -> {
            if (Character.isISOControl(c) || Character.getType(c) == Character.FORMAT || c == 0x2028 || c == 0x2029)
                b.append(String.format("\\u%04x", c));
            else b.appendCodePoint(c);
        });
        return b.toString();
    }
}
