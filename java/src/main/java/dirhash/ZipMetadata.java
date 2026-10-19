package dirhash;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.CRC32;

final class ZipMetadata {
    record Unix(int mode, byte[] target, int externalMode, int creatorPlatform, boolean asiPresent) {}

    static Map<Integer, byte[]> fields(byte[] extras) {
        Map<Integer, byte[]> result = new HashMap<>();
        for (int p = 0; p < extras.length;) {
            if (extras.length - p < 4) throw Failure.invalid("ARCHIVE_INTEGRITY", "truncated ZIP extra field");
            int id = ZipPhysical.u16(extras, p), size = ZipPhysical.u16(extras, p + 2);
            p += 4;
            if (size > extras.length - p) throw Failure.invalid("ARCHIVE_INTEGRITY", "truncated ZIP extra field");
            byte[] value = Arrays.copyOfRange(extras, p, p + size);
            if (result.putIfAbsent(id, value) != null && java.util.Set.of(
                    1, 0x756e, 0x5455, 0xa, 0x7875, 0x5855, 0x7855, 0xd, 0x7075).contains(id))
                throw Failure.invalid("ARCHIVE_INTEGRITY", "duplicate ZIP semantic extra field");
            validate(id, value);
            p += size;
        }
        return result;
    }

    private static void validate(int id, byte[] data) {
        switch (id) {
            case 0x756e -> {
                if (data.length < 14) corrupt("short ASi Unix extra field");
                CRC32 crc = new CRC32();
                crc.update(data, 4, data.length - 4);
                if (crc.getValue() != ZipPhysical.u32(data, 0)) corrupt("ASi Unix extra-field CRC mismatch");
                int type = ZipPhysical.u16(data, 4) & 0170000;
                if (type == 0120000) {
                    if (ZipPhysical.u32(data, 6) != data.length - 14) corrupt("ASi symlink length mismatch");
                } else if (data.length != 14) corrupt("unexpected ASi Unix link data");
            }
            case 0x5455 -> {
                if (data.length < 1 || (data[0] & ~7) != 0 || (data.length - 1) % 4 != 0)
                    corrupt("invalid extended timestamp field");
                if ((data[0] & 1) != 0 && data.length < 5) corrupt("missing ZIP modification timestamp");
            }
            case 0x000a -> {
                if (data.length < 4) corrupt("short NTFS extra field");
                for (int p = 4; p < data.length;) {
                    if (data.length - p < 4) corrupt("truncated NTFS attribute");
                    int tag = ZipPhysical.u16(data, p), length = ZipPhysical.u16(data, p + 2);
                    p += 4;
                    if (length > data.length - p || tag == 1 && length != 24) corrupt("invalid NTFS attribute");
                    p += length;
                }
                ntfs(data);
            }
            case 0x7875 -> {
                if (data.length < 3 || data[0] != 1) corrupt("invalid Unix UID/GID extra field");
                int uid = data[1] & 255;
                if (uid < 1 || uid > 8 || 2 + uid >= data.length) corrupt("invalid Unix UID width");
                int gid = data[2 + uid] & 255;
                if (gid < 1 || gid > 8 || data.length != 3 + uid + gid) corrupt("invalid Unix GID width");
            }
            case 0x5855 -> {
                if (data.length != 8 && data.length != 12) corrupt("invalid old Info-ZIP Unix field");
            }
            case 0x7855 -> {
                if (data.length != 0 && data.length != 4) corrupt("invalid Info-ZIP Unix UID/GID field");
            }
            case 0x000d -> {
                if (data.length < 12) corrupt("short PKWARE Unix field");
            }
            default -> {}
        }
    }

    static Unix unix(int externalMode, int creatorPlatform, byte[] local, byte[] central) {
        Map<Integer, byte[]> l = fields(local), c = fields(central);
        validateLocal(l);
        byte[] asi = l.getOrDefault(0x756e, c.get(0x756e));
        int mode = externalMode;
        byte[] target = null;
        if (asi != null) {
            int represented = ZipPhysical.u16(asi, 4);
            int externalType = mode & 0170000, representedType = represented & 0170000;
            if (mode != 0 && ((mode & 07777) != (represented & 07777)
                    || externalType != 0 && representedType != 0 && externalType != representedType))
                throw Failure.invalid("ARCHIVE_LAYOUT", "ASi Unix mode conflicts with external attributes");
            mode = represented | (representedType == 0 ? externalType : 0);
            if ((mode & 0170000) == 0120000) target = Arrays.copyOfRange(asi, 14, asi.length);
        }
        byte[] pkware = l.getOrDefault(0x000d, c.get(0x000d));
        if (pkware != null && pkware.length > 12 && (mode & 0170000) == 0120000) {
            byte[] representedTarget = Arrays.copyOfRange(pkware, 12, pkware.length);
            if (target != null) same(target, representedTarget);
            target = representedTarget;
        }
        return new Unix(mode, target, externalMode, creatorPlatform, asi != null);
    }

    static String modeDescription(int mode) {
        return "unsupported ZIP Unix mode " + String.format(java.util.Locale.ROOT, "0%o", mode)
                + " (type " + String.format(java.util.Locale.ROOT, "0%o", mode & 0170000) + ")";
    }

    static boolean directoryModeCompatibility(Unix unix, String name, long size, boolean strict) {
        return !strict && unix.externalMode() == 0177777
                && (unix.creatorPlatform() == 3 || unix.creatorPlatform() == 19)
                && !unix.asiPresent() && name.endsWith("/") && size == 0;
    }

    static void reconcile(byte[] local, byte[] central) {
        Map<Integer, byte[]> l = fields(local), c = fields(central);
        validateLocal(l);
        for (var field : l.entrySet()) {
            byte[] a = field.getValue(), b = c.get(field.getKey());
            if (b == null) continue;
            switch (field.getKey()) {
                case 0x756e, 0x7075 -> same(a, b);
                case 0x000a -> {
                    Map<Integer, byte[]> x = ntfs(a), y = ntfs(b);
                    for (var attribute : x.entrySet())
                        if (y.containsKey(attribute.getKey())) same(attribute.getValue(), y.get(attribute.getKey()));
                }
                case 0x7875 -> {
                    java.math.BigInteger[] x = unixIds(a), y = unixIds(b);
                    if (!Arrays.equals(x, y))
                        throw Failure.invalid("ARCHIVE_LAYOUT", "conflicting ZIP Unix ownership fields");
                }
                case 0x5455 -> {
                    if ((a[0] & b[0] & 1) != 0) same(Arrays.copyOfRange(a, 1, 5), Arrays.copyOfRange(b, 1, 5));
                    // Central UT fields conventionally carry only mtime despite local flags.
                    if (b.length > 5) {
                        int flags = a[0] & b[0] & 7;
                        int x = 1, y = 1;
                        for (int bit = 1; bit <= 4; bit <<= 1) {
                            boolean ax = (a[0] & bit) != 0 && x + 4 <= a.length;
                            boolean by = (b[0] & bit) != 0 && y + 4 <= b.length;
                            if ((flags & bit) != 0 && ax && by)
                                same(Arrays.copyOfRange(a, x, x + 4), Arrays.copyOfRange(b, y, y + 4));
                            if (ax) x += 4;
                            if (by) y += 4;
                        }
                    }
                }
                case 0x5855 -> {
                    same(Arrays.copyOf(a, 8), Arrays.copyOf(b, 8));
                    if (a.length == 12 && b.length == 12) same(a, b);
                }
                case 0x7855 -> { if (a.length != 0 && b.length != 0) same(a, b); }
                case 0x000d -> {
                    same(Arrays.copyOf(a, 12), Arrays.copyOf(b, 12));
                    if (a.length > 12 && b.length > 12) same(a, b);
                }
                default -> {}
            }
        }
    }

    private static void same(byte[] a, byte[] b) {
        if (!Arrays.equals(a, b))
            throw Failure.invalid("ARCHIVE_LAYOUT", "conflicting local/central ZIP semantic extra fields");
    }

    private static void validateLocal(Map<Integer, byte[]> fields) {
        byte[] timestamp = fields.get(0x5455);
        if (timestamp != null && timestamp.length != 1 + 4 * Integer.bitCount(timestamp[0] & 7))
            corrupt("local ZIP extended timestamp flags disagree with values");
    }

    private static Map<Integer, byte[]> ntfs(byte[] value) {
        Map<Integer, byte[]> attributes = new HashMap<>();
        for (int p = 4; p < value.length;) {
            int id = ZipPhysical.u16(value, p), size = ZipPhysical.u16(value, p + 2);
            p += 4;
            byte[] previous = attributes.putIfAbsent(id, Arrays.copyOfRange(value, p, p + size));
            if (previous != null) corrupt("duplicate NTFS semantic attribute");
            p += size;
        }
        return attributes;
    }

    private static java.math.BigInteger[] unixIds(byte[] value) {
        int uidSize = value[1] & 255, gidSize = value[2 + uidSize] & 255;
        byte[] uid = new byte[uidSize], gid = new byte[gidSize];
        for (int i = 0; i < uidSize; i++) uid[uidSize - i - 1] = value[2 + i];
        for (int i = 0; i < gidSize; i++) gid[gidSize - i - 1] = value[3 + uidSize + i];
        return new java.math.BigInteger[] {new java.math.BigInteger(1, uid), new java.math.BigInteger(1, gid)};
    }

    private static void corrupt(String reason) {
        throw Failure.invalid("ARCHIVE_INTEGRITY", reason);
    }
}
