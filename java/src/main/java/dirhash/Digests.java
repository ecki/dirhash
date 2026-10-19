package dirhash;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.Blake2bDigest;
import org.bouncycastle.crypto.digests.Blake3Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;

final class Digests {
    static Digest create(String name) {
        return switch (name) {
            case "sha1" -> new SHA1Digest();
            case "sha256" -> new SHA256Digest();
            case "sha512" -> new SHA512Digest();
            case "blake2b-256" -> new Blake2bDigest(256);
            case "blake2b-512" -> new Blake2bDigest(512);
            case "blake3" -> new Blake3Digest();
            case "sha3-256" -> new SHA3Digest(256);
            case "sha3-512" -> new SHA3Digest(512);
            default -> throw new AssertionError(name);
        };
    }

    static void update(Digest digest, byte[] bytes) {
        digest.update(bytes, 0, bytes.length);
    }

    static byte[] finish(Digest digest) {
        byte[] bytes = new byte[digest.getDigestSize()];
        digest.doFinal(bytes, 0);
        return bytes;
    }

    static byte[] hash(String name, byte[] bytes) {
        Digest digest = create(name);
        update(digest, bytes);
        return finish(digest);
    }
}
