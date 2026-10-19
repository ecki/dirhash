package dirhash;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.CRC32;
import org.bouncycastle.crypto.Digest;

final class Payload extends FilterInputStream {
    final Map<String, Digest> raw = new HashMap<>();
    final Map<String, Digest> blob = new HashMap<>();
    final CRC32 crc = new CRC32();
    final Engine engine;
    final boolean expanded;
    long count;

    Payload(InputStream in, Engine engine, long size, boolean expanded, boolean report) {
        super(in);
        this.engine = engine;
        this.expanded = expanded;
        if (!report) return;
        for (Options.Selection s : engine.options.selections) {
            if (s.scheme().equals("h1") || s.scheme().equals("h1-go"))
                raw.computeIfAbsent(s.digest(), Digests::create);
            if (s.scheme().equals("gittree") || s.scheme().equals("swhid")) {
                if (size < 0) throw Failure.unsupported("UNSUPPORTED_STREAMING",
                        "blob length is unavailable before streamed payload");
                blob.computeIfAbsent(s.digest(), name -> {
                    Digest d = Digests.create(name);
                    Digests.update(d, Bytes.utf8("blob " + size + "\0"));
                    return d;
                });
            }
        }
    }

    @Override
    public int read(byte[] bytes, int offset, int length) throws IOException {
        int n = in.read(bytes, offset, length);
        if (n > 0) {
            count += n;
            if (expanded) engine.expanded(n);
            crc.update(bytes, offset, n);
            raw.values().forEach(d -> d.update(bytes, offset, n));
            blob.values().forEach(d -> d.update(bytes, offset, n));
        }
        return n;
    }

    @Override
    public int read() throws IOException {
        byte[] b = new byte[1];
        return read(b, 0, 1) < 0 ? -1 : b[0] & 255;
    }

    @Override
    public long skip(long amount) throws IOException {
        byte[] buffer = new byte[8192];
        long count = 0;
        while (count < amount) {
            int n = read(buffer, 0, (int) Math.min(buffer.length, amount - count));
            if (n < 0) break;
            count += n;
        }
        return count;
    }

    @Override
    public void close() {}

    void finish(Model.Node node, boolean go) {
        raw.forEach((name, d) -> (go ? node.go : node.raw).put(name, Digests.finish(d)));
        blob.forEach((name, d) -> node.blobs.put(name, Digests.finish(d)));
    }
}
