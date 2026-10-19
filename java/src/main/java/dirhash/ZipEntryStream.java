package dirhash;

import java.io.IOException;
import java.io.InputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;

final class ZipEntryStream extends InputStream {
    private final PipedInputStream input;
    private final FutureTask<Void> task;
    private boolean eof;

    static InputStream open(Model.Opener source, int selected) throws IOException {
        return new ZipEntryStream(source, selected);
    }

    private ZipEntryStream(Model.Opener source, int selected) throws IOException {
        input = new PipedInputStream(65536);
        PipedOutputStream output = new PipedOutputStream(input);
        task = new FutureTask<>(() -> {
            try (InputStream archive = source.open(); output) {
                boolean[] found = {false};
                new StreamingZip(archive, false, false, Map.of(),
                        (name, raw, size, unix, bytes, index) -> {
                            if (index == selected) {
                                found[0] = true;
                                bytes.transferTo(output);
                            }
                            Model.Node node = new Model.Node(name,
                                    name.endsWith("/") ? Model.Type.DIRECTORY : Model.Type.REGULAR);
                            node.storedName = name;
                            return node;
                        }, (node, name, unix) -> {}).read();
                if (!found[0]) throw Failure.invalid("INPUT_CHANGED", "ZIP entry disappeared during reread");
            }
            return null;
        });
        Thread.startVirtualThread(task);
    }

    @Override
    public int read(byte[] bytes, int offset, int length) throws IOException {
        if (length == 0) return 0;
        if (eof) return -1;
        int count = input.read(bytes, offset, length);
        if (count < 0) {
            eof = true;
            await();
        }
        return count;
    }

    @Override
    public int read() throws IOException {
        byte[] value = new byte[1];
        return read(value, 0, 1) < 0 ? -1 : value[0] & 255;
    }

    private void await() throws IOException {
        try {
            task.get();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("interrupted ZIP reread", e);
        } catch (ExecutionException e) {
            if (e.getCause() instanceof Failure failure) throw failure;
            if (e.getCause() instanceof IOException io) throw io;
            throw new IOException("ZIP reread failed", e.getCause());
        }
    }

    @Override
    public void close() throws IOException {
        try {
            input.close();
        } finally {
            if (!eof) task.cancel(true);
        }
    }
}
