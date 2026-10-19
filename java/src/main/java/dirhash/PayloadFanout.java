package dirhash;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;

final class PayloadFanout extends FilterInputStream {
    @FunctionalInterface interface Consumer { void read(InputStream input) throws IOException; }
    private record Branch(PipedOutputStream output, FutureTask<Void> task) {}
    private final List<Branch> branches = new ArrayList<>();
    private boolean closed;

    PayloadFanout(InputStream source, List<Consumer> consumers) throws IOException {
        super(source);
        for (Consumer consumer : consumers) {
            PipedInputStream input = new PipedInputStream(65536);
            PipedOutputStream output = new PipedOutputStream(input);
            FutureTask<Void> task = new FutureTask<>(() -> {
                try (input) { consumer.read(input); }
                return null;
            });
            branches.add(new Branch(output, task));
            Thread.ofVirtual().start(task);
        }
    }

    @Override public int read(byte[] bytes, int offset, int length) throws IOException {
        int count = in.read(bytes, offset, length);
        if (count > 0) try {
            for (Branch branch : branches) branch.output.write(bytes, offset, count);
        } catch (IOException failure) {
            close();
            throw failure;
        }
        return count;
    }

    @Override public int read() throws IOException {
        byte[] value = new byte[1];
        return read(value, 0, 1) < 0 ? -1 : value[0] & 255;
    }

    @Override public void close() throws IOException {
        if (closed) return;
        closed = true;
        IOException failure = null;
        RuntimeException invalid = null;
        for (Branch branch : branches) try { branch.output.close(); }
        catch (IOException e) { failure = e; }
        for (Branch branch : branches) try { branch.task.get(); }
        catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            branch.task.cancel(true);
            failure = new IOException("archive fanout interrupted", e);
        } catch (ExecutionException e) {
            if (e.getCause() instanceof RuntimeException runtime) invalid = runtime;
            else if (e.getCause() instanceof Error error) throw error;
            else failure = new IOException("archive fanout failed", e.getCause());
        }
        if (invalid != null) throw invalid;
        if (failure != null) throw failure;
    }
}
