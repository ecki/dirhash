package dirhash;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;

final class Download {
    private static final java.util.concurrent.ConcurrentHashMap<Path, Thread> CLEANUP =
            new java.util.concurrent.ConcurrentHashMap<>();

    static Path fetch(String source, long maximum) {
        Path file = null;
        try {
            URI uri = URI.create(source);
            validate(uri);
            for (int redirect = 0;; redirect++) {
                HttpURLConnection connection = (HttpURLConnection) uri.toURL().openConnection();
                connection.setInstanceFollowRedirects(false);
                connection.setConnectTimeout(30000);
                connection.setReadTimeout(30000);
                connection.setRequestProperty("Accept-Encoding", "identity");
                try {
                    int status = connection.getResponseCode();
                    if (status == 301 || status == 302 || status == 303 || status == 307 || status == 308) {
                        if (redirect == 5) throw new IOException("too many redirects");
                        String location = connection.getHeaderField("Location");
                        if (location == null) throw new IOException("redirect without Location");
                        URI next = uri.resolve(location);
                        validate(next);
                        if (uri.getScheme().equalsIgnoreCase("https") && next.getScheme().equalsIgnoreCase("http"))
                            throw new IOException("HTTPS downgrade redirect");
                        uri = next;
                        continue;
                    }
                    if (status < 200 || status >= 300) throw new IOException("unsuccessful HTTP response");
                    String encoding = connection.getHeaderField("Content-Encoding");
                    if (encoding != null && !encoding.isBlank() && !encoding.equalsIgnoreCase("identity"))
                        throw new IOException("non-identity HTTP content coding");
                    long declared = connection.getContentLengthLong();
                    if (declared > maximum) throw Failure.invalid("LIMIT_EXCEEDED", "download byte limit exceeded");
                    file = createPrivateTemp(Path.of(System.getProperty("java.io.tmpdir")).toRealPath(),
                            "dirhash-download-");
                    long count = 0;
                    try (InputStream in = connection.getInputStream(); OutputStream out = Files.newOutputStream(file)) {
                        byte[] buffer = new byte[65536];
                        int n;
                        while ((n = in.read(buffer)) >= 0) {
                            if (n == 0) continue;
                            if (n > maximum - count)
                                throw Failure.invalid("LIMIT_EXCEEDED", "download byte limit exceeded");
                            count += n;
                            out.write(buffer, 0, n);
                        }
                    }
                    if (declared >= 0 && declared != count) throw new IOException("truncated HTTP representation");
                    return file;
                } finally {
                    connection.disconnect();
                }
            }
        } catch (Failure e) {
            cleanup(file);
            throw e;
        } catch (IOException | IllegalArgumentException e) {
            cleanup(file);
            throw new Failure(4, "NETWORK_ERROR", "HTTP archive transfer failed");
        }
    }

    private static void validate(URI uri) throws IOException {
        if (uri.getUserInfo() != null || uri.getHost() == null || uri.getScheme() == null
                || !(uri.getScheme().equalsIgnoreCase("http") || uri.getScheme().equalsIgnoreCase("https")))
            throw new IOException("unsupported URL or URL credentials");
    }

    static Path createPrivateTemp(Path directory, String prefix) throws IOException {
        var store = Files.getFileStore(directory);
        Path file;
        if (store.supportsFileAttributeView("posix")) {
            file = Files.createTempFile(directory, prefix, ".archive",
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        } else if (store.supportsFileAttributeView("acl")) {
            var owner = directory.getFileSystem().getUserPrincipalLookupService()
                    .lookupPrincipalByName(System.getProperty("user.name"));
            var acl = java.nio.file.attribute.AclEntry.newBuilder()
                    .setType(java.nio.file.attribute.AclEntryType.ALLOW).setPrincipal(owner)
                    .setPermissions(java.util.EnumSet.allOf(java.nio.file.attribute.AclEntryPermission.class))
                    .build();
            java.nio.file.attribute.FileAttribute<java.util.List<java.nio.file.attribute.AclEntry>> attribute =
                    new java.nio.file.attribute.FileAttribute<>() {
                        @Override public String name() { return "acl:acl"; }
                        @Override public java.util.List<java.nio.file.attribute.AclEntry> value() {
                            return java.util.List.of(acl);
                        }
                    };
            file = Files.createTempFile(directory, prefix, ".archive", attribute);
        } else throw new IOException("filesystem cannot create a private temporary archive");
        return track(file);
    }

    private static Path track(Path file) throws IOException {
        Thread hook = new Thread(() -> {
            try { Files.deleteIfExists(file); } catch (IOException ignored) {}
        }, "dirhash-private-file-cleanup");
        try {
            Runtime.getRuntime().addShutdownHook(hook);
            CLEANUP.put(file, hook);
            return file;
        } catch (RuntimeException failure) {
            Files.deleteIfExists(file);
            throw failure;
        }
    }

    static void delete(Path file) throws IOException {
        if (file == null) return;
        try {
            Files.deleteIfExists(file);
        } finally {
            Thread hook = CLEANUP.remove(file);
            if (hook != null) try {
                Runtime.getRuntime().removeShutdownHook(hook);
            } catch (IllegalStateException ignored) {}
        }
    }

    private static void cleanup(Path file) {
        try { delete(file); } catch (IOException ignored) {}
    }
}
