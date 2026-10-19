package dirhash;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

final class FilesInput {
    record Stamp(Object key, long size, java.nio.file.attribute.FileTime modified,
                 java.nio.file.attribute.FileTime created, Object changed, int mode,
                 boolean directory, boolean file, boolean link) {}

    static Stamp stamp(Path path) throws IOException {
        BasicFileAttributes a = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        Object changed = null;
        try {
            changed = Files.getAttribute(path, "unix:ctime", LinkOption.NOFOLLOW_LINKS);
        } catch (UnsupportedOperationException | IllegalArgumentException ignored) {}
        return new Stamp(a.fileKey(), a.size(), a.lastModifiedTime(), a.creationTime(),
                changed, mode(path),
                a.isDirectory(), a.isRegularFile(), a.isSymbolicLink());
    }

    static void verify(Path path, Stamp original) throws IOException {
        try {
            if (!stamp(path).equals(original))
                throw Failure.invalid("INPUT_CHANGED", "filesystem object changed during hashing").at(path.toString());
        } catch (java.nio.file.NoSuchFileException | java.nio.file.NotDirectoryException e) {
            throw Failure.invalid("INPUT_CHANGED", "filesystem object disappeared during hashing").at(path.toString());
        }
    }

    static List<String> inventory(Path path) throws IOException {
        List<String> names = new ArrayList<>();
        try (var stream = Files.newDirectoryStream(path)) {
            for (Path child : stream) {
                Path name = child.getFileName();
                if (!name.equals(Path.of(name.toString())))
                    throw Failure.invalid("INVALID_ENCODING", "filesystem name cannot be exposed losslessly");
                names.add(name.toString());
            }
        }
        names.sort(Bytes::compare);
        return names;
    }

    static int mode(Path path) throws IOException {
        try {
            Set<PosixFilePermission> p = Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS);
            return (p.contains(PosixFilePermission.OWNER_EXECUTE) ? 0100 : 0)
                    | (p.contains(PosixFilePermission.GROUP_EXECUTE) ? 0010 : 0)
                    | (p.contains(PosixFilePermission.OTHERS_EXECUTE) ? 0001 : 0);
        } catch (UnsupportedOperationException e) {
            return 0;
        }
    }

    static Model.Opener opener(Path path, Stamp stamp) {
        return () -> {
            verify(path, stamp);
            return new FilterInputStream(Files.newInputStream(path)) {
                @Override
                public void close() throws IOException {
                    try { super.close(); } finally { verify(path, stamp); }
                }
            };
        };
    }

    static Model.SeekableOpener seekable(Path path, Stamp stamp) {
        return () -> {
            verify(path, stamp);
            var channel = Files.newByteChannel(path);
            return new java.nio.channels.SeekableByteChannel() {
                @Override public int read(java.nio.ByteBuffer bytes) throws IOException { return channel.read(bytes); }
                @Override public int write(java.nio.ByteBuffer bytes) { throw new java.nio.channels.NonWritableChannelException(); }
                @Override public long position() throws IOException { return channel.position(); }
                @Override public java.nio.channels.SeekableByteChannel position(long offset) throws IOException {
                    channel.position(offset);
                    return this;
                }
                @Override public long size() throws IOException { return channel.size(); }
                @Override public java.nio.channels.SeekableByteChannel truncate(long size) {
                    throw new java.nio.channels.NonWritableChannelException();
                }
                @Override public boolean isOpen() { return channel.isOpen(); }
                @Override public void close() throws IOException {
                    try { channel.close(); } finally { verify(path, stamp); }
                }
            };
        };
    }
}
