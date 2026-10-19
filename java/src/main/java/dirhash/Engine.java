package dirhash;

import java.io.ByteArrayInputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipFile;

final class Engine {
    final Options options;
    private static final class Budget {
        long entries;
        long expanded;
        final List<ArchiveSpool> spools = new ArrayList<>();
        final ArchiveSpool.MemoryBudget spoolMemory = new ArchiveSpool.MemoryBudget();
        final Map<String, String> warnings = new LinkedHashMap<>();
    }
    private final Budget budget;
    int zipReaderOpens;
    private boolean directoryInput;
    String location;
    private final List<RunnableIO> verifications = new ArrayList<>();

    @FunctionalInterface
    private interface RunnableIO { void run() throws IOException; }

    Engine(Options options) {
        this(options, new Budget());
    }

    private Engine(Options options, Budget budget) {
        this.options = options;
        this.budget = budget;
        location = options.input;
    }

    void entry() {
        synchronized (budget) {
            if (budget.entries == options.maxEntries) throw Failure.invalid("LIMIT_EXCEEDED", "entry limit exceeded");
            budget.entries++;
        }
    }

    void expanded(long n) {
        synchronized (budget) {
            if (n > options.maxExpanded - budget.expanded)
                throw Failure.invalid("LIMIT_EXCEEDED", "expanded archive byte limit exceeded");
            budget.expanded += n;
        }
    }

    private void warnZipDirectory(Model.Root root, String name, int mode) {
        String path = display(root.locations, name);
        String message = "WARN_ZIP_DIRECTORY_MODE: " + Bytes.diagnostic(path)
                + ": accepted malformed empty ZIP directory with Unix mode "
                + String.format(java.util.Locale.ROOT, "0%o", mode) + "\n";
        synchronized (budget) { budget.warnings.putIfAbsent(path, message); }
    }

    List<String> warnings() {
        synchronized (budget) { return List.copyOf(budget.warnings.values()); }
    }

    private String zipLogicalName(Model.Root root, String name, Model.Type type, long size) {
        if (options.strict || type != Model.Type.DIRECTORY || size != 0 || !name.endsWith("//"))
            return name;
        int end = name.length();
        while (end > 0 && name.charAt(end - 1) == '/') end--;
        String prefix = name.substring(0, end);
        if (prefix.isEmpty() || prefix.startsWith("./"))
            throw Failure.invalid("INVALID_PATH", "invalid archive path component");
        Names.path(prefix, false, options);
        String path = display(root.locations, name);
        String message = "WARN_ZIP_DIRECTORY_SLASH: " + Bytes.diagnostic(path)
                + ": accepted empty ZIP directory with repeated trailing slashes\n";
        synchronized (budget) { budget.warnings.putIfAbsent("slash:" + path, message); }
        return prefix + "/";
    }

    private Model.Node zipNode(Model.Root root, String name, Model.Type type, int mode,
                               long size, byte[] raw) {
        Model.Node node = archiveNode(root, zipLogicalName(root, name, type, size), type, mode, size, raw);
        node.storedName = name;
        return node;
    }

    List<Model.Result> run() throws IOException {
        Path downloaded = null;
        try {
            Path path;
            if (options.input.matches("(?i)^https?://.*")) {
                downloaded = Download.fetch(options.input, options.maxDownload);
                path = downloaded.toRealPath();
            } else {
                if (options.input.matches("^[A-Za-z][A-Za-z0-9+.-]*://.*"))
                    throw Failure.unsupported("UNSUPPORTED_FORMAT", "only HTTP(S) URL inputs are supported");
                path = Path.of(options.input).toRealPath();
            }
            Model.Root root;
            if (Files.isDirectory(path)) {
                if (options.has("plain"))
                    throw Failure.unsupported("UNSUPPORTED_FORMAT", "plain hashing requires an archive input");
                if (options.stripSet) throw Failure.usage("strip-components requires an archive input");
                directoryInput = true;
                budget.spoolMemory.selectedRoot(path);
                root = directory(path);
            } else if (Files.isRegularFile(path)) {
                FilesInput.Stamp stamp = FilesInput.stamp(path);
                Model.Opener opener = FilesInput.opener(path, stamp);
                try (InputStream in = opener.open()) {
                    String suffixName = downloaded == null ? options.input : java.net.URI.create(options.input).getPath();
                    Discovery.Probe probe = Discovery.probe(in, suffixName, true);
                    root = archive(probe.stream(), probe.type(), opener, FilesInput.seekable(path, stamp),
                            List.of(), 0, true, options.strip, stamp.size());
                }
                FilesInput.verify(path, stamp);
            } else throw Failure.invalid("SPECIAL_FILE", "selected input is not a directory or archive file");
            List<Model.Result> output = new ArrayList<>();
            Deque<Model.Root> pending = new ArrayDeque<>();
            pending.push(root);
            while (!pending.isEmpty()) {
                Model.Root current = pending.pop();
                output.addAll(current.results);
                current.nested.sort((a, b) -> Bytes.compare(a.locations.getLast(), b.locations.getLast()));
                for (int i = current.nested.size() - 1; i >= 0; i--) pending.push(current.nested.get(i));
            }
            cleanupSpools();
            for (RunnableIO verify : verifications) verify.run();
            return output;
        } finally {
            try {
                cleanupSpools();
            } finally {
                Download.delete(downloaded);
            }
        }
    }

    private void cleanupSpools() throws IOException {
        IOException failure = null;
        for (ArchiveSpool spool : budget.spools) {
            try { spool.close(); }
            catch (IOException e) { failure = e; }
        }
        if (failure != null) throw failure;
        budget.spools.clear();
    }

    private Model.Root directory(Path base) throws IOException {
        Model.Tree tree = new Model.Tree();
        tree.goDirectories = false;
        Model.Root root = new Model.Root(List.of(), "directory", tree);
        root.filesystemRoot = true;
        Deque<Path> pending = new ArrayDeque<>();
        pending.push(base);
        while (!pending.isEmpty()) {
            Path path = pending.pop();
            FilesInput.Stamp stamp = FilesInput.stamp(path);
            if (stamp.directory()) {
                List<String> names = FilesInput.inventory(path);
                verifications.add(() -> {
                    location = path.toString();
                    FilesInput.verify(path, stamp);
                    if (!FilesInput.inventory(path).equals(names))
                        throw Failure.invalid("INPUT_CHANGED", "directory namespace changed");
                });
                for (int i = names.size() - 1; i >= 0; i--) pending.push(path.resolve(names.get(i)));
            }
            if (path.equals(base)) continue;
            String relative = base.relativize(path).toString().replace(java.io.File.separatorChar, '/');
            location = display(List.of(), relative);
            for (String component : relative.split("/")) Names.component(component, options);
            Model.Type type = stamp.directory() ? Model.Type.DIRECTORY : stamp.link()
                    ? Model.Type.SYMLINK : stamp.file() ? Model.Type.REGULAR : null;
            if (type == null) throw Failure.invalid("SPECIAL_FILE", "unsupported filesystem entry type");
            Model.Node node = new Model.Node(relative, type);
            node.explicit = true;
            node.included = !Exclusions.excluded(options, List.of(), relative, stamp.directory());
            node.manifestName = Bytes.utf8(relative);
            node.storedName = relative;
            node.mode = FilesInput.mode(path);
            node.size = stamp.size();
            entry();
            tree.add(node);
            if (type == Model.Type.DIRECTORY) continue;
            if (type == Model.Type.SYMLINK) {
                Path rawTarget = Files.readSymbolicLink(path);
                String target = rawTarget.toString();
                if (!rawTarget.equals(Path.of(target)))
                    throw Failure.invalid("INVALID_ENCODING", "filesystem link target cannot be exposed losslessly");
                node.target = Bytes.utf8(target);
                node.size = node.target.length;
                try (InputStream in = new ByteArrayInputStream(node.target)) {
                    payload(in, node, root, false, false, true, null, 0);
                }
                if (options.has("h1-go") && node.included) {
                    Path resolved;
                    try { resolved = path.toRealPath(); }
                    catch (java.nio.file.FileSystemLoopException e) {
                        throw Failure.invalid("UNSAFE_SYMLINK", "filesystem symlink cycle");
                    }
                    catch (IOException e) { throw Failure.invalid("DANGLING_SYMLINK", "cannot resolve filesystem link"); }
                    if (!resolved.startsWith(base) || !Files.isRegularFile(resolved))
                        throw Failure.invalid("UNSAFE_SYMLINK", "Go-compatible link read is not a confined regular file");
                    FilesInput.Stamp targetStamp = FilesInput.stamp(resolved);
                    try (InputStream in = FilesInput.opener(resolved, targetStamp).open()) {
                        Payload p = new Payload(in, this, targetStamp.size(), false, true);
                        drain(p);
                        p.raw.forEach((name, d) -> node.go.put(name, Digests.finish(d)));
                    }
                }
                FilesInput.verify(path, stamp);
            } else {
                node.opener = FilesInput.opener(path, stamp);
                node.seekable = FilesInput.seekable(path, stamp);
                node.independentRead = true;
                try (InputStream in = node.opener.open()) {
                    payload(in, node, root, false, node.included && options.discovers(), true, node.seekable, 1);
                }
            }
        }
        Names.collisions(tree.nodes, options);
        tree.membership();
        root.results = Hashing.results(options, root);
        return root;
    }

    private Model.Root archive(InputStream input, String type, Model.Opener opener, Model.SeekableOpener seekable,
                               List<String> locations, long depth, boolean report, int strip, long plainSize) throws IOException {
        if (depth > options.maxDepth) throw Failure.invalid("LIMIT_EXCEEDED", "archive-boundary depth exceeded");
        String previous = location;
        location = display(locations, null);
        Model.Root root = new Model.Root(locations, type, new Model.Tree());
        root.filesystemRoot = directoryInput;
        root.plainOpener = opener;
        root.plainSize = plainSize;
        boolean completed = false;
        try {
            if (type.equals("zip")) {
                if (seekable != null && locations.isEmpty()) zipFile(seekable, root, depth, report);
                else if (seekable != null) zipStreamKnown(input, opener, seekable, root, depth, report);
                else zipStream(input, opener, root, depth, report);
            } else tar(input, type.equals("tar.gz"), opener, seekable, root, depth, report);
            hardlinks(root, depth);
            Names.collisions(root.tree.nodes, options);
            if (options.strict) Names.links(root.tree.nodes);
            if (strip > 0) root.tree = project(root.tree, strip);
            root.tree.membership();
            if (report) root.results = Hashing.results(options, root);
            completed = true;
            return root;
        } catch (org.apache.commons.compress.archivers.zip.UnsupportedZipFeatureException e) {
            throw Failure.unsupported("UNSUPPORTED_METHOD", "unsupported ZIP feature or method");
        } catch (IOException | IllegalArgumentException e) {
            Failure failure = Failure.invalid("ARCHIVE_INTEGRITY", "archive decoder or structure validation failed");
            failure.initCause(e);
            throw failure;
        } finally {
            try {
                for (AutoCloseable resource : root.resources) {
                    try { resource.close(); }
                    catch (IOException e) { throw e; }
                    catch (Exception e) { throw new IOException(e); }
                }
                root.resources.clear();
            } finally {
                if (completed) location = previous;
            }
        }
    }

    private void add(Model.Root root, Model.Node node) {
        for (Model.Node added : root.tree.add(node)) {
            entry();
            added.included |= !Exclusions.excluded(options, root.locations, added.path,
                    added.type == Model.Type.DIRECTORY);
        }
    }

    private Model.Node archiveNode(Model.Root root, String name, Model.Type type, int mode,
                                   long size, byte[] manifest) {
        String logical = Names.path(name, type == Model.Type.DIRECTORY, options);
        Model.Node node = new Model.Node(logical, type);
        node.explicit = true;
        node.mode = mode;
        node.size = size;
        node.manifestName = manifest;
        node.storedName = name;
        node.included = !Exclusions.excluded(options, root.locations, logical, type == Model.Type.DIRECTORY);
        add(root, node);
        return node;
    }

    private void zipFile(Model.SeekableOpener source, Model.Root root, long depth, boolean report) throws IOException {
        ZipFile zip = openZipReader(source);
        root.resources.add(zip);
        List<ZipArchiveEntry> all = Collections.list(zip.getEntries());
        Map<Long, ZipPhysical.Metadata> checked = checkZip(source, all, root);
        for (ZipArchiveEntry e : all) {
            ZipPhysical.Metadata meta = checked.get(e.getLocalHeaderOffset());
            location = display(root.locations, meta.name());
            zipMethod(e);
            ZipMetadata.Unix unix = meta.unix();
            int fileType = unix.mode() & 0170000;
            boolean compatibilityDirectory = ZipMetadata.directoryModeCompatibility(
                    unix, meta.name(), e.getSize(), options.strict);
            if (!compatibilityDirectory && fileType != 0 && fileType != 0100000
                    && fileType != 0040000 && fileType != 0120000)
                throw Failure.invalid("SPECIAL_FILE", ZipMetadata.modeDescription(unix.mode())
                        + " for entry " + Bytes.textPath(meta.name())).at(display(root.locations, meta.name()));
            if (fileType == 0040000 && !e.isDirectory()
                    || e.isDirectory() && fileType != 0 && fileType != 0040000 && !compatibilityDirectory)
                throw Failure.invalid("ARCHIVE_LAYOUT", "ZIP directory name and Unix type disagree");
            Model.Type type = e.isDirectory() || compatibilityDirectory ? Model.Type.DIRECTORY
                    : fileType == 0120000 ? Model.Type.SYMLINK : Model.Type.REGULAR;
            if (compatibilityDirectory) warnZipDirectory(root, meta.name(), unix.mode());
            if (e.isDirectory() && e.getSize() != 0)
                throw Failure.invalid("ARCHIVE_INTEGRITY", "ZIP directory marker has a payload");
            Model.Node node = zipNode(root, meta.name(), type, unix.mode(),
                    e.getSize(), e.getRawName());
            node.opener = zipEntryOpener(zip, e, source);
            if (e.getMethod() == 0 && type == Model.Type.REGULAR)
                node.seekable = LogicalChannel.range(source, e.getDataOffset(), e.getSize());
            node.independentRead = true;
            // Commons' Deflate64 statistics omit stored-block bytes.
            var raw64 = e.getMethod() == 9
                    ? new org.apache.commons.io.input.CountingInputStream(zip.getRawInputStream(e)) : null;
            try (InputStream in = e.getMethod() == 8
                    ? new StreamingZip.Inflated(zip.getRawInputStream(e), null)
                    : raw64 == null ? zip.getInputStream(e)
                    : new org.apache.commons.compress.compressors.deflate64.Deflate64CompressorInputStream(raw64)) {
                Payload p = unix.target() == null ? payload(in, node, root, true,
                        type == Model.Type.REGULAR && node.included && options.discovers(), report, node.seekable, depth + 1)
                        : zipLinkPayload(in, node, root, unix.target(), e.getSize(), report, depth);
                if (p.count != e.getSize() || p.crc.getValue() != e.getCrc())
                    throw Failure.invalid("ARCHIVE_INTEGRITY", "ZIP payload CRC or size mismatch");
                if (e.getMethod() != 9 && in instanceof org.apache.commons.compress.utils.InputStreamStatistics stats
                        && stats.getCompressedCount() != e.getCompressedSize())
                    throw Failure.invalid("ARCHIVE_INTEGRITY", "ZIP decoder did not consume exact compressed extent");
                if (raw64 != null && raw64.getByteCount() != e.getCompressedSize())
                    throw Failure.invalid("ARCHIVE_INTEGRITY", "Deflate64 decoder did not consume exact compressed extent");
                if (in instanceof StreamingZip.Inflated inflater && inflater.compressedCount() != e.getCompressedSize())
                    throw Failure.invalid("ARCHIVE_INTEGRITY", "DEFLATE decoder did not consume exact compressed extent");
            }
        }
    }

    private void zipStream(InputStream input, Model.Opener opener, Model.Root root,
                           long depth, boolean report) throws IOException {
        zipStreamWithMetadata(input, opener, Map.of(), Map.of(), null, null, root, depth, report);
    }

    private void zipStreamKnown(InputStream input, Model.Opener opener, Model.SeekableOpener seekable, Model.Root root,
                                long depth, boolean report) throws IOException {
        ZipFile zip = openZipReader(seekable);
        root.resources.add(zip);
        List<ZipArchiveEntry> entries = Collections.list(zip.getEntries());
        Map<Long, ZipPhysical.Metadata> checked = checkZip(seekable, entries, root);
        Map<String, ZipArchiveEntry> metadata = new HashMap<>();
        for (ZipArchiveEntry entry : entries) metadata.put(Bytes.hex(entry.getRawName()), entry);
        zipStreamWithMetadata(input, opener, metadata, checked, seekable, zip, root, depth, report);
    }

    private void zipStreamWithMetadata(InputStream input, Model.Opener opener, Map<String, ZipArchiveEntry> metadata,
                                       Map<Long, ZipPhysical.Metadata> checked,
                                       Model.SeekableOpener seekable, ZipFile cachedZip,
                                       Model.Root root, long depth, boolean report) throws IOException {
        try {
            new StreamingZip(input, options.strict, options.strict || report && options.has("nar"), metadata,
                    (name, raw, size, localUnix, bytes, index) -> {
                        ZipArchiveEntry known = metadata.get(Bytes.hex(raw));
                        ZipPhysical.Metadata meta = known == null ? null : checked.get(known.getLocalHeaderOffset());
                        ZipMetadata.Unix unix = meta == null ? localUnix : meta.unix();
                        boolean compatibilityDirectory = ZipMetadata.directoryModeCompatibility(
                                unix, name, size, options.strict);
                        Model.Type type = name.endsWith("/") || compatibilityDirectory ? Model.Type.DIRECTORY
                                : (unix.mode() & 0170000) == 0120000 ? Model.Type.SYMLINK : Model.Type.REGULAR;
                        if (compatibilityDirectory) warnZipDirectory(root, name, unix.mode());
                        if (known != null) {
                            name = meta.name();
                            size = known.getSize();
                        }
                        location = display(root.locations, name);
                        Model.Node node = streamedZipNode(root, name, type, unix.mode(), size, raw,
                                known != null, index);
                        node.opener = known == null ? sequentialOpener(opener, "zip", index)
                                : zipEntryOpener(cachedZip, known, seekable);
                        if (known != null && known.getMethod() == 0 && type == Model.Type.REGULAR)
                            node.seekable = LogicalChannel.range(seekable, known.getDataOffset(), known.getSize());
                        node.independentRead = known != null;
                        Payload p = unix.target() == null ? payload(bytes, node, root, true,
                                type == Model.Type.REGULAR && node.included && options.discovers(),
                                report, node.seekable, depth + 1)
                                : zipLinkPayload(bytes, node, root, unix.target(), size, report, depth);
                        if (type == Model.Type.DIRECTORY && p.count != 0)
                            throw Failure.invalid("ARCHIVE_INTEGRITY", "ZIP directory marker has a payload");
                        return node;
                    }, (node, name, unix) -> {
                        String finalPath = Names.path(zipLogicalName(root, name, node.type, node.size),
                                node.type == Model.Type.DIRECTORY, options);
                        if (!node.storedName.equals(name)) {
                            if (options.discovers() && (node.archiveHint || Discovery.suffix(name) != null))
                                throw Failure.unsupported("UNSUPPORTED_STREAMING",
                                        "effective ZIP name needed for discovery is deferred");
                            node.storedName = name;
                        }
                        node.path = finalPath;
                        node.included = !Exclusions.excluded(options, root.locations, node.path,
                                node.type == Model.Type.DIRECTORY);
                        if (unix.target() != null && node.target == null) {
                            node.go.putAll(node.raw);
                            long physicalSize = node.size;
                            node.target = unix.target();
                            node.size = node.target.length;
                            Payload semantic = new Payload(new ByteArrayInputStream(node.target), this,
                                    node.size, false, report);
                            drain(semantic);
                            semantic.finish(node, false);
                            expanded(Math.max(0, node.size - physicalSize));
                        } else if ((unix.mode() & 0170000) == 0120000 && node.target == null
                                && options.selections.stream().allMatch(s -> s.scheme().equals("nar"))) {
                            try (InputStream target = node.opener.open()) {
                                node.target = target.readNBytes(1_048_577);
                                if (node.target.length > 1_048_576)
                                    throw Failure.invalid("LIMIT_EXCEEDED",
                                            "symlink target exceeds metadata representation");
                                node.size = node.target.length;
                            }
                        }
                    }).read();
        } catch (Failure failure) {
            if (failure.location != null) failure.location = display(root.locations, failure.location);
            throw failure;
        }
        Model.Tree reconciled = new Model.Tree();
        for (Model.Node node : root.tree.manifest) reconciled.add(node);
        for (Model.Node node : reconciled.nodes.values()) if (!node.explicit)
            node.included = !Exclusions.excluded(options, root.locations, node.path, true);
        root.tree = reconciled;
    }

    private Model.Node streamedZipNode(Model.Root root, String name, Model.Type type, int mode, long size,
                                       byte[] raw, boolean known, int index) {
        try {
            return zipNode(root, name, type, mode, size, raw);
        } catch (Failure failure) {
            if (known || !failure.code.equals("INVALID_PATH")) throw failure;
            Model.Node node = new Model.Node(name, type);
            node.path = "\0deferred-zip-" + index;
            node.storedName = name;
            node.manifestName = raw;
            node.explicit = true;
            node.included = !Exclusions.excluded(options, root.locations, name, type == Model.Type.DIRECTORY);
            node.mode = mode;
            node.size = size;
            add(root, node);
            return node;
        }
    }

    private Payload zipLinkPayload(InputStream bytes, Model.Node node, Model.Root root, byte[] target,
                                   long physicalSize, boolean report, long depth) throws IOException {
        node.target = target;
        node.size = physicalSize;
        Payload physical = new Payload(bytes, this, physicalSize, true, false);
        if (report) options.selections.stream().filter(s -> s.scheme().equals("h1-go"))
                .forEach(s -> physical.raw.computeIfAbsent(s.digest(), Digests::create));
        byte[] buffer = new byte[8192];
        long position = 0;
        int count;
        while ((count = physical.read(buffer)) >= 0) {
            for (int i = 0; i < count; i++) {
                if (position >= target.length || buffer[i] != target[(int) position++])
                    throw Failure.invalid("ARCHIVE_INTEGRITY", "ZIP inline link target contradicts its payload");
            }
        }
        if (position != 0 && position != target.length)
            throw Failure.invalid("ARCHIVE_INTEGRITY", "ZIP inline link target payload is incomplete");
        physical.raw.forEach((name, digest) -> node.go.put(name, Digests.finish(digest)));
        node.size = target.length;
        Payload semantic = new Payload(new ByteArrayInputStream(target), this, target.length, false, report);
        drain(semantic);
        semantic.finish(node, false);
        expanded(Math.max(0, target.length - physicalSize));
        return physical;
    }

    private ZipFile openZipReader(Model.SeekableOpener source) throws IOException {
        zipReaderOpens++;
        return zipReader(source);
    }

    private Map<Long, ZipPhysical.Metadata> checkZip(Model.SeekableOpener source,
                                                      List<ZipArchiveEntry> entries,
                                                      Model.Root root) throws IOException {
        try {
            return ZipPhysical.check(source, entries, options.strict);
        } catch (Failure failure) {
            if (failure.location != null) {
                failure.location = display(root.locations, failure.location);
                location = failure.location;
            }
            throw failure;
        }
    }

    private static ZipFile zipReader(Model.SeekableOpener source) throws IOException {
        var channel = ZipMetadataChannel.open(source);
        try {
            return ZipFile.builder().setSeekableByteChannel(channel).setCharset("IBM437")
                    .setUseUnicodeExtraFields(false).get();
        } catch (IOException | RuntimeException e) {
            channel.close();
            throw e;
        }
    }

    private Model.Opener zipEntryOpener(ZipFile zip, ZipArchiveEntry entry, Model.SeekableOpener source) {
        return () -> {
            verifySource(source);
            InputStream stream = zip.getInputStream(entry);
            return new java.io.FilterInputStream(stream) {
                private final java.util.zip.CRC32 crc = new java.util.zip.CRC32();
                private long count;
                private boolean verified;

                private void verify() {
                    if (verified) return;
                    verified = true;
                    if (count != entry.getSize() || crc.getValue() != entry.getCrc())
                        throw Failure.invalid("ARCHIVE_INTEGRITY", "ZIP reread CRC or size mismatch");
                }

                @Override public int read(byte[] bytes, int offset, int length) throws IOException {
                    int n = in.read(bytes, offset, length);
                    if (n > 0) {
                        count += n;
                        crc.update(bytes, offset, n);
                    } else if (n < 0) verify();
                    return n;
                }

                @Override public int read() throws IOException {
                    byte[] one = new byte[1];
                    return read(one, 0, 1) < 0 ? -1 : one[0] & 255;
                }

                @Override public void close() throws IOException {
                    try {
                        byte[] buffer = new byte[65536];
                        while (read(buffer) >= 0) {}
                    } finally {
                        try { super.close(); }
                        finally { verifySource(source); }
                    }
                }
            };
        };
    }

    private static void verifySource(Model.SeekableOpener source) throws IOException {
        if (source == null) return;
        try (var channel = source.open()) {}
    }

    private void zipMethod(ZipArchiveEntry e) {
        if (e.getDiskNumberStart() != 0)
            throw Failure.unsupported("UNSUPPORTED_FORMAT", "split/multi-disk ZIP entry");
        if (e.getGeneralPurposeBit().usesEncryption())
            throw Failure.unsupported("UNSUPPORTED_FORMAT", "encrypted ZIP");
        if (!Set.of(0, 8, 9, 12, 20, 93, 95).contains(e.getMethod()))
            throw Failure.unsupported("UNSUPPORTED_METHOD", "ZIP method " + e.getMethod());
    }

    private void tar(InputStream input, boolean gzip, Model.Opener opener, Model.SeekableOpener seekable, Model.Root root,
                     long depth, boolean report) throws IOException {
        InputStream decoded = input;
        if (gzip) decoded = new GzipInput(input, options.strict);
        TarPhysical physical = new TarPhysical(decoded, this);
        TarArchiveInputStream tar = new SparseTarInput(physical);
        TarArchiveEntry e;
        int index = 0;
        while ((e = tar.getNextEntry()) != null) {
            if (!e.isCheckSumOK()) throw Failure.invalid("ARCHIVE_INTEGRITY", "invalid TAR header checksum");
            Model.Type type = e.isDirectory() ? Model.Type.DIRECTORY : e.isSymbolicLink()
                    ? Model.Type.SYMLINK : e.isLink() ? Model.Type.HARDLINK
                    : Set.of((byte) 0, (byte) '0', (byte) '7', (byte) 'S').contains(e.getLinkFlag())
                    ? Model.Type.REGULAR : null;
            if (type == null) throw Failure.invalid("SPECIAL_FILE", "unsupported TAR special entry");
            if (e.isStarSparse()) throw Failure.unsupported("UNSUPPORTED_FORMAT", "unsupported STAR sparse extension");
            if (e.isSparse()) e.getOrderedSparseHeaders();
            String name = e.getName();
            location = display(root.locations, name);
            Model.Node node = archiveNode(root, name, type, e.getMode(),
                    e.isSparse() ? e.getRealSize() : e.getSize(), Bytes.utf8(name));
            int entryIndex = index++;
            node.opener = sequentialOpener(opener, gzip ? "tar.gz" : "tar", entryIndex);
            if (!gzip && seekable != null && type == Model.Type.REGULAR) {
                List<org.apache.commons.compress.archivers.tar.TarArchiveStructSparse> extents =
                        e.isSparse() ? List.copyOf(e.getOrderedSparseHeaders())
                        : List.of(new org.apache.commons.compress.archivers.tar.TarArchiveStructSparse(0, node.size));
                node.seekable = LogicalChannel.sparse(seekable, physical.position(), node.size, extents);
                node.opener = () -> java.nio.channels.Channels.newInputStream(node.seekable.open());
                node.independentRead = true;
            }
            if (type == Model.Type.SYMLINK) {
                node.target = Bytes.utf8(e.getLinkName());
                node.size = node.target.length;
                payload(new ByteArrayInputStream(node.target), node, root, true, false, report, null, depth + 1);
                drain(tar);
            } else if (type == Model.Type.HARDLINK) {
                try {
                    node.hardTarget = Names.path(e.getLinkName(), false, options);
                } catch (Failure failure) {
                    if (failure.code.equals("INVALID_ENCODING")) throw failure;
                    throw Failure.invalid("INVALID_HARDLINK", "invalid archive-root-relative hard-link target");
                }
                drain(tar);
            } else {
                Payload p = tarPayload(tar, node, root, depth, report);
                if (p.count != node.size)
                    throw Failure.invalid("ARCHIVE_INTEGRITY", "TAR logical size mismatch");
            }
        }
        drain(physical);
    }

    private Payload tarPayload(InputStream input, Model.Node target, Model.Root root, long depth,
                               boolean report) throws IOException {
        List<Model.Node> aliases = new ArrayList<>();
        if (!target.independentRead && target.type == Model.Type.REGULAR && options.discovers()
                && options.selections.stream().anyMatch(selection -> !selection.scheme().equals("nar"))) {
            for (Model.Node candidate : root.tree.nodes.values()) {
                if (candidate.type != Model.Type.HARDLINK || !candidate.included) continue;
                Set<String> seen = new HashSet<>();
                Model.Node reference = candidate;
                while (reference != null && reference.type == Model.Type.HARDLINK && seen.add(reference.path))
                    reference = root.tree.nodes.get(reference.hardTarget);
                if (reference == target) aliases.add(candidate);
            }
        }
        if (aliases.isEmpty()) return payload(input, target, root, true,
                target.type == Model.Type.REGULAR && target.included && options.discovers(),
                report, target.seekable, depth + 1);
        if (aliases.size() > 1024)
            throw Failure.invalid("LIMIT_EXCEEDED", "concurrent archive alias representation limit");
        List<PayloadFanout.Consumer> consumers = new ArrayList<>();
        List<Model.Root> containers = new ArrayList<>();
        for (Model.Node alias : aliases) {
            alias.size = target.size;
            alias.opener = target.opener;
            Model.Root container = new Model.Root(root.locations, root.inputType, new Model.Tree());
            containers.add(container);
            Engine child = new Engine(options, budget);
            child.directoryInput = directoryInput;
            consumers.add(stream -> {
                try {
                    child.payload(stream, alias, container, false, true, false, null, depth + 1);
                } catch (IOException | RuntimeException failure) {
                    synchronized (budget) { location = child.location; }
                    throw failure;
                }
            });
        }
        try (PayloadFanout fanout = new PayloadFanout(input, consumers)) {
            Payload result = payload(fanout, target, root, true, target.included && options.discovers(),
                    report, null, depth + 1);
            fanout.close();
            aliases.forEach(alias -> alias.discoveryComplete = true);
            containers.forEach(container -> root.nested.addAll(container.nested));
            return result;
        }
    }

    private Model.Opener sequentialOpener(Model.Opener source, String type, int target) {
        return () -> {
            if (type.equals("zip")) return ZipEntryStream.open(source, target);
            InputStream input = source.open();
            try {
                InputStream decoded = type.equals("tar.gz") ? new GzipInput(input, options.strict) : input;
                TarArchiveInputStream archive = new SparseTarInput(decoded);
                for (int i = 0; i <= target; i++)
                    if (archive.getNextEntry() == null) throw Failure.invalid("INPUT_CHANGED", "archive entry disappeared");
                return archive;
            } catch (IOException | RuntimeException e) {
                input.close();
                throw e;
            }
        };
    }

    private Payload payload(InputStream input, Model.Node node, Model.Root root, boolean archive,
                            boolean discover, boolean report, Model.SeekableOpener seekable, long childDepth) throws IOException {
        Payload p = new Payload(input, this, node.size, archive, report);
        if (node.type == Model.Type.SYMLINK && node.target == null) {
            if (node.size > 1_048_576)
                throw Failure.invalid("LIMIT_EXCEEDED", "symlink target exceeds bounded metadata representation");
            node.target = p.readNBytes(1_048_577);
            if (node.target.length > 1_048_576)
                throw Failure.invalid("LIMIT_EXCEEDED", "symlink target exceeds bounded metadata representation");
        } else if (discover) {
            Discovery.Probe probe = Discovery.probe(p, node.original, false);
            node.archiveHint = probe.type() != null;
            if (probe.type() != null) {
                List<String> locations = new ArrayList<>(root.locations);
                locations.add(node.original);
                if (childDepth > options.maxDepth)
                    throw Failure.invalid("LIMIT_EXCEEDED", "archive-boundary depth exceeded");
                Model.Root child;
                if (seekable == null) {
                    ArchiveSpool spool = ArchiveSpool.copy(probe.stream(), node.size, budget.spoolMemory);
                    synchronized (budget) { budget.spools.add(spool); }
                    node.opener = spool::open;
                    node.seekable = spool::channel;
                    node.independentRead = true;
                    try (InputStream replay = node.opener.open()) {
                        child = archive(replay, probe.type(), node.opener, node.seekable,
                                List.copyOf(locations), childDepth, options.recurse, 0, node.size);
                    }
                } else child = archive(probe.stream(), probe.type(), node.opener, seekable,
                            List.copyOf(locations), childDepth, options.recurse, 0, node.size);
                if (options.recurse) root.nested.add(child);
            }
            drain(probe.stream());
        } else if (archive && options.discovers() && node.type == Model.Type.REGULAR) {
            Discovery.Probe probe = Discovery.probe(p, "", false);
            node.archiveHint = probe.type() != null;
            drain(probe.stream());
        } else drain(p);
        if (node.type == Model.Type.REGULAR && node.size >= 0 && p.count != node.size)
            throw Failure.invalid(archive ? "ARCHIVE_INTEGRITY" : "INPUT_CHANGED",
                    "regular-file length differs from its declared metadata");
        p.finish(node, false);
        return p;
    }

    private void hardlinks(Model.Root root, long depth) throws IOException {
        Model.Tree tree = root.tree;
        List<Model.Node> aliases = tree.nodes.values().stream()
                .filter(n -> n.type == Model.Type.HARDLINK).toList();
        for (Model.Node start : tree.nodes.values()) {
            if (start.type != Model.Type.HARDLINK) continue;
            List<Model.Node> chain = new ArrayList<>();
            Set<String> seen = new HashSet<>();
            Model.Node target = start;
            while (target.type == Model.Type.HARDLINK) {
                if (!seen.add(target.path)) throw Failure.invalid("INVALID_HARDLINK", "hard-link cycle");
                chain.add(target);
                target = tree.nodes.get(target.hardTarget);
                if (target == null) throw Failure.invalid("INVALID_HARDLINK", "missing hard-link target");
            }
            if (target.type != Model.Type.REGULAR)
                throw Failure.invalid("INVALID_HARDLINK", "hard-link ultimate target is not a regular file");
            for (Model.Node node : chain) {
                node.type = Model.Type.REGULAR;
                node.size = target.size;
                node.opener = target.opener;
                node.raw.putAll(target.raw);
                node.blobs.putAll(target.blobs);
                node.archiveHint = target.archiveHint;
                node.independentRead = target.independentRead;
                node.seekable = target.seekable;
                expanded(node.size);
            }
        }
        for (Model.Node alias : aliases) {
            if (!alias.included || !options.discovers() || alias.discoveryComplete) continue;
            if (!alias.archiveHint && Discovery.suffix(alias.original) == null) continue;
            if (!alias.independentRead && options.selections.stream().anyMatch(s -> !s.scheme().equals("nar")))
                throw Failure.unsupported("UNSUPPORTED_STREAMING",
                        "archive hard-link alias cannot be revisited without rereading its sequential parent payload");
            try (InputStream in = alias.opener.open()) {
                payload(in, alias, root, false, true, false, alias.seekable, depth + 1);
            }
        }
    }

    private Model.Tree project(Model.Tree original, int strip) {
        Model.Tree projected = new Model.Tree();
        for (Model.Node n : original.manifest) {
            String stored = n.storedName;
            boolean trailing = stored.endsWith("/");
            if (trailing) stored = stored.substring(0, stored.length() - 1);
            String[] parts = stored.split("/", -1);
            if (parts.length <= strip) {
                if (n.type != Model.Type.DIRECTORY)
                    throw Failure.invalid("INVALID_PATH", "strip-components consumes a non-directory entry");
                continue;
            }
            String transformed = String.join("/", java.util.Arrays.copyOfRange(parts, strip, parts.length))
                    + (trailing ? "/" : "");
            Model.Node copy = n.copy(Names.path(transformed, n.type == Model.Type.DIRECTORY, options));
            int rawStart = 0;
            for (int component = 0; component < strip; component++) {
                while (rawStart < n.manifestName.length && n.manifestName[rawStart] != '/') rawStart++;
                if (rawStart < n.manifestName.length) rawStart++;
            }
            copy.manifestName = java.util.Arrays.copyOfRange(n.manifestName, rawStart, n.manifestName.length);
            copy.storedName = transformed;
            projected.add(copy);
        }
        Names.collisions(projected.nodes, options);
        if (options.strict) Names.links(projected.nodes);
        return projected;
    }

    private String display(List<String> locations, String entry) {
        if (directoryInput) {
            if (locations.isEmpty())
                return entry == null ? options.input : Path.of(options.input).resolve(entry).toString();
            String value = Path.of(options.input).resolve(locations.getFirst()).toString();
            if (locations.size() == 1 && entry == null) return value;
            value = value.replace("!", "!!");
            for (int i = 1; i < locations.size(); i++)
                value += "!/" + locations.get(i).replace("!", "!!");
            if (entry != null) value += "!/" + entry.replace("!", "!!");
            return value;
        }
        if (locations.isEmpty() && entry == null) return options.input;
        String value = options.input.replace("!", "!!");
        for (String location : locations) value += "!/" + location.replace("!", "!!");
        if (entry != null) value += "!/" + entry.replace("!", "!!");
        return value;
    }

    static void drain(InputStream input) throws IOException {
        byte[] buffer = new byte[65536];
        while (input.read(buffer) >= 0) {}
    }

    private static InputStream closing(InputStream stream, AutoCloseable owner) {
        return new FilterInputStream(stream) {
            @Override
            public void close() throws IOException {
                try { super.close(); } finally {
                    try { owner.close(); }
                    catch (IOException e) { throw e; }
                    catch (Exception e) { throw new IOException(e); }
                }
            }
        };
    }
}
