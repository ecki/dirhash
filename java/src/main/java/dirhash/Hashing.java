package dirhash;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.bouncycastle.crypto.Digest;

final class Hashing {
    static List<Model.Result> results(Options options, Model.Root root) throws IOException {
        List<Model.Result> results = new ArrayList<>();
        Map<String, byte[]> nar = options.has("nar") ? nar(options, root.tree) : Map.of();
        Map<String, byte[]> plain = options.has("plain") ? plain(options, root) : Map.of();
        for (Options.Selection selection : options.selections) {
            String scheme = selection.scheme();
            String primitive = selection.digest();
            byte[] value = switch (scheme) {
                case "h1", "h1-go" -> manifest(root.tree, primitive, scheme.equals("h1-go"));
                case "gittree", "swhid" -> tree(root.tree, primitive, scheme.equals("swhid"));
                case "nar" -> nar.get(primitive);
                case "plain" -> plain.get(primitive);
                default -> throw new AssertionError();
            };
            String display;
            int firstArchive = 0;
            if (root.filesystemRoot && !root.locations.isEmpty()) {
                display = java.nio.file.Path.of(options.input).resolve(root.locations.getFirst()).toString();
                firstArchive = 1;
            } else {
                display = options.input;
            }
            if (root.locations.size() > firstArchive) display = display.replace("!", "!!");
            for (int i = firstArchive; i < root.locations.size(); i++)
                display += "!/" + root.locations.get(i).replace("!", "!!");
            results.add(new Model.Result(display, options.input, root.locations, root.inputType,
                    scheme, primitive, render(scheme, primitive, value)));
        }
        return results;
    }

    private static String render(String scheme, String digest, byte[] value) {
        if (scheme.equals("plain")) return digest + ":" + Bytes.hex(value);
        if ((scheme.equals("h1") || scheme.equals("h1-go")) && digest.equals("sha256"))
            return "h1:" + Base64.getEncoder().encodeToString(value);
        if (scheme.equals("gittree") && (digest.equals("sha1") || digest.equals("sha256")))
            return Bytes.hex(value);
        if (scheme.equals("swhid") && digest.equals("sha1")) return "swh:1:dir:" + Bytes.hex(value);
        if (scheme.equals("nar") && digest.equals("sha256"))
            return "sha256-" + Base64.getEncoder().encodeToString(value);
        return "dirhash:1:" + scheme + ":" + digest + ":" + Bytes.hex(value);
    }

    private static Map<String, byte[]> plain(Options options, Model.Root root) throws IOException {
        if (root.plainOpener == null)
            throw Failure.unsupported("UNSUPPORTED_FORMAT", "plain hashing requires an archive input");
        Map<String, Digest> digests = new HashMap<>();
        options.selections.stream().filter(selection -> selection.scheme().equals("plain"))
                .forEach(selection -> digests.putIfAbsent(selection.digest(), Digests.create(selection.digest())));
        byte[] buffer = new byte[65536];
        long count = 0;
        try (InputStream input = root.plainOpener.open()) {
            int n;
            while ((n = input.read(buffer)) >= 0) {
                if (n == 0) continue;
                if (root.plainSize >= 0 && n > root.plainSize - count)
                    throw Failure.invalid("INPUT_CHANGED", "archive byte length changed during plain hashing");
                count += n;
                for (Digest digest : digests.values()) digest.update(buffer, 0, n);
            }
        }
        if (root.plainSize >= 0 && count != root.plainSize)
            throw Failure.invalid("INPUT_CHANGED", "archive byte length changed during plain hashing");
        Map<String, byte[]> values = new HashMap<>();
        digests.forEach((name, digest) -> values.put(name, Digests.finish(digest)));
        return values;
    }

    private static byte[] manifest(Model.Tree tree, String primitive, boolean go) {
        List<Model.Node> files = go ? new ArrayList<>(tree.manifest) : tree.nodes.values().stream()
                .filter(n -> n.type != Model.Type.DIRECTORY).collect(java.util.stream.Collectors.toList());
        files.removeIf(n -> !n.included);
        if (go && !tree.goDirectories) files.removeIf(n -> n.type == Model.Type.DIRECTORY);
        files.sort((a, b) -> java.util.Arrays.compareUnsigned(go ? a.manifestName : Bytes.utf8(a.path),
                go ? b.manifestName : Bytes.utf8(b.path)));
        Digest digest = Digests.create(primitive);
        for (Model.Node node : files) {
            byte[] content = go ? node.go.getOrDefault(primitive, node.raw.get(primitive)) : node.raw.get(primitive);
            if (node.type == Model.Type.DIRECTORY) content = Digests.hash(primitive, new byte[0]);
            Digests.update(digest, Bytes.utf8(Bytes.hex(content) + "  "));
            Digests.update(digest, go ? node.manifestName : Bytes.utf8(node.path));
            digest.update((byte) '\n');
        }
        return Digests.finish(digest);
    }

    private static Map<String, List<Model.Node>> children(Model.Tree tree) {
        Map<String, List<Model.Node>> children = new HashMap<>();
        for (Model.Node node : tree.nodes.values()) {
            if (!node.included || node.path.isEmpty()) continue;
            children.computeIfAbsent(parent(node.path), ignored -> new ArrayList<>()).add(node);
        }
        return children;
    }

    private static String parent(String path) {
        int slash = path.lastIndexOf('/');
        return slash < 0 ? "" : path.substring(0, slash);
    }

    private static String name(String path) {
        return path.substring(path.lastIndexOf('/') + 1);
    }

    private static byte[] tree(Model.Tree tree, String primitive, boolean swh) {
        Map<String, List<Model.Node>> children = children(tree);
        Map<String, byte[]> ids = new HashMap<>();
        List<Model.Node> directories = tree.nodes.values().stream()
                .filter(n -> n.included && n.type == Model.Type.DIRECTORY)
                .sorted((a, b) -> Integer.compare(b.path.length(), a.path.length())).toList();
        for (Model.Node directory : directories) {
            List<Model.Node> selected = new ArrayList<>(children.getOrDefault(directory.path, List.of()));
            selected.removeIf(n -> n.type == Model.Type.DIRECTORY && !ids.containsKey(n.path));
            if (!swh && selected.isEmpty() && !directory.path.isEmpty()) continue;
            selected.sort((a, b) -> Bytes.compare(name(a.path) + (a.type == Model.Type.DIRECTORY ? "/" : ""),
                    name(b.path) + (b.type == Model.Type.DIRECTORY ? "/" : "")));
            long length = 0;
            int width = Digests.create(primitive).getDigestSize();
            for (Model.Node node : selected)
                length += Bytes.utf8(mode(node, swh) + " " + name(node.path)).length + 1L + width;
            Digest hash = Digests.create(primitive);
            Digests.update(hash, Bytes.utf8("tree " + length + "\0"));
            for (Model.Node node : selected) {
                Digests.update(hash, Bytes.utf8(mode(node, swh) + " " + name(node.path) + "\0"));
                Digests.update(hash, node.type == Model.Type.DIRECTORY ? ids.get(node.path) : node.blobs.get(primitive));
            }
            ids.put(directory.path, Digests.finish(hash));
        }
        return ids.get("");
    }

    private static String mode(Model.Node n, boolean swh) {
        return switch (n.type) {
            case DIRECTORY -> "40000";
            case SYMLINK -> "120000";
            default -> (n.mode & (swh ? 0111 : 0100)) != 0 ? "100755" : "100644";
        };
    }

    private static Map<String, byte[]> nar(Options options, Model.Tree tree) throws IOException {
        Map<String, Digest> hashes = new HashMap<>();
        options.selections.stream().filter(s -> s.scheme().equals("nar"))
                .forEach(s -> hashes.put(s.digest(), Digests.create(s.digest())));
        Map<String, List<Model.Node>> children = children(tree);
        children.values().forEach(list -> list.sort((a, b) -> Bytes.compare(name(a.path), name(b.path))));
        Deque<Object> pending = new ArrayDeque<>();
        pending.addFirst(tree.nodes.get(""));
        pending.addFirst("nix-archive-1");
        byte[] buffer = new byte[65536];
        while (!pending.isEmpty()) {
            Object action = pending.removeFirst();
            if (action instanceof String token) {
                string(hashes, Bytes.utf8(token));
            } else if (action instanceof byte[] value) {
                string(hashes, value);
            } else {
                Model.Node node = (Model.Node) action;
                string(hashes, Bytes.utf8("("));
                string(hashes, Bytes.utf8("type"));
                switch (node.type) {
                    case DIRECTORY -> {
                        string(hashes, Bytes.utf8("directory"));
                        pending.addFirst(")");
                        List<Model.Node> list = children.getOrDefault(node.path, List.of());
                        for (int i = list.size() - 1; i >= 0; i--) {
                            Model.Node child = list.get(i);
                            pending.addFirst(")");
                            pending.addFirst(child);
                            pending.addFirst("node");
                            pending.addFirst(name(child.path));
                            pending.addFirst("name");
                            pending.addFirst("(");
                            pending.addFirst("entry");
                        }
                    }
                    case SYMLINK -> {
                        string(hashes, Bytes.utf8("symlink"));
                        string(hashes, Bytes.utf8("target"));
                        string(hashes, node.target);
                        string(hashes, Bytes.utf8(")"));
                    }
                    default -> {
                        string(hashes, Bytes.utf8("regular"));
                        if ((node.mode & 0100) != 0) {
                            string(hashes, Bytes.utf8("executable"));
                            string(hashes, new byte[0]);
                        }
                        string(hashes, Bytes.utf8("contents"));
                        length(hashes, node.size);
                        long count = 0;
                        try (InputStream in = node.opener.open()) {
                            int n;
                            while ((n = in.read(buffer)) >= 0) {
                                if (n == 0) continue;
                                update(hashes, buffer, n);
                                count += n;
                                if (count > node.size)
                                    throw Failure.invalid("INPUT_CHANGED", "file length changed during NAR pass");
                            }
                        }
                        if (count != node.size)
                            throw Failure.invalid("INPUT_CHANGED", "file length changed during NAR pass");
                        padding(hashes, node.size);
                        string(hashes, Bytes.utf8(")"));
                    }
                }
            }
        }
        Map<String, byte[]> results = new HashMap<>();
        hashes.forEach((name, hash) -> results.put(name, Digests.finish(hash)));
        return results;
    }

    private static void string(Map<String, Digest> hashes, byte[] value) {
        length(hashes, value.length);
        update(hashes, value, value.length);
        padding(hashes, value.length);
    }

    private static void length(Map<String, Digest> hashes, long length) {
        byte[] bytes = new byte[8];
        for (int i = 0; i < 8; i++) bytes[i] = (byte) (length >>> (8 * i));
        update(hashes, bytes, bytes.length);
    }

    private static void padding(Map<String, Digest> hashes, long length) {
        update(hashes, new byte[8], (int) ((8 - (length & 7)) & 7));
    }

    private static void update(Map<String, Digest> hashes, byte[] bytes, int length) {
        hashes.values().forEach(d -> d.update(bytes, 0, length));
    }
}
