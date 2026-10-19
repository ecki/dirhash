package dirhash;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

final class Model {
    enum Type { DIRECTORY, REGULAR, SYMLINK, HARDLINK }

    @FunctionalInterface
    interface Opener {
        InputStream open() throws IOException;
    }

    @FunctionalInterface
    interface SeekableOpener {
        java.nio.channels.SeekableByteChannel open() throws IOException;
    }

    static final class Node {
        String path;
        final String original;
        Type type;
        int mode;
        long size;
        byte[] target;
        String hardTarget;
        byte[] manifestName;
        String storedName;
        boolean explicit;
        boolean included;
        boolean archiveHint;
        boolean independentRead;
        boolean discoveryComplete;
        Opener opener;
        SeekableOpener seekable;
        final Map<String, byte[]> raw = new HashMap<>();
        final Map<String, byte[]> blobs = new HashMap<>();
        final Map<String, byte[]> go = new HashMap<>();

        Node(String path, Type type) {
            this.path = path;
            this.original = path;
            this.type = type;
        }

        Node copy(String projected) {
            Node n = new Node(projected, type);
            n.mode = mode;
            n.size = size;
            n.target = target;
            n.explicit = explicit;
            n.included = included;
            n.archiveHint = archiveHint;
            n.independentRead = independentRead;
            n.manifestName = manifestName;
            n.storedName = storedName;
            n.opener = opener;
            n.seekable = seekable;
            n.raw.putAll(raw);
            n.blobs.putAll(blobs);
            n.go.putAll(go);
            return n;
        }
    }

    static final class Tree {
        final Map<String, Node> nodes = new TreeMap<>(Bytes::compare);
        final List<Node> manifest = new ArrayList<>();
        boolean rootExplicit;
        boolean goDirectories = true;

        Tree() {
            Node root = new Node("", Type.DIRECTORY);
            root.included = true;
            nodes.put("", root);
        }

        List<Node> add(Node n) {
            List<Node> added = new ArrayList<>();
            if (n.path.isEmpty()) {
                if (rootExplicit) throw Failure.invalid("DUPLICATE_ENTRY", "duplicate root marker");
                rootExplicit = true;
                nodes.get("").explicit = true;
                manifest.add(n);
                return added;
            }
            int start = 0;
            while ((start = n.path.indexOf('/', start)) >= 0) {
                String parent = n.path.substring(0, start++);
                Node previous = nodes.get(parent);
                if (previous != null && previous.type != Type.DIRECTORY)
                    throw Failure.invalid("DUPLICATE_ENTRY", "file/directory conflict");
                if (previous == null) {
                    Node dir = new Node(parent, Type.DIRECTORY);
                    nodes.put(parent, dir);
                    added.add(dir);
                }
            }
            Node old = nodes.get(n.path);
            if (old != null) {
                if (old.type != Type.DIRECTORY || n.type != Type.DIRECTORY || old.explicit)
                    throw Failure.invalid("DUPLICATE_ENTRY", "duplicate entry or file/directory conflict");
                n.included |= old.included;
            } else added.add(n);
            nodes.put(n.path, n);
            if (n.explicit) manifest.add(n);
            return added;
        }

        void membership() {
            for (Node n : new ArrayList<>(nodes.values())) {
                if (!n.included) continue;
                String path = n.path;
                while (path.contains("/")) {
                    path = path.substring(0, path.lastIndexOf('/'));
                    nodes.get(path).included = true;
                }
            }
        }
    }

    record Result(String path, String source, List<String> archiveEntries, String inputType,
                  String scheme, String digestAlgorithm, String value) {
        String json() {
            return "{\"path\":" + Bytes.json(path) + ",\"source\":" + Bytes.json(source)
                    + ",\"archiveEntries\":[" + String.join(",", archiveEntries.stream().map(Bytes::json).toList())
                    + "],\"inputType\":" + Bytes.json(inputType) + ",\"scheme\":" + Bytes.json(scheme)
                    + ",\"digestAlgorithm\":" + Bytes.json(digestAlgorithm) + ",\"value\":"
                    + Bytes.json(value) + "}";
        }
    }

    static final class Root {
        final List<String> locations;
        final String inputType;
        Tree tree;
        Opener plainOpener;
        long plainSize;
        boolean filesystemRoot;
        final List<AutoCloseable> resources = new ArrayList<>();
        final List<Root> nested = new ArrayList<>();
        List<Result> results = List.of();

        Root(List<String> locations, String inputType, Tree tree) {
            this.locations = locations;
            this.inputType = inputType;
            this.tree = tree;
        }
    }
}
