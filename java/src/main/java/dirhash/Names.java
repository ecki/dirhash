package dirhash;

import com.ibm.icu.lang.UCharacter;
import com.ibm.icu.lang.UCharacterCategory;
import com.ibm.icu.text.Normalizer2;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.Map;

final class Names {
    private static final Normalizer2 NFC = Normalizer2.getNFCInstance();

    static String path(String stored, boolean directory, Options options) {
        Bytes.scalar(stored);
        if (stored.isEmpty()) throw Failure.invalid("INVALID_PATH", "empty archive entry name");
        if (stored.equals(".")) throw Failure.invalid("INVALID_PATH", "bare dot is not an archive root marker");
        if (stored.indexOf('\0') >= 0 || stored.indexOf('\\') >= 0 || stored.startsWith("/")
                || stored.matches("^[A-Za-z]:.*"))
            throw Failure.invalid("INVALID_PATH", "archive path is not root-relative");
        String value = stored;
        if (directory && value.endsWith("/")) value = value.substring(0, value.length() - 1);
        while (value.startsWith("./")) value = value.substring(2);
        if (value.equals(".") && directory) value = "";
        if (value.matches("^[A-Za-z]:.*"))
            throw Failure.invalid("INVALID_PATH", "drive-qualified logical archive path");
        if (value.isEmpty()) {
            if (!directory) throw Failure.invalid("INVALID_PATH", "empty non-directory path");
            return "";
        }
        for (String part : value.split("/", -1)) {
            if (part.isEmpty() || part.equals(".") || part.equals(".."))
                throw Failure.invalid("INVALID_PATH", "invalid archive path component");
            component(part, options);
        }
        return value;
    }

    static void component(String value, Options options) {
        Bytes.scalar(value);
        if (value.indexOf('\0') >= 0 || value.indexOf('/') >= 0 || value.indexOf('\\') >= 0)
            throw Failure.invalid("INVALID_PATH", "invalid filename");
        if ((options.has("h1") || options.has("h1-go")) && value.indexOf('\n') >= 0)
            throw Failure.invalid("INVALID_PATH", "LF cannot be represented in an h1 manifest");
        if (!options.strict) return;
        value.codePoints().forEach(c -> {
            int category = UCharacter.getType(c);
            if (category == UCharacterCategory.CONTROL || category == UCharacterCategory.FORMAT
                    || c >= 0xfdd0 && c <= 0xfdef || (c & 0xffff) >= 0xfffe
                    || "<>:\"|?*".indexOf(c) >= 0)
                throw Failure.invalid("INVALID_PATH", "non-portable filename character");
        });
        if (value.endsWith(".") || value.endsWith(" "))
            throw Failure.invalid("INVALID_PATH", "filename ends in dot or space");
        String base = value.split("\\.", 2)[0].toUpperCase(java.util.Locale.ROOT);
        if (base.matches("CON|PRN|AUX|NUL|CONIN\\$|CONOUT\\$|COM[1-9¹²³]|LPT[1-9¹²³]"))
            throw Failure.invalid("INVALID_PATH", "reserved device name");
    }

    static String fold(String value) {
        return NFC.normalize(UCharacter.foldCase(NFC.normalize(value), true));
    }

    static void collisions(Map<String, Model.Node> nodes, Options options) {
        if (!options.strict) return;
        Map<String, String> seen = new HashMap<>();
        for (String path : nodes.keySet()) {
            if (path.isEmpty()) continue;
            int slash = path.lastIndexOf('/');
            String parent = slash < 0 ? "" : path.substring(0, slash + 1);
            String name = path.substring(slash + 1);
            String previous = seen.putIfAbsent(parent + fold(name), path);
            if (previous != null && !previous.equals(path))
                throw Failure.invalid("NAME_COLLISION", "portable sibling name collision");
        }
    }

    static void links(Map<String, Model.Node> nodes) {
        for (Model.Node node : nodes.values()) {
            if (node.type != Model.Type.SYMLINK) continue;
            resolve(node.path, nodes);
        }
    }

    private static void resolve(String link, Map<String, Model.Node> nodes) {
        Deque<String> pending = new ArrayDeque<>();
        pending.addAll(java.util.List.of(link.split("/")));
        Deque<String> current = new ArrayDeque<>();
        java.util.Set<String> active = new java.util.HashSet<>();
        while (!pending.isEmpty()) {
            String part = pending.removeFirst();
            if (part.startsWith("\0")) {
                active.remove(part.substring(1));
                continue;
            }
            if (part.isEmpty() || part.equals(".")) continue;
            if (part.equals("..")) {
                if (current.isEmpty()) throw Failure.invalid("UNSAFE_SYMLINK", "link escapes archive root");
                current.removeLast();
                continue;
            }
            current.addLast(part);
            Model.Node found = nodes.get(String.join("/", current));
            if (found == null) throw Failure.invalid("DANGLING_SYMLINK", "archive link target does not exist");
            if (found.type == Model.Type.SYMLINK) {
                if (!active.add(found.path))
                    throw Failure.invalid("UNSAFE_SYMLINK", "archive link cycle");
                String target = Bytes.decode(found.target);
                if (target.isEmpty() || target.startsWith("/") || target.indexOf('\\') >= 0
                        || target.indexOf('\0') >= 0 || target.matches("^[A-Za-z]:.*"))
                    throw Failure.invalid("UNSAFE_SYMLINK", "invalid archive link target");
                current.removeLast();
                String[] components = target.split("/", -1);
                pending.addFirst("\0" + found.path);
                for (int i = components.length - 1; i >= 0; i--) pending.addFirst(components[i]);
            } else if (pending.stream().anyMatch(p -> !p.startsWith("\0")) && found.type != Model.Type.DIRECTORY)
                throw Failure.invalid("UNSAFE_SYMLINK", "non-directory link target component");
        }
    }
}
