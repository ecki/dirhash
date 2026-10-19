package dirhash;

import java.util.ArrayList;
import java.util.List;

final class Exclusions {
    record Pattern(List<String> levels, boolean directory) {}

    static Pattern compile(String value) {
        if (value.isEmpty() || value.indexOf('\\') >= 0 || value.indexOf('\0') >= 0)
            throw Failure.usage("invalid exclusion pattern");
        Bytes.scalar(value);
        boolean directory = value.endsWith("/");
        if (directory) value = value.substring(0, value.length() - 1);
        List<String> levels = new ArrayList<>();
        StringBuilder level = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c != '!') {
                level.append(c);
            } else if (i + 1 < value.length() && value.charAt(i + 1) == '!') {
                level.append('!');
                i++;
            } else if (i + 1 < value.length() && value.charAt(i + 1) == '/') {
                levels.add(level.toString());
                level.setLength(0);
                i++;
            } else throw Failure.usage("literal ! in a pattern must be written !!");
        }
        levels.add(level.toString());
        for (String l : levels) {
            if (l.isEmpty()) throw Failure.usage("empty exclusion boundary");
            for (String p : l.split("/", -1)) {
                if (p.isEmpty() || p.equals(".") || p.equals("..") || p.contains("**") && !p.equals("**"))
                    throw Failure.usage("invalid exclusion component");
            }
        }
        return new Pattern(List.copyOf(levels), directory);
    }

    static boolean excluded(Options options, List<String> archives, String path, boolean directory) {
        for (Pattern pattern : options.excludes) {
            if (pattern.levels.size() != archives.size() + 1) continue;
            boolean match = true;
            for (int i = 0; i < archives.size(); i++)
                match &= matchPath(pattern.levels.get(i), archives.get(i));
            if (!match) continue;
            String last = pattern.levels.getLast();
            String[] components = path.split("/");
            for (int end = 1; end <= components.length; end++) {
                boolean isDir = end < components.length || directory;
                if ((!pattern.directory || isDir)
                        && matchPath(last, String.join("/", java.util.Arrays.copyOf(components, end))))
                    return true;
            }
        }
        return false;
    }

    private static boolean matchPath(String pattern, String path) {
        String[] p = pattern.split("/");
        String[] s = path.split("/");
        boolean[] state = new boolean[s.length + 1];
        state[0] = true;
        for (String part : p) {
            boolean[] next = new boolean[s.length + 1];
            if (part.equals("**")) {
                boolean seen = false;
                for (int j = 0; j <= s.length; j++) next[j] = seen |= state[j];
            } else {
                for (int j = 0; j < s.length; j++)
                    if (state[j] && component(part, s[j])) next[j + 1] = true;
            }
            state = next;
        }
        return state[s.length];
    }

    private static boolean component(String pattern, String value) {
        int[] p = pattern.codePoints().toArray();
        int[] v = value.codePoints().toArray();
        int i = 0, j = 0, star = -1, mark = -1;
        while (j < v.length) {
            if (i < p.length && p[i] == '*') { star = i++; mark = j; }
            else if (i < p.length && p[i] == v[j]) { i++; j++; }
            else if (star >= 0) { i = star + 1; j = ++mark; }
            else return false;
        }
        while (i < p.length && p[i] == '*') i++;
        return i == p.length;
    }
}
