package dirhash;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

final class Options {
    static final List<String> SCHEMES = List.of("h1", "h1-go", "gittree", "swhid", "nar", "plain");
    static final List<String> DIGESTS = List.of("sha1", "sha256", "sha512", "blake2b-256",
            "blake2b-512", "blake3", "sha3-256", "sha3-512");
    record Selection(String scheme, String digest) {}

    final List<Selection> selections = new ArrayList<>();
    final List<Exclusions.Pattern> excludes = new ArrayList<>();
    boolean strict;
    boolean recurse;
    boolean stripSet;
    int strip;
    String format = "text";
    String input;
    long maxDepth = 16;
    long maxEntries = 1_000_000;
    long maxExpanded = 107_374_182_400L;
    long maxDownload = 10_737_418_240L;

    static Options parse(String[] args) {
        Options o = new Options();
        Set<String> singles = new HashSet<>();
        boolean ended = false;
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if (!ended && arg.equals("--")) {
                ended = true;
                continue;
            }
            if (!ended && arg.startsWith("-")) {
                if (!arg.startsWith("--")) throw Failure.usage("unknown option");
                String name = arg.substring(2);
                int colon = name.indexOf(':');
                String scheme = colon < 0 ? name : name.substring(0, colon);
                if (SCHEMES.contains(scheme)) {
                    String digest = colon < 0 ? (scheme.equals("gittree") || scheme.equals("swhid")
                            ? "sha1" : "sha256") : name.substring(colon + 1);
                    if (!DIGESTS.contains(digest)) throw Failure.usage("unknown digest");
                    Selection selection = new Selection(scheme, digest);
                    if (!o.selections.contains(selection)) o.selections.add(selection);
                    continue;
                }
                int eq = name.indexOf('=');
                String key = eq < 0 ? name : name.substring(0, eq);
                if (key.equals("strict") || key.equals("recurse")) {
                    if (eq >= 0 || !singles.add(key)) throw Failure.usage("repeated or malformed flag");
                    if (key.equals("strict")) o.strict = true;
                    else o.recurse = true;
                    continue;
                }
                if (!List.of("exclude", "strip-components", "format", "max-depth", "max-entries",
                        "max-expanded-bytes", "max-download-bytes").contains(key))
                    throw Failure.usage("unknown option");
                if (!key.equals("exclude") && !singles.add(key))
                    throw Failure.usage("repeated option " + key);
                String value;
                if (eq >= 0) value = name.substring(eq + 1);
                else {
                    if (++i == args.length) throw Failure.usage("missing option value");
                    value = args[i];
                }
                switch (key) {
                    case "exclude" -> o.excludes.add(Exclusions.compile(value));
                    case "format" -> {
                        if (!List.of("text", "json", "jsonl").contains(value))
                            throw Failure.usage("unknown output format");
                        o.format = value;
                    }
                    case "strip-components" -> {
                        long n = number(value, false);
                        if (n > Integer.MAX_VALUE) throw Failure.usage("strip-components is too large");
                        o.strip = (int) n;
                        o.stripSet = true;
                    }
                    case "max-depth" -> o.maxDepth = number(value, true);
                    case "max-entries" -> o.maxEntries = number(value, true);
                    case "max-expanded-bytes" -> o.maxExpanded = number(value, true);
                    case "max-download-bytes" -> o.maxDownload = number(value, true);
                    default -> throw new AssertionError();
                }
            } else {
                if (o.input != null) throw Failure.usage("exactly one input is required");
                o.input = arg;
            }
        }
        if (o.input == null || o.selections.isEmpty())
            throw Failure.usage("one input and at least one hash selection are required");
        o.selections.sort((a, b) -> {
            int c = Integer.compare(SCHEMES.indexOf(a.scheme), SCHEMES.indexOf(b.scheme));
            return c != 0 ? c : Integer.compare(DIGESTS.indexOf(a.digest), DIGESTS.indexOf(b.digest));
        });
        return o;
    }

    private static long number(String value, boolean unlimited) {
        if (unlimited && value.equals("unlimited")) return Long.MAX_VALUE;
        if (!value.matches("[0-9]+")) throw Failure.usage("limit must be a non-negative decimal integer");
        try {
            return Long.parseLong(value);
        } catch (NumberFormatException e) {
            throw Failure.usage("numeric option overflow");
        }
    }

    boolean has(String scheme) {
        return selections.stream().anyMatch(s -> s.scheme.equals(scheme));
    }

    boolean discovers() {
        return strict || recurse;
    }
}
