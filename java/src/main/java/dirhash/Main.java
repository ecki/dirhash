package dirhash;

import java.io.PrintStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

public final class Main {
    static final String VERSION = "dirhash 0.1.0-SNAPSHOT\n";
    static final String USAGE = "Usage: dirhash [options] INPUT\n";
    static final String QUICK_USAGE = USAGE + """
            Select at least one hash: --h1 --h1-go --gittree --swhid --nar --plain
            Examples:
              dirhash --h1 .
              java -jar dirhash.jar --h1-go library.jar
              java -jar dirhash.jar --h1 --gittree --strict archive.zip
            Use --help for all options.
            """;
    static final String HELP = """
            Usage: dirhash [options] INPUT

              --h1[:DIGEST] --h1-go[:DIGEST] --gittree[:DIGEST]
              --swhid[:DIGEST] --nar[:DIGEST] --plain[:DIGEST]
                                              Select one or more hashes
              --strict --recurse              Validate portable names / discover archives
              --exclude=PATTERN               Anchored exclusions; !/ archive boundary, !! literal !
              --strip-components=N            Strip original archive prefixes only
              --format=text|json|jsonl         Atomic UTF-8/LF output (default text)
              --max-depth=N                   Archive depth (default 16)
              --max-entries=N                 Entry budget (default 1000000)
              --max-expanded-bytes=N          Expansion budget (default 107374182400)
              --max-download-bytes=N          HTTP body budget (default 10737418240)
              --help --version                No input or selection required

            Limits also accept unlimited. Value options accept =VALUE or a following argument.
            Digests: sha1, sha256, sha512, blake2b-256, blake2b-512, blake3, sha3-256, sha3-512.
            Inputs: directory, ZIP/ZIP64, TAR (PAX/GNU/sparse), TAR.GZ, HTTP(S) archive.
            --plain hashes exact archive bytes; recursive records hash included archive payloads.
            ZIP methods: Stored (0), DEFLATE (8), Deflate64 (9), BZIP2 (12),
            Zstandard (20,93), XZ (95). Encryption, LZMA (14), PPMd (98) unsupported.
            Nested archives use seekable views, up to 10 MB aggregate memory, then private budgeted disk spools.
            SHA-1 is provided for interoperability, not modern collision resistance.
            """ + "\n" + QUICK_USAGE;

    private Main() {}

    public static void main(String[] args) {
        System.exit(run(args, new PrintStream(System.out, true, StandardCharsets.UTF_8),
                new PrintStream(System.err, true, StandardCharsets.UTF_8)));
    }

    static int run(String[] args, PrintStream out, PrintStream err) {
        String text;
        List<String> warnings = List.of();
        if (args.length == 1 && args[0].equals("--help")) {
            text = HELP;
        } else if (args.length == 1 && args[0].equals("--version")) {
            text = VERSION;
        } else {
            Engine engine = null;
            try {
                Options options = Options.parse(args);
                engine = new Engine(options);
                List<Model.Result> results = engine.run();
                warnings = engine.warnings();
                StringBuilder b = new StringBuilder();
                if (options.format.equals("json")) {
                    b.append("{\"schemaVersion\":1,\"results\":[");
                    for (int i = 0; i < results.size(); i++) {
                        if (i != 0) b.append(',');
                        b.append(results.get(i).json());
                    }
                    b.append("]}\n");
                } else for (Model.Result record : results) {
                    if (options.format.equals("jsonl")) b.append(record.json());
                    else {
                        b.append(record.scheme());
                        String defaultDigest = record.scheme().equals("gittree") || record.scheme().equals("swhid")
                                ? "sha1" : "sha256";
                        if (!record.digestAlgorithm().equals(defaultDigest))
                            b.append(':').append(record.digestAlgorithm());
                        b.append('\t').append(record.value()).append('\t').append(Bytes.textPath(record.path()));
                    }
                    b.append('\n');
                }
                text = b.toString();
            } catch (Failure e) {
                String failureLocation = safeLocation(engine, e.location);
                err.print(e.code + ": " + (e.status == 2 ? "" : failureLocation + ": ")
                        + Bytes.diagnostic(e.getMessage()) + "\n");
                if (e.status == 2) err.print(QUICK_USAGE);
                return e.status;
            } catch (IOException | SecurityException e) {
                err.print("IO_ERROR: " + safeLocation(engine) + ": input/output operation failed\n");
                return 4;
            } catch (OutOfMemoryError | StackOverflowError e) {
                err.print("LIMIT_EXCEEDED: " + safeLocation(engine) + ": allocation or representation limit\n");
                return 1;
            } catch (RuntimeException e) {
                err.print("IO_ERROR: " + safeLocation(engine) + ": runtime computation failed\n");
                return 4;
            }
        }
        out.print(text);
        if (out.checkError()) {
            err.print("IO_ERROR: failed to write CLI output.\n");
            return 4;
        }
        for (String warning : warnings) err.print(warning);
        return 0;
    }

    private static String safeLocation(Engine engine) {
        return safeLocation(engine, null);
    }

    private static String safeLocation(Engine engine, String requested) {
        if (engine == null) return Bytes.diagnostic(requested == null ? "input" : requested);
        String location = requested == null ? engine.location : requested;
        if (engine.options.input.matches("(?i)^https?://.*")) {
            try {
                var uri = java.net.URI.create(engine.options.input);
                String sanitized = uri.getScheme() + "://" + uri.getHost()
                        + (uri.getPort() < 0 ? "" : ":" + uri.getPort())
                        + (uri.getPath() == null ? "" : uri.getPath());
                if (!location.equals(engine.options.input)) {
                    String prefix = engine.options.input.replace("!", "!!");
                    if (location.startsWith(prefix)) sanitized += location.substring(prefix.length());
                }
                location = sanitized;
            } catch (IllegalArgumentException e) { location = "URL"; }
        }
        return Bytes.diagnostic(location);
    }
}
