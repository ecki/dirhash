import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.zip.ZipFile;

/** Checks the packaged bytes, not just the shade configuration. */
class VerifyLicenses {
    public static void main(String[] args) throws Exception {
        try (var jar = new ZipFile(args[0])) {
            require(jar, "META-INF/LICENSE", Files.readAllBytes(Path.of(args[3])));
            require(jar, "META-INF/NOTICE", Files.readAllBytes(Path.of(args[4])));
            var names = new HashSet<String>();
            for (var entry : jar.stream().toList()) {
                if (!names.add(entry.getName())) {
                    throw new IOException("Duplicate JAR resource: " + entry.getName());
                }
                var name = entry.getName();
                if (name.matches("META-INF/[^/]+\\.(SF|RSA|DSA)")
                        || name.startsWith("tests/") || name.startsWith("test-vectors/")
                        || name.startsWith("org/junit/")) {
                    throw new IOException("Unexpected runtime resource: " + name);
                }
            }
            try (var files = Files.walk(Path.of(args[2]))) {
                for (var file : files.filter(Files::isRegularFile).toList()) {
                    var relative = Path.of(args[2]).relativize(file).toString().replace('\\', '/');
                    require(jar, "META-INF/licenses/" + relative, Files.readAllBytes(file));
                }
            }
            int dependencies = 0;
            try (var files = Files.list(Path.of(args[1]))) {
                for (var file : files.filter(p -> p.toString().endsWith(".jar")).toList()) {
                    dependencies++;
                    String artifact = file.getFileName().toString().replaceFirst("\\.jar$", "");
                    boolean covered = false;
                    try (var dependency = new ZipFile(file.toFile())) {
                        for (var entry : dependency.stream().filter(e -> !e.isDirectory()).toList()) {
                            if (entry.getName().startsWith("META-INF/services/")) {
                                var merged = jar.getEntry(entry.getName());
                                if (merged == null) {
                                    throw new IOException("Service descriptor lost: " + entry.getName());
                                }
                                String providers = new String(jar.getInputStream(merged).readAllBytes(), StandardCharsets.UTF_8);
                                String original = new String(dependency.getInputStream(entry).readAllBytes(), StandardCharsets.UTF_8);
                                for (String line : original.lines().toList()) {
                                    String provider = line.split("#", 2)[0].strip();
                                    if (!provider.isEmpty() && providers.lines().noneMatch(p -> p.strip().equals(provider))) {
                                        throw new IOException("Service provider lost: " + provider);
                                    }
                                }
                            }
                            if (!legal(entry.getName())) {
                                continue;
                            }
                            byte[] original = dependency.getInputStream(entry).readAllBytes();
                            boolean preserved = false;
                            for (var candidate : jar.stream().filter(e -> !e.isDirectory()
                                    && e.getName().startsWith("META-INF/licenses/")
                                    && e.getName().contains(artifact)
                                    && e.getName().endsWith("/" + entry.getName())).toList()) {
                                if (Arrays.equals(original, jar.getInputStream(candidate).readAllBytes())) {
                                    preserved = true;
                                }
                            }
                            if (!preserved) {
                                throw new IOException("Dependency notice lost: " + artifact + "/" + entry.getName());
                            }
                            covered = true;
                        }
                    }
                    if (!covered) {
                        String prefix = "META-INF/licenses/" + artifact + "/";
                        covered = jar.stream().anyMatch(e -> e.getName().startsWith(prefix)
                                && !e.isDirectory() && legal(e.getName()));
                    }
                    if (!covered) {
                        throw new IOException("No license for runtime dependency: " + artifact);
                    }
                }
            }
            if (dependencies == 0) {
                throw new IOException("No runtime dependencies found for license verification");
            }
            if (jar.getEntry("META-INF/services/java.security.Provider") == null) {
                throw new IOException("Shaded service descriptor lost");
            }
            System.out.println("Verified project legal bytes and notices for " + dependencies + " runtime dependencies.");
        }
    }

    private static boolean legal(String path) {
        String name = path.substring(path.lastIndexOf('/') + 1).toUpperCase(Locale.ROOT);
        return !name.endsWith(".CLASS")
                && name.matches("(LICENSE|NOTICE|COPYING|COPYRIGHT|PATENTS)([._-].*)?");
    }

    private static void require(ZipFile jar, String name, byte[] expected) throws IOException {
        var entry = jar.getEntry(name);
        if (entry == null || !Arrays.equals(expected, jar.getInputStream(entry).readAllBytes())) {
            throw new IOException("Missing or changed legal resource: " + name);
        }
    }
}
