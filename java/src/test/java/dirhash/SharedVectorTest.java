package dirhash;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class SharedVectorTest {
    @Test
    void sharedLogicalTreesMatchEveryIndependentExpectedHash() throws Exception {
        String configured = System.getenv("DIRHASH_TEST_VECTORS");
        Path resource = configured == null ? Path.of("..", "tests", "vectors") : Path.of(configured);
        Map<String, List<String[]>> expected = new LinkedHashMap<>();
        for (String[] row : rows(resource.resolve("hashes.tsv"), 4))
            expected.computeIfAbsent(row[0], ignored -> new ArrayList<>()).add(row);
        assertEquals(6, expected.size());
        Map<String, List<String[]>> trees = new HashMap<>();
        for (String[] row : rows(resource.resolve("trees.tsv"), 5)) {
            assertTrue(expected.containsKey(row[0]), row[0]);
            trees.computeIfAbsent(row[0], ignored -> new ArrayList<>()).add(row);
        }
        int checked = 0;
        for (var fixture : expected.entrySet()) {
            List<String> arguments = new ArrayList<>();
            fixture.getValue().forEach(row -> arguments.add("--" + row[1] + ":" + row[2]));
            arguments.add("shared-" + fixture.getKey());
            Options options = Options.parse(arguments.toArray(String[]::new));
            Engine engine = new Engine(options);
            Model.Tree tree = new Model.Tree();
            tree.goDirectories = false;
            for (String[] row : trees.getOrDefault(fixture.getKey(), List.of())) {
                Model.Type type = switch (row[2]) {
                    case "file" -> Model.Type.REGULAR;
                    case "dir" -> Model.Type.DIRECTORY;
                    case "link" -> Model.Type.SYMLINK;
                    default -> throw new AssertionError("unknown shared vector kind: " + row[2]);
                };
                Model.Node node = new Model.Node(row[1], type);
                node.mode = Integer.parseInt(row[3], 8);
                node.included = true;
                node.explicit = true;
                node.manifestName = Bytes.utf8(node.path);
                node.storedName = node.path;
                byte[] bytes = HexFormat.of().parseHex(row[4]);
                node.size = bytes.length;
                node.opener = () -> new ByteArrayInputStream(bytes);
                if (type == Model.Type.SYMLINK) node.target = bytes;
                if (type != Model.Type.DIRECTORY) {
                    Payload payload = new Payload(node.opener.open(), engine, node.size, false, true);
                    Engine.drain(payload);
                    payload.finish(node, false);
                }
                tree.add(node);
            }
            tree.nodes.values().forEach(node -> node.included = true);
            Model.Root root = new Model.Root(List.of(), "directory", tree);
            Map<String, String> actual = new HashMap<>();
            for (Model.Result result : Hashing.results(options, root))
                assertNull(actual.put(result.scheme() + ":" + result.digestAlgorithm(), result.value()));
            assertEquals(fixture.getValue().size(), actual.size());
            for (String[] row : fixture.getValue()) {
                assertEquals(row[3], actual.get(row[1] + ":" + row[2]),
                        row[0] + ":" + row[1] + ":" + row[2]);
                checked++;
            }
        }
        assertEquals(168, checked);
    }

    private static List<String[]> rows(Path path, int columns) throws Exception {
        List<String[]> rows = new ArrayList<>();
        for (String line : Files.readAllLines(path, StandardCharsets.UTF_8)) {
            if (line.isEmpty() || line.startsWith("#")) continue;
            String[] row = line.split("\t", -1);
            assertEquals(columns, row.length, path + ": " + line);
            rows.add(row);
        }
        return rows;
    }
}
