package dirhash;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class MainTest {
    @Test
    void help() {
        assertRun(new String[] {"--help"}, 0, Main.HELP, "");
    }

    @Test
    void version() {
        assertRun(new String[] {"--version"}, 0, Main.VERSION, "");
    }

    @Test
    void missingArguments() {
        assertRun(new String[0], 2, "", "USAGE: one input and at least one hash selection are required\n" + Main.QUICK_USAGE);
    }

    @Test
    void invalidDigestFailsBeforeIO() {
        assertRun(new String[] {"--h1:no-such-digest", "missing"}, 2, "", "USAGE: unknown digest\n" + Main.QUICK_USAGE);
    }

    @Test
    void readableTextPath() {
        assertEquals(".\\folder\\a \"quoted\"\\t\\n\\u0001.zip",
                Bytes.textPath(".\\folder\\a \"quoted\"\t\n\u0001.zip"));
    }

    @Test
    void diagnosticsKeepFilesystemBackslashesReadableAndEscapeControls() {
        String windowsPath = "C:\\Users\\alice\\missing.zip";
        assertRun(new String[] {"--h1", windowsPath}, 4, "",
                "IO_ERROR: " + windowsPath + ": input/output operation failed\n");
        String controlledPath = "C:\\vault\\line\nnext.zip";
        assertRun(new String[] {"--h1", controlledPath}, 4, "",
                "IO_ERROR: C:\\vault\\line\\u000anext.zip: input/output operation failed\n");
    }

    @Test
    void outputFailure() {
        var errors = new ByteArrayOutputStream();
        var broken = new PrintStream(new OutputStream() {
            @Override
            public void write(int value) throws IOException {
                throw new IOException("test output failure");
            }
        });
        int status = Main.run(new String[] {"--help"}, broken,
                new PrintStream(errors, true, StandardCharsets.UTF_8));
        assertEquals(4, status);
        assertEquals("IO_ERROR: failed to write CLI output.\n",
                errors.toString(StandardCharsets.UTF_8));
    }

    private static void assertRun(String[] args, int status, String stdout, String stderr) {
        var output = new ByteArrayOutputStream();
        var errors = new ByteArrayOutputStream();
        int actual = Main.run(args,
                new PrintStream(output, true, StandardCharsets.UTF_8),
                new PrintStream(errors, true, StandardCharsets.UTF_8));
        assertEquals(status, actual);
        assertEquals(stdout, output.toString(StandardCharsets.UTF_8));
        assertEquals(stderr, errors.toString(StandardCharsets.UTF_8));
    }
}
