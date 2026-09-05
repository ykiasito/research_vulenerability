package com.vulncheck.app;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/**
 * Backlog item 321: {@code backend/src/test/resources/} and {@code test-data/} both hold copies of
 * the same fixture CSVs on purpose (the former is what ships on the test classpath and is read by
 * {@code *JobCreator}/{@code *RecallTest} classes; the latter is what the {@code test-data/*.py}
 * measurement/verification scripts read directly off disk). Nothing enforced that the two copies of
 * a same-named file stayed byte-identical — item 320 found a real drift (golden-300.csv's
 * Blender/Rufus rows carried opposite {@code expected_outcome} ground truth in each copy) that had
 * gone unnoticed. This test makes that class of drift impossible to merge unnoticed again: for
 * every filename that exists in both directories, it asserts the two copies are byte-for-byte
 * identical.
 *
 * <p><b>Locating {@code test-data/}:</b> this directory lives at the repo root, one level above the
 * {@code backend/} Maven module, so it is not on the test classpath and is not visible to a {@code
 * mvn test} run whose Docker container only has {@code backend/} mounted (the single-directory
 * mount shown as the default example in this project's operating notes). To find it, this test
 * walks upward from the JVM's working directory looking for a directory that has both a {@code
 * test-data} child and a {@code backend/src/test/resources} child — true whether Maven is invoked
 * from the repo root or from {@code backend/} itself. If no such ancestor exists (i.e. the running
 * container was started with only {@code backend/} mounted), the test fails loudly with a message
 * explaining the mount needs widening, rather than silently skipping and losing its guarantee.
 */
class FixtureDirectoryParityTest {

    @Test
    void duplicatedFixtureFilesAreByteIdenticalAcrossBothDirectories() throws IOException {
        Path repoRoot = findRepoRoot();
        assertThat(repoRoot)
                .withFailMessage(
                        "Could not locate the repo root (an ancestor directory containing both "
                                + "'test-data' and 'backend/src/test/resources') from the JVM working "
                                + "directory '%s'. This test needs test-data/ to be visible on disk -- if "
                                + "you're running via 'docker run -v <repo>/backend:/build', re-run with the "
                                + "full repo mounted instead (e.g. '-v <repo>:/build -w /build/backend'), not "
                                + "just the backend/ subtree.",
                        Paths.get("").toAbsolutePath())
                .isNotNull();

        Path resourcesDir = repoRoot.resolve("backend/src/test/resources");
        Path testDataDir = repoRoot.resolve("test-data");

        Set<String> resourcesFiles = listRegularFileNames(resourcesDir);
        Set<String> testDataFiles = listRegularFileNames(testDataDir);

        Set<String> commonNames = new TreeSet<>(resourcesFiles);
        commonNames.retainAll(testDataFiles);
        assertThat(commonNames).isNotEmpty();

        List<String> mismatches = new ArrayList<>();
        for (String name : commonNames) {
            Path a = resourcesDir.resolve(name);
            Path b = testDataDir.resolve(name);
            if (!filesAreByteIdentical(a, b)) {
                mismatches.add(name);
            }
        }

        if (!mismatches.isEmpty()) {
            fail("The following fixture file(s) exist under both backend/src/test/resources/ and "
                    + "test-data/ but are NOT byte-identical (one copy was edited without the other): "
                    + mismatches.stream().sorted().collect(Collectors.joining(", ")));
        }
    }

    private static boolean filesAreByteIdentical(Path a, Path b) throws IOException {
        return Arrays.equals(Files.readAllBytes(a), Files.readAllBytes(b));
    }

    private static Set<String> listRegularFileNames(Path dir) throws IOException {
        try (Stream<Path> entries = Files.list(dir)) {
            return entries.filter(Files::isRegularFile)
                    .map(p -> p.getFileName().toString())
                    .collect(Collectors.toCollection(TreeSet::new));
        }
    }

    private static Path findRepoRoot() {
        Path dir = Paths.get("").toAbsolutePath();
        while (dir != null) {
            if (Files.isDirectory(dir.resolve("test-data"))
                    && Files.isDirectory(dir.resolve("backend/src/test/resources"))) {
                return dir;
            }
            dir = dir.getParent();
        }
        return null;
    }
}
