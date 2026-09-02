package com.vulncheck.app.repository;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.context.annotation.Import;

/**
 * Exercises {@link RegistryMirrorSeedNameRepositoryImpl} against a real Postgres instance (closed-
 * mode backlog item 185) — same {@code @DataJpaTest} + {@code @AutoConfigureTestDatabase(Replace.NONE)}
 * + {@code @Import} shape as {@code RegistryPackageMirrorRepositoryImplTest} (see that class's own
 * javadoc for why {@code @Import} is needed here: this table has no JPA entity, so {@code
 * @DataJpaTest}'s repository auto-detection never picks up this plain-interface implementation on
 * its own). Each test runs in a transaction rolled back afterward.
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import(RegistryMirrorSeedNameRepositoryImpl.class)
class RegistryMirrorSeedNameRepositoryImplTest {

    @Autowired
    private RegistryMirrorSeedNameRepository registryMirrorSeedNameRepository;

    @Test
    void findDistinctPackageNamesIsEmptyWhenNothingHasBeenUploadedYet() {
        assertThat(registryMirrorSeedNameRepository.findDistinctPackageNames("npm")).isEmpty();
    }

    @Test
    void insertBatchThenFindDistinctPackageNamesRoundTrips() {
        registryMirrorSeedNameRepository.insertBatch("npm", List.of("left-pad", "is-odd"));

        assertThat(registryMirrorSeedNameRepository.findDistinctPackageNames("npm"))
                .containsExactlyInAnyOrder("left-pad", "is-odd");
    }

    @Test
    void insertBatchIsScopedToItsOwnEcosystem() {
        registryMirrorSeedNameRepository.insertBatch("npm", List.of("left-pad"));
        registryMirrorSeedNameRepository.insertBatch("crates.io", List.of("serde"));

        assertThat(registryMirrorSeedNameRepository.findDistinctPackageNames("npm")).containsExactly("left-pad");
        assertThat(registryMirrorSeedNameRepository.findDistinctPackageNames("crates.io")).containsExactly("serde");
    }

    @Test
    void insertBatchIsIdempotentForAnAlreadyPresentName() {
        registryMirrorSeedNameRepository.insertBatch("npm", List.of("left-pad"));

        // Re-uploading the same name (e.g. a second admin submission overlapping a prior one) must
        // not throw ON CONFLICT-target unique-index violations and must not duplicate the row.
        registryMirrorSeedNameRepository.insertBatch("npm", List.of("left-pad", "is-odd"));

        assertThat(registryMirrorSeedNameRepository.findDistinctPackageNames("npm"))
                .containsExactlyInAnyOrder("left-pad", "is-odd");
    }

    @Test
    void insertBatchIsANoOpForAnEmptyList() {
        registryMirrorSeedNameRepository.insertBatch("npm", List.of());

        assertThat(registryMirrorSeedNameRepository.findDistinctPackageNames("npm")).isEmpty();
    }
}
