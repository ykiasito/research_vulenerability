package com.vulncheck.app.repository;

import static org.assertj.core.api.Assertions.assertThat;

import com.vulncheck.app.entity.IdentifiedProduct;
import com.vulncheck.app.entity.ResearchJob;
import com.vulncheck.app.entity.ResearchJobItem;
import com.vulncheck.app.entity.User;
import java.math.BigDecimal;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;

/**
 * Exercises {@link IdentifiedProductRepository} against a real Postgres instance, specifically
 * V30's new measurement-only {@code cpe_candidate_count}/{@code cpe_candidate_variant_derived}
 * columns (docs/spec/task-backlog.md item 16) — confirms they round-trip through the entity/JPA
 * mapping correctly, both when set and when left {@code null} (the case for every row written
 * before V30 and every row whose {@link IdentifiedProduct#getCpe()} is {@code null}).
 * {@code @DataJpaTest} wraps each test in a transaction rolled back afterward, so nothing written
 * here is persisted past the test run.
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
class IdentifiedProductRepositoryTest {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private ResearchJobRepository researchJobRepository;
    @Autowired
    private ResearchJobItemRepository researchJobItemRepository;
    @Autowired
    private IdentifiedProductRepository identifiedProductRepository;

    private Long newJobItem() {
        User user = new User();
        user.setEmail("identified-product-repo-test-" + System.nanoTime() + "@example.com");
        user.setPasswordHash("hash");
        user = userRepository.save(user);

        ResearchJob job = new ResearchJob();
        job.setUserId(user.getId());
        job.setCsvFilename("test.csv");
        job.setStatus(ResearchJob.STATUS_COMPLETED);
        job = researchJobRepository.save(job);

        ResearchJobItem item = new ResearchJobItem();
        item.setJobId(job.getId());
        item.setProductName("widget");
        item.setVersion("1.0.0");
        item.setUsageText("test");
        item.setStatus(ResearchJobItem.STATUS_IDENTIFIED);
        item = researchJobItemRepository.save(item);
        return item.getId();
    }

    @Test
    void cpeCandidateProvenanceFieldsRoundTripWhenSet() {
        IdentifiedProduct product = new IdentifiedProduct();
        product.setJobItemId(newJobItem());
        product.setMethod(IdentifiedProduct.METHOD_STATIC);
        product.setCpe("cpe:2.3:a:acme:widget:1.0.0:*:*:*:*:*:*:*");
        product.setConfidence(new BigDecimal("0.6"));
        product.setCpeCandidateCount(3);
        product.setCpeCandidateVariantDerived(true);

        Long savedId = identifiedProductRepository.save(product).getId();
        IdentifiedProduct reloaded = identifiedProductRepository.findById(savedId).orElseThrow();

        assertThat(reloaded.getCpeCandidateCount()).isEqualTo(3);
        assertThat(reloaded.getCpeCandidateVariantDerived()).isTrue();
    }

    @Test
    void cpeCandidateProvenanceFieldsDefaultToNullWhenNeverSet() {
        // The pre-V30-migration case (and any row whose cpe is null, e.g. a registry-only match) —
        // these columns must stay null rather than defaulting to 0/false.
        IdentifiedProduct product = new IdentifiedProduct();
        product.setJobItemId(newJobItem());
        product.setMethod(IdentifiedProduct.METHOD_STATIC);
        product.setConfidence(new BigDecimal("0.95"));

        Long savedId = identifiedProductRepository.save(product).getId();
        IdentifiedProduct reloaded = identifiedProductRepository.findById(savedId).orElseThrow();

        assertThat(reloaded.getCpeCandidateCount()).isNull();
        assertThat(reloaded.getCpeCandidateVariantDerived()).isNull();
    }

    /** Closed-mode backlog item 183 — {@code RegistryMirrorSyncService}'s observed-name seed
     *  source query. */
    @Test
    void findDistinctPackageNamesByEcosystemReturnsOnlyDistinctNonNullNamesForThatEcosystem() {
        IdentifiedProduct npmLodash = new IdentifiedProduct();
        npmLodash.setJobItemId(newJobItem());
        npmLodash.setMethod(IdentifiedProduct.METHOD_STATIC);
        npmLodash.setEcosystem("npm");
        npmLodash.setPackageName("lodash");
        identifiedProductRepository.save(npmLodash);

        // A second row for the same (ecosystem, package_name) — must be folded into one entry.
        IdentifiedProduct npmLodashAgain = new IdentifiedProduct();
        npmLodashAgain.setJobItemId(newJobItem());
        npmLodashAgain.setMethod(IdentifiedProduct.METHOD_STATIC);
        npmLodashAgain.setEcosystem("npm");
        npmLodashAgain.setPackageName("lodash");
        identifiedProductRepository.save(npmLodashAgain);

        IdentifiedProduct npmReact = new IdentifiedProduct();
        npmReact.setJobItemId(newJobItem());
        npmReact.setMethod(IdentifiedProduct.METHOD_STATIC);
        npmReact.setEcosystem("npm");
        npmReact.setPackageName("react");
        identifiedProductRepository.save(npmReact);

        // A different ecosystem — must not leak into the npm result.
        IdentifiedProduct pypiRequests = new IdentifiedProduct();
        pypiRequests.setJobItemId(newJobItem());
        pypiRequests.setMethod(IdentifiedProduct.METHOD_STATIC);
        pypiRequests.setEcosystem("pypi");
        pypiRequests.setPackageName("requests");
        identifiedProductRepository.save(pypiRequests);

        // A CPE-only match (no registry ecosystem/package name at all) — must not produce a null entry.
        IdentifiedProduct cpeOnly = new IdentifiedProduct();
        cpeOnly.setJobItemId(newJobItem());
        cpeOnly.setMethod(IdentifiedProduct.METHOD_STATIC);
        cpeOnly.setCpe("cpe:2.3:a:acme:widget:1.0.0:*:*:*:*:*:*:*");
        identifiedProductRepository.save(cpeOnly);

        assertThat(identifiedProductRepository.findDistinctPackageNamesByEcosystem("npm"))
                .containsExactlyInAnyOrder("lodash", "react");
        assertThat(identifiedProductRepository.findDistinctPackageNamesByEcosystem("pypi"))
                .containsExactly("requests");
        assertThat(identifiedProductRepository.findDistinctPackageNamesByEcosystem("go")).isEmpty();
    }
}
