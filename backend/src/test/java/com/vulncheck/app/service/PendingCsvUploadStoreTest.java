package com.vulncheck.app.service;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class PendingCsvUploadStoreTest {

    private final PendingCsvUploadStore store = new PendingCsvUploadStore();

    @Test
    void storesAndRetrievesByToken() {
        byte[] content = "a,b,c".getBytes(StandardCharsets.UTF_8);
        String token = store.store(content, "products.csv", true);

        Optional<PendingCsvUploadStore.PendingUpload> result = store.get(token);

        assertThat(result).isPresent();
        assertThat(result.get().content()).isEqualTo(content);
        assertThat(result.get().filename()).isEqualTo("products.csv");
        assertThat(result.get().bundledComponentCheckEnabled()).isTrue();
    }

    @Test
    void getIsNonDestructiveSoAFailedMappingSubmissionCanBeRetried() {
        String token = store.store("x".getBytes(StandardCharsets.UTF_8), "x.csv", false);

        store.get(token);
        Optional<PendingCsvUploadStore.PendingUpload> secondRead = store.get(token);

        assertThat(secondRead).isPresent();
    }

    @Test
    void removeActuallyDeletesTheEntry() {
        String token = store.store("x".getBytes(StandardCharsets.UTF_8), "x.csv", false);

        store.remove(token);

        assertThat(store.get(token)).isEmpty();
    }

    @Test
    void unknownTokenReturnsEmpty() {
        assertThat(store.get("does-not-exist")).isEmpty();
    }
}
