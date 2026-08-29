package com.vulncheck.app.service.nvd;

import static org.assertj.core.api.Assertions.assertThat;

import com.vulncheck.app.entity.CpeDictionaryEntry;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class CpeNameVariantCacheTest {

    private CpeDictionaryEntry entry(String cpeString) {
        CpeDictionaryEntry entry = new CpeDictionaryEntry();
        entry.setCpeString(cpeString);
        entry.setLastSyncedAt(OffsetDateTime.now());
        return entry;
    }

    @Test
    void repeatedLookupsForTheSameVendorAndProductNameOnlyComputeOnce() {
        // This project's CSVs repeat the same product name across many version-duplicate rows
        // (see RegistryLookupCache's own javadoc for the measured repeat rate) — a job that pays
        // for the name-variant search once for "VS Code" should not pay for it again on every
        // other row for the same product.
        CpeNameVariantCache cache = new CpeNameVariantCache();
        AtomicInteger calls = new AtomicInteger();
        List<CpeDictionaryEntry> result = List.of(entry("cpe:2.3:a:microsoft:visual_studio_code:1.0.0:*:*:*:*:*:*:*"));

        List<CpeDictionaryEntry> first = cache.get("Microsoft", "VS Code", () -> {
            calls.incrementAndGet();
            return result;
        });
        List<CpeDictionaryEntry> second = cache.get("Microsoft", "VS Code", () -> {
            calls.incrementAndGet();
            return result;
        });

        assertThat(calls.get()).isEqualTo(1);
        assertThat(first).isEqualTo(result);
        assertThat(second).isEqualTo(result);
    }

    @Test
    void anEmptyResultIsAlsoCachedNotJustAHit() {
        // Negative results are the common case here (this search only ever runs when the literal
        // dictionary search already failed), and re-computing "still nothing" on every duplicate
        // row would be exactly the pattern this cache exists to avoid.
        CpeNameVariantCache cache = new CpeNameVariantCache();
        AtomicInteger calls = new AtomicInteger();

        cache.get("Pete Batard", "Rufus", () -> {
            calls.incrementAndGet();
            return List.of();
        });
        cache.get("Pete Batard", "Rufus", () -> {
            calls.incrementAndGet();
            return List.of();
        });

        assertThat(calls.get()).isEqualTo(1);
    }

    @Test
    void differentVendorsForTheSameProductNameAreCachedSeparately() {
        CpeNameVariantCache cache = new CpeNameVariantCache();
        AtomicInteger calls = new AtomicInteger();

        cache.get("Broadcom", "Norton 360", () -> {
            calls.incrementAndGet();
            return List.of();
        });
        cache.get("Symantec", "Norton 360", () -> {
            calls.incrementAndGet();
            return List.of();
        });

        assertThat(calls.get()).isEqualTo(2);
    }

    @Test
    void aVendorAndProductNamePairDoesNotCollideWithADifferentSplitOfTheSameWords() {
        // Bug found live 2026-08-25: joining vendor+productName with a plain space let vendor "a b"
        // + product "c" collide with vendor "a" + product "b c" — both concatenate to "a b c". The
        // key must separate the two fields with a character that cannot appear in real input.
        CpeNameVariantCache cache = new CpeNameVariantCache();
        AtomicInteger calls = new AtomicInteger();

        cache.get("a b", "c", () -> {
            calls.incrementAndGet();
            return List.of();
        });
        cache.get("a", "b c", () -> {
            calls.incrementAndGet();
            return List.of();
        });

        assertThat(calls.get()).isEqualTo(2);
    }
}
