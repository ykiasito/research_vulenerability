package com.vulncheck.app.service;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Short-lived in-memory holding area for a CSV's raw bytes between "show the column-mapping
 * screen" and "confirm the mapping and create the job" — two separate HTTP requests. Round-
 * tripping the file itself through a hidden form field would risk exceeding Tomcat's default max
 * form-POST size once base64-inflated (a 5MB CSV, this app's own upload cap, becomes ~6.7MB of
 * base64), so instead only a small opaque token travels through the browser; this single-instance
 * app has no need for anything heavier (Redis, a DB table) for what's essentially a few minutes of
 * transient state. Entries are one-shot in the success path (removed by the caller after the job
 * is created) and swept here on a timer in case a user abandons the mapping screen without
 * confirming.
 */
@Component
@Slf4j
public class PendingCsvUploadStore {

    private static final java.time.Duration MAX_AGE = java.time.Duration.ofMinutes(15);

    /** {@code bundledComponentCheckEnabled} carries the upload form's opt-in checkbox choice
     *  through to the mapping-confirmation screen, which has no checkbox of its own — see
     *  {@code JobController#confirmMapping}. */
    public record PendingUpload(byte[] content, String filename, boolean bundledComponentCheckEnabled, Instant createdAt) {
    }

    private final Map<String, PendingUpload> uploads = new ConcurrentHashMap<>();

    public String store(byte[] content, String filename, boolean bundledComponentCheckEnabled) {
        String token = UUID.randomUUID().toString();
        uploads.put(token, new PendingUpload(content, filename, bundledComponentCheckEnabled, Instant.now()));
        return token;
    }

    /** Non-destructive — the mapping-confirmation screen may need to re-render itself (e.g. a
     *  validation error) more than once before the upload is actually consumed. */
    public Optional<PendingUpload> get(String token) {
        return Optional.ofNullable(uploads.get(token));
    }

    public void remove(String token) {
        uploads.remove(token);
    }

    @Scheduled(fixedRate = 5 * 60 * 1000)
    public void sweepExpired() {
        Instant cutoff = Instant.now().minus(MAX_AGE);
        int before = uploads.size();
        uploads.values().removeIf(upload -> upload.createdAt().isBefore(cutoff));
        int removed = before - uploads.size();
        if (removed > 0) {
            log.info("Pending CSV upload sweep: removed {} abandoned upload(s)", removed);
        }
    }
}
