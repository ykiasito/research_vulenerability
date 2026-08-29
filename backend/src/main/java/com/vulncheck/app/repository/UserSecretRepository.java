package com.vulncheck.app.repository;

import com.vulncheck.app.entity.UserSecret;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

public interface UserSecretRepository extends JpaRepository<UserSecret, Long> {

    List<UserSecret> findByUserId(Long userId);

    Optional<UserSecret> findByUserIdAndProvider(Long userId, String provider);

    @Modifying
    @Transactional
    void deleteByUserIdAndProvider(Long userId, String provider);

    // Upsert on the table's (user_id, provider) unique constraint: saving a key for a provider
    // the user already configured must replace it in place, not fail or create a duplicate row.
    @Modifying
    @Transactional
    @Query(
            value = """
                    INSERT INTO user_secrets (user_id, provider, encrypted_key)
                    VALUES (:userId, :provider, :encryptedKey)
                    ON CONFLICT (user_id, provider) DO UPDATE SET encrypted_key = EXCLUDED.encrypted_key
                    """,
            nativeQuery = true)
    void upsert(@Param("userId") Long userId, @Param("provider") String provider, @Param("encryptedKey") String encryptedKey);
}
