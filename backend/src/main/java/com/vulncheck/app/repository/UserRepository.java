package com.vulncheck.app.repository;

import com.vulncheck.app.entity.User;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);

    /** Case-insensitive duplicate check used by {@code AuthController#register} (task-backlog
     *  item 148). A plain case-sensitive exists-check alone let anyone register a case-variant of
     *  an existing email — including {@code ADMIN_EMAIL} — and be granted {@code ROLE_ADMIN} by
     *  {@code AppUserDetailsService}'s case-insensitive comparison, since the DB's plain UNIQUE
     *  constraint on {@code email} is case-sensitive. */
    boolean existsByEmailIgnoreCase(String email);
}
