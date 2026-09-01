package com.vulncheck.app.repository;

import com.vulncheck.app.entity.User;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);

    /** Case-insensitive lookup — used only by {@code UserApiKeyService#getAdminNvdApiKey()} to
     *  match how {@code AppUserDetailsService} already grants ROLE_ADMIN via {@code
     *  adminEmail.equalsIgnoreCase(user.getEmail())}. If {@code ADMIN_EMAIL} differs from the
     *  stored row only in case, a plain {@link #findByEmail} would silently find nothing while
     *  login still worked fine (task-backlog item 142 REVISE). Not used for login itself, since
     *  {@code AppUserDetailsService} looks the user up by their own typed-in email, not by
     *  comparing against a separately-configured admin email. */
    Optional<User> findByEmailIgnoreCase(String email);

    boolean existsByEmail(String email);

    /** Case-insensitive duplicate check used by {@code AuthController#register} (task-backlog
     *  item 148). {@link #existsByEmail} alone let anyone register a case-variant of an existing
     *  email — including {@code ADMIN_EMAIL} — and be granted {@code ROLE_ADMIN} by {@code
     *  AppUserDetailsService}'s case-insensitive comparison, since the DB's plain UNIQUE
     *  constraint on {@code email} is case-sensitive. */
    boolean existsByEmailIgnoreCase(String email);
}
