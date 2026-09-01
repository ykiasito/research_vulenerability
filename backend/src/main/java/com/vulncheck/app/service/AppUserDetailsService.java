package com.vulncheck.app.service;

import com.vulncheck.app.entity.User;
import com.vulncheck.app.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Locale;

@Service
@RequiredArgsConstructor
public class AppUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    /** The single account granted ROLE_ADMIN, set via the {@code ADMIN_EMAIL} env var (see
     *  application.yml) — not a persisted column, so there's nothing to migrate/backfill and a
     *  deployment with the var unset simply has no admin, never an accidental one. */
    @Value("${app.admin-email:}")
    private String adminEmail;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        String normalizedEmail = email.toLowerCase(Locale.ROOT);
        User user = userRepository.findByEmail(normalizedEmail)
                .orElseThrow(() -> new UsernameNotFoundException("No user found for email: " + email));

        var builder = org.springframework.security.core.userdetails.User
                .withUsername(user.getEmail())
                .password(user.getPasswordHash());

        boolean isAdmin = !adminEmail.isBlank()
                && adminEmail.toLowerCase(Locale.ROOT).equals(user.getEmail().toLowerCase(Locale.ROOT));
        builder.authorities(isAdmin ? new String[] {"ROLE_USER", "ROLE_ADMIN"} : new String[] {"ROLE_USER"});

        return builder.build();
    }
}
