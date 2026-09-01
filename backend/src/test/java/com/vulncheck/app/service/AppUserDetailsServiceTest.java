package com.vulncheck.app.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.vulncheck.app.entity.User;
import com.vulncheck.app.repository.UserRepository;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * Unit coverage for {@link AppUserDetailsService#loadUserByUsername} (senior-reviewer PR#87
 * REVISE, task-backlog item 148 follow-up). Plain Mockito unit test, same convention as {@link
 * UserApiKeyServiceTest}/{@code AuthControllerTest} (no MockMvc/@WebMvcTest infrastructure in this
 * codebase).
 */
class AppUserDetailsServiceTest {

    private final UserRepository userRepository = mock(UserRepository.class);
    private final AppUserDetailsService service = new AppUserDetailsService(userRepository);

    @Test
    void loginResolvesStoredLowercaseRowFromAMixedCaseInput() {
        // Regression test for the REVISE item 1 bug: registration now lowercases stored emails,
        // but loadUserByUsername was still calling findByEmail with the raw (possibly mixed-case)
        // login input, so a user who typed "Foo@Bar.com" at registration and then again at login
        // would fail to authenticate against their own lowercased row "foo@bar.com".
        ReflectionTestUtils.setField(service, "adminEmail", "");
        User stored = new User(1L, "foo@bar.com", "hash", null);
        when(userRepository.findByEmail("foo@bar.com")).thenReturn(Optional.of(stored));

        UserDetails result = service.loadUserByUsername("Foo@Bar.com");

        assertThat(result.getUsername()).isEqualTo("foo@bar.com");
    }

    @Test
    void grantsRoleAdminWhenAdminEmailExactlyMatchesStoredEmail() {
        ReflectionTestUtils.setField(service, "adminEmail", "admin@example.com");
        User stored = new User(1L, "admin@example.com", "hash", null);
        when(userRepository.findByEmail("admin@example.com")).thenReturn(Optional.of(stored));

        UserDetails result = service.loadUserByUsername("admin@example.com");

        assertThat(result.getAuthorities())
                .extracting(Object::toString)
                .containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN");
    }

    @Test
    void doesNotGrantRoleAdminForAUnicodeCaseFoldMismatch() {
        // Regression test for REVISE item 2: equalsIgnoreCase folds Unicode characters (e.g. long s
        // U+017F "ſ") differently than toLowerCase(Locale.ROOT)/Postgres lower(), so under some
        // collations a stored "admin@ſyscorp.com" could previously be granted ROLE_ADMIN against an
        // ADMIN_EMAIL of "admin@syscorp.com". With this fix, it must not be.
        ReflectionTestUtils.setField(service, "adminEmail", "admin@syscorp.com");
        User stored = new User(1L, "admin@ſyscorp.com", "hash", null);
        when(userRepository.findByEmail("admin@ſyscorp.com")).thenReturn(Optional.of(stored));

        UserDetails result = service.loadUserByUsername("admin@ſyscorp.com");

        assertThat(result.getAuthorities())
                .extracting(Object::toString)
                .containsExactly("ROLE_USER");
    }

    @Test
    void neverGrantsRoleAdminWhenAdminEmailIsBlank() {
        ReflectionTestUtils.setField(service, "adminEmail", "");
        User stored = new User(1L, "someone@example.com", "hash", null);
        when(userRepository.findByEmail("someone@example.com")).thenReturn(Optional.of(stored));

        UserDetails result = service.loadUserByUsername("someone@example.com");

        assertThat(result.getAuthorities())
                .extracting(Object::toString)
                .containsExactly("ROLE_USER");
    }
}
