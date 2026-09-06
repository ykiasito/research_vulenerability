package com.vulncheck.app.controller;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.vulncheck.app.config.SecurityConfig;
import com.vulncheck.app.entity.User;
import com.vulncheck.app.entity.UserSecret;
import com.vulncheck.app.repository.UserRepository;
import com.vulncheck.app.repository.UserSecretRepository;
import com.vulncheck.app.service.SecretEncryptionService;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Closed-mode backlog item 393: confirms {@code /settings/secrets/**} actually falls under {@link
 * SecurityConfig}'s {@code hasRole("ADMIN")} rule at request-handling time — same infrastructure
 * and shape as {@code AdminControllerSecurityTest}'s coverage of {@code /admin/**}. Item363's
 * investigation found a non-admin's registered NVD key (the only provider this page still offers,
 * per {@link SecretsController#VALID_PROVIDERS}) is never read by anything, so this page is
 * restricted to the admin account the same way {@code /admin/**} already is.
 */
@WebMvcTest(controllers = SecretsController.class)
@Import(SecurityConfig.class)
class SecretsControllerSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private UserRepository userRepository;
    @MockBean
    private UserSecretRepository userSecretRepository;
    @MockBean
    private SecretEncryptionService secretEncryptionService;

    private User user(Long id, String email) {
        User user = new User();
        user.setId(id);
        user.setEmail(email);
        user.setPasswordHash("hash");
        return user;
    }

    @Test
    void unauthenticatedGetIsRedirectedToLogin() throws Exception {
        mockMvc.perform(get("/settings/secrets"))
                .andExpect(status().is3xxRedirection());
    }

    @Test
    @WithMockUser(username = "user@example.com", roles = "USER")
    void authenticatedNonAdminUserIsForbiddenFromGet() throws Exception {
        mockMvc.perform(get("/settings/secrets"))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "admin@example.com", roles = "ADMIN")
    void adminUserIsAllowedThroughToGet() throws Exception {
        when(userRepository.findByEmail("admin@example.com"))
                .thenReturn(Optional.of(user(1L, "admin@example.com")));
        when(userSecretRepository.findByUserId(1L)).thenReturn(List.of());

        mockMvc.perform(get("/settings/secrets"))
                .andExpect(status().isOk());
    }

    @Test
    void unauthenticatedPostIsRedirectedToLogin() throws Exception {
        mockMvc.perform(post("/settings/secrets")
                        .param("provider", UserSecret.PROVIDER_NVD)
                        .param("apiKey", "some-key")
                        .with(csrf()))
                .andExpect(status().is3xxRedirection());
    }

    @Test
    @WithMockUser(username = "user@example.com", roles = "USER")
    void authenticatedNonAdminUserIsForbiddenFromPost() throws Exception {
        mockMvc.perform(post("/settings/secrets")
                        .param("provider", UserSecret.PROVIDER_NVD)
                        .param("apiKey", "some-key")
                        .with(csrf()))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "admin@example.com", roles = "ADMIN")
    void adminUserIsAllowedThroughToPost() throws Exception {
        when(userRepository.findByEmail("admin@example.com"))
                .thenReturn(Optional.of(user(1L, "admin@example.com")));
        when(secretEncryptionService.encrypt(anyString(), eq(1L), eq(UserSecret.PROVIDER_NVD)))
                .thenReturn("encrypted");

        mockMvc.perform(post("/settings/secrets")
                        .param("provider", UserSecret.PROVIDER_NVD)
                        .param("apiKey", "some-key")
                        .with(csrf()))
                .andExpect(status().is3xxRedirection());
    }

    @Test
    void unauthenticatedDeleteIsRedirectedToLogin() throws Exception {
        mockMvc.perform(post("/settings/secrets/nvd/delete").with(csrf()))
                .andExpect(status().is3xxRedirection());
    }

    @Test
    @WithMockUser(username = "user@example.com", roles = "USER")
    void authenticatedNonAdminUserIsForbiddenFromDelete() throws Exception {
        mockMvc.perform(post("/settings/secrets/nvd/delete").with(csrf()))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "admin@example.com", roles = "ADMIN")
    void adminUserIsAllowedThroughToDelete() throws Exception {
        when(userRepository.findByEmail("admin@example.com"))
                .thenReturn(Optional.of(user(1L, "admin@example.com")));

        mockMvc.perform(post("/settings/secrets/nvd/delete").with(csrf()))
                .andExpect(status().is3xxRedirection());
    }
}
