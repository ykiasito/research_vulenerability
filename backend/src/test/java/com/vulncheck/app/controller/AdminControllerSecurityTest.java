package com.vulncheck.app.controller;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.vulncheck.app.config.SecurityConfig;
import com.vulncheck.app.repository.CsafSyncStateRepository;
import com.vulncheck.app.repository.GhsaSyncFailureRepository;
import com.vulncheck.app.repository.GhsaSyncStateRepository;
import com.vulncheck.app.repository.OsvSyncFailureRepository;
import com.vulncheck.app.repository.OsvSyncStateRepository;
import com.vulncheck.app.repository.UserRepository;
import com.vulncheck.app.service.NvdCpeSyncService;
import com.vulncheck.app.service.UserApiKeyService;
import com.vulncheck.app.service.csaf.RedHatCsafSyncService;
import com.vulncheck.app.service.csaf.SiemensCsafSyncService;
import com.vulncheck.app.service.cveorg.CveOrgSyncService;
import com.vulncheck.app.service.ghsa.GhsaSyncService;
import com.vulncheck.app.service.osv.OsvSyncService;
import com.vulncheck.app.service.registry.RegistryMirrorSyncService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Confirms {@code POST /admin/cpe-dictionary/sync-all} (the new full-sync endpoint added
 * alongside the existing {@code /admin/cpe-dictionary/sync}) actually falls under {@link
 * SecurityConfig}'s blanket {@code /admin/**} -> {@code hasRole("ADMIN")} rule at request-handling
 * time — not just that the literal path string happens to start with {@code /admin/}. Loads the
 * real {@link SecurityConfig} filter chain via {@code @Import} rather than relying on the
 * default {@code @WebMvcTest} security auto-config, since the latter would build its own
 * default-deny chain that says nothing about this project's actual rule.
 *
 * <p>Every request goes through {@code csrf()} so this test isolates the authorization rule
 * itself: CSRF protection on POST forms is a pre-existing, orthogonal concern shared by every
 * admin sync endpoint (see {@code SecurityConfig}, which leaves Spring Security's default CSRF
 * protection enabled), not something introduced by or specific to this new route.
 */
@WebMvcTest(controllers = AdminController.class)
@Import(SecurityConfig.class)
class AdminControllerSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private NvdCpeSyncService nvdCpeSyncService;
    @MockBean
    private UserApiKeyService userApiKeyService;
    @MockBean
    private UserRepository userRepository;
    @MockBean
    private CveOrgSyncService cveOrgSyncService;
    @MockBean
    private SiemensCsafSyncService siemensCsafSyncService;
    @MockBean
    private RedHatCsafSyncService redHatCsafSyncService;
    @MockBean
    private CsafSyncStateRepository csafSyncStateRepository;
    @MockBean
    private GhsaSyncService ghsaSyncService;
    @MockBean
    private GhsaSyncStateRepository ghsaSyncStateRepository;
    @MockBean
    private GhsaSyncFailureRepository ghsaSyncFailureRepository;
    @MockBean
    private OsvSyncService osvSyncService;
    @MockBean
    private OsvSyncStateRepository osvSyncStateRepository;
    @MockBean
    private OsvSyncFailureRepository osvSyncFailureRepository;
    @MockBean
    private RegistryMirrorSyncService registryMirrorSyncService;

    @Test
    void unauthenticatedRequestIsRedirectedToLogin() throws Exception {
        mockMvc.perform(post("/admin/cpe-dictionary/sync-all").with(csrf()))
                .andExpect(status().is3xxRedirection());
    }

    @Test
    @WithMockUser(roles = "USER")
    void authenticatedNonAdminUserIsForbidden() throws Exception {
        mockMvc.perform(post("/admin/cpe-dictionary/sync-all").with(csrf()))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void adminUserIsAllowedThrough() throws Exception {
        mockMvc.perform(post("/admin/cpe-dictionary/sync-all").with(csrf()))
                .andExpect(status().is2xxSuccessful());
    }

    /** Same {@code /admin/**} -> {@code hasRole("ADMIN")} rule, exercised against the new
     *  registry-mirror sync endpoint (closed-mode backlog item 183). */
    @Test
    void unauthenticatedRequestToRegistryMirrorSyncIsRedirectedToLogin() throws Exception {
        mockMvc.perform(post("/admin/registry-mirror/sync-all").with(csrf()))
                .andExpect(status().is3xxRedirection());
    }

    @Test
    @WithMockUser(roles = "USER")
    void authenticatedNonAdminUserIsForbiddenFromRegistryMirrorSync() throws Exception {
        mockMvc.perform(post("/admin/registry-mirror/sync-all").with(csrf()))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void adminUserIsAllowedThroughToRegistryMirrorSync() throws Exception {
        mockMvc.perform(post("/admin/registry-mirror/sync-all").with(csrf()))
                .andExpect(status().is2xxSuccessful());
    }
}
