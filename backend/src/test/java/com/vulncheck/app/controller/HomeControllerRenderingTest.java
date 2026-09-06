package com.vulncheck.app.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.vulncheck.app.config.SecurityConfig;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

/**
 * {@link HomeController#home} rendered through the real {@code home.html} Thymeleaf template via
 * {@code @WebMvcTest}+{@code MockMvc} (same infrastructure {@code JobControllerDetailRenderingTest}
 * already uses), rather than only asserting the model attributes.
 *
 * <p>Closed-mode backlog item 393/408 (senior-reviewer REVISE, 3rd round on PR#294): {@code
 * /settings/secrets} was restricted to {@code ROLE_ADMIN} in {@link SecurityConfig}, but {@code
 * home.html}'s nav still linked to it for every logged-in user -- a non-admin clicking it landed
 * on Spring Boot's bare whitelabel 403, and {@code guide.html}'s own new "管理者アカウントにのみ
 * 表示されます" copy became false the moment the link stayed visible to everyone. {@code home.html}
 * now wraps that link (plus its leading separator) in {@code sec:authorize="hasRole('ADMIN')"} so
 * a non-admin never sees it at all. These tests confirm the {@code sec:authorize} dialect is
 * actually being evaluated at render time, not just present in the template source.
 */
@WebMvcTest(controllers = HomeController.class)
@Import(SecurityConfig.class)
class HomeControllerRenderingTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @WithMockUser(username = "user@example.com", roles = "USER")
    void nonAdminUserDoesNotSeeTheApiKeySettingsLink() throws Exception {
        MvcResult result = mockMvc.perform(get("/"))
                .andExpect(status().isOk())
                .andReturn();
        String body = result.getResponse().getContentAsString(StandardCharsets.UTF_8);

        // Checks for the rendered anchor specifically (not a bare "/settings/secrets" substring
        // search), since home.html's own explanatory HTML comment about this exact restriction
        // mentions that path in plain text -- a bare substring check would false-fail against that
        // comment even though the actual <a> tag is correctly suppressed.
        assertThat(body).doesNotContain("href=\"/settings/secrets\"");
    }

    @Test
    @WithMockUser(username = "admin@example.com", roles = "ADMIN")
    void adminUserSeesTheApiKeySettingsLink() throws Exception {
        MvcResult result = mockMvc.perform(get("/"))
                .andExpect(status().isOk())
                .andReturn();
        String body = result.getResponse().getContentAsString(StandardCharsets.UTF_8);

        assertThat(body).contains("href=\"/settings/secrets\"");
    }
}
