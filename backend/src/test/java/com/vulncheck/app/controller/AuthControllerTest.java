package com.vulncheck.app.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.vulncheck.app.entity.User;
import com.vulncheck.app.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.ui.ExtendedModelMap;
import org.springframework.ui.Model;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.validation.BindingResult;

/**
 * {@link AuthController#register} — task-backlog item 148: {@code AppUserDetailsService} grants
 * ROLE_ADMIN via a case-INSENSITIVE comparison against {@code ADMIN_EMAIL}, so registration must
 * normalize/dedupe case-insensitively too, or a case-variant of an existing (in particular the
 * admin's) email could slip past the duplicate check and be granted admin. Plain Mockito unit test
 * invoking the controller method directly, same convention as {@link AdminControllerTest}/{@link
 * JobControllerTest} (no MockMvc/@WebMvcTest infrastructure in this codebase).
 */
@ExtendWith(MockitoExtension.class)
class AuthControllerTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    private AuthController newController() {
        return new AuthController(userRepository, passwordEncoder);
    }

    private AuthController.RegisterForm form(String email, String password) {
        AuthController.RegisterForm form = new AuthController.RegisterForm();
        form.setEmail(email);
        form.setPassword(password);
        return form;
    }

    @Test
    void registerLowercasesEmailBeforeDuplicateCheckAndSave() {
        AuthController controller = newController();
        AuthController.RegisterForm registerForm = form("Admin@Example.com", "password123");
        BindingResult bindingResult = new BeanPropertyBindingResult(registerForm, "registerForm");
        Model model = new ExtendedModelMap();

        when(userRepository.existsByEmailIgnoreCase("admin@example.com")).thenReturn(false);
        when(passwordEncoder.encode("password123")).thenReturn("hashed");

        String view = controller.register(registerForm, bindingResult, model);

        assertThat(view).isEqualTo("redirect:/login?registered");
        verify(userRepository).existsByEmailIgnoreCase("admin@example.com");

        ArgumentCaptor<User> savedUser = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(savedUser.capture());
        assertThat(savedUser.getValue().getEmail()).isEqualTo("admin@example.com");
    }

    @Test
    void registerRejectsCaseVariantOfExistingEmail() {
        AuthController controller = newController();
        // Differs only in case from an already-registered "admin@example.com" — this is exactly
        // the case that previously let a non-admin register a case-variant of ADMIN_EMAIL and be
        // granted ROLE_ADMIN by AppUserDetailsService's case-insensitive comparison.
        AuthController.RegisterForm registerForm = form("ADMIN@EXAMPLE.COM", "password123");
        BindingResult bindingResult = new BeanPropertyBindingResult(registerForm, "registerForm");
        Model model = new ExtendedModelMap();

        when(userRepository.existsByEmailIgnoreCase("admin@example.com")).thenReturn(true);

        String view = controller.register(registerForm, bindingResult, model);

        assertThat(view).isEqualTo("register");
        assertThat(model.getAttribute("error")).isNotNull();
        verify(userRepository, never()).save(any());
    }
}
