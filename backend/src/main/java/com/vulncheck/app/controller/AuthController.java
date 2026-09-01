package com.vulncheck.app.controller;

import com.vulncheck.app.entity.User;
import com.vulncheck.app.repository.UserRepository;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.util.Locale;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
@RequiredArgsConstructor
public class AuthController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @GetMapping("/login")
    public String loginForm() {
        return "login";
    }

    @GetMapping("/register")
    public String registerForm(Model model) {
        if (!model.containsAttribute("registerForm")) {
            model.addAttribute("registerForm", new RegisterForm());
        }
        return "register";
    }

    @PostMapping("/register")
    public String register(@Valid @ModelAttribute("registerForm") RegisterForm form,
                            BindingResult bindingResult,
                            Model model) {
        if (bindingResult.hasErrors()) {
            return "register";
        }

        // Normalize to lowercase before any lookup/save so that a case-variant of an existing
        // email (most importantly ADMIN_EMAIL, see AppUserDetailsService's case-insensitive
        // comparison) can never sneak past the duplicate check and be granted ROLE_ADMIN
        // (task-backlog item 148). Locale.ROOT avoids locale-dependent casing surprises (e.g.
        // Turkish "I").
        String normalizedEmail = form.getEmail().toLowerCase(Locale.ROOT);

        if (userRepository.existsByEmailIgnoreCase(normalizedEmail)) {
            model.addAttribute("error", "このメールアドレスは既に登録されています。");
            return "register";
        }

        User user = new User();
        user.setEmail(normalizedEmail);
        user.setPasswordHash(passwordEncoder.encode(form.getPassword()));
        userRepository.save(user);

        return "redirect:/login?registered";
    }

    @Getter
    @Setter
    @NoArgsConstructor
    @AllArgsConstructor
    public static class RegisterForm {

        @NotBlank
        @Email
        private String email;

        @NotBlank
        @Size(min = 8, message = "パスワードは8文字以上で入力してください。")
        private String password;
    }
}
