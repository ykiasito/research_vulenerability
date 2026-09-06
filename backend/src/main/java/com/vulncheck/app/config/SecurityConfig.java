package com.vulncheck.app.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.StaticHeadersWriter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/register", "/login", "/css/**", "/js/**", "/robots.txt").permitAll()
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        // Closed-mode backlog item 393: the only remaining provider on this page is
                        // NVD (item392/B2 already stripped the Claude key UI, see SecretsController's
                        // own VALID_PROVIDERS), and item363's investigation found a non-admin's
                        // registered NVD key is never read by anything — only the admin account's own
                        // key is ever resolved (UserApiKeyService#getAdminNvdApiKey / the admin-only
                        // /admin/** sync routes). Gating the whole page here, the same way /admin/**
                        // is gated, avoids letting non-admin users accumulate encrypted keys that can
                        // never be used.
                        .requestMatchers("/settings/secrets/**").hasRole("ADMIN")
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form
                        .loginPage("/login")
                        .defaultSuccessUrl("/", true)
                        .permitAll()
                )
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/login?logout")
                        .permitAll()
                )
                // Not a commercial/public product — keep it out of search indexes even if it ends
                // up reachable on a public IP/domain. Paired with robots.txt (see static resources).
                .headers(headers -> headers
                        .addHeaderWriter(new StaticHeadersWriter("X-Robots-Tag", "noindex, nofollow"))
                );

        return http.build();
    }
}
