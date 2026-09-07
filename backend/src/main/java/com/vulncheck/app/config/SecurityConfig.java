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
                        // "/error" must stay permitAll: spring.security.filter.dispatcher-types is
                        // left at Spring Security's default (ASYNC, ERROR, REQUEST — not overridden
                        // anywhere in application.yml), so the container's internal forward to /error
                        // on an unhandled exception/sendError is itself subject to authorization. An
                        // unauthenticated request that fails on a permitAll page (e.g. /register)
                        // before establishing a session would otherwise have that forward blocked and
                        // redirected to /login with no explanation, instead of rendering the intended
                        // custom error page. Safe to leave open: templates/error/*.html render only
                        // static Japanese text (no server-side data at all), and server.error.include-*
                        // are all pinned to never/false (item411, see ErrorPropertiesConfigBindingTest),
                        // so nothing sensitive can flow through this path regardless of auth state.
                        .requestMatchers("/register", "/login", "/css/**", "/js/**", "/robots.txt", "/error")
                        .permitAll()
                        .requestMatchers("/admin/**").hasRole("ADMIN")
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
