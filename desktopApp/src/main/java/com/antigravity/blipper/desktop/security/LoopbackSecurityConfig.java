package com.antigravity.blipper.desktop.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;

@Configuration
@EnableWebSecurity
public class LoopbackSecurityConfig {

    @Bean
    public SecurityFilterChain loopbackFilterChain(
            HttpSecurity http,
            LocalHookSecretManager secretManager
    ) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(new LocalHookAuthenticationFilter(secretManager), UsernamePasswordAuthenticationFilter.class)
                .authorizeHttpRequests(auth -> auth.anyRequest().hasAuthority("ROLE_LOCAL_HOOK"));
        return http.build();
    }

    public static class LocalHookAuthenticationFilter extends OncePerRequestFilter {

        private final LocalHookSecretManager secretManager;

        public LocalHookAuthenticationFilter(LocalHookSecretManager secretManager) {
            this.secretManager = secretManager;
        }

        @Override
        protected void doFilterInternal(
                HttpServletRequest request,
                HttpServletResponse response,
                FilterChain filterChain
        ) throws ServletException, IOException {
            if (!isStrictLoopback(request.getRemoteAddr())) {
                deny(response, "NON_LOOPBACK_REJECTED");
                return;
            }
            String providedSecret = request.getHeader(LocalHookSecretManager.HEADER_NAME);
            if (!secretManager.matchesSecret(providedSecret)) {
                deny(response, "INVALID_LOCAL_SECRET");
                return;
            }
            var auth = new UsernamePasswordAuthenticationToken(
                    "antigravity-local-hook",
                    null,
                    List.of(new SimpleGrantedAuthority("ROLE_LOCAL_HOOK"))
            );
            SecurityContextHolder.getContext().setAuthentication(auth);
            try {
                filterChain.doFilter(request, response);
            } finally {
                SecurityContextHolder.clearContext();
            }
        }

        private static boolean isStrictLoopback(String remoteAddr) {
            if (remoteAddr == null || remoteAddr.isBlank()) {
                return false;
            }
            try {
                return InetAddress.getByName(remoteAddr).isLoopbackAddress();
            } catch (Exception e) {
                return false;
            }
        }

        private static void deny(HttpServletResponse response, String code) throws IOException {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setCharacterEncoding(StandardCharsets.UTF_8.name());
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"" + code + "\"}");
        }
    }
}
