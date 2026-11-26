
package com.spring.spring_mvc.security;

import com.spring.spring_mvc.service.CustomUserDetailsService;
import java.util.Arrays;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * Spring Security configuration class defining
 * authentication, password encoding,
 * and HTTP security filter chain rules for the application.
 */
@EnableWebSecurity
@Configuration
public class SecurityConfig {

    private CustomUserDetailsService userDetailsService;

    /**
     * Constructs a {@code SecurityConfig} with the
     * specified {@link CustomUserDetailsService}.
     *
     * @param userDetailsService the custom service
     *                           used to load user-specific authentication data
     */
    public SecurityConfig(CustomUserDetailsService userDetailsService) {
        this.setUserDetailsService(userDetailsService);
    }

    /**
     * Returns the configured {@link CustomUserDetailsService}.
     *
     * @return the custom user details service
     */
    public CustomUserDetailsService getUserDetailsService() {
        return userDetailsService;
    }

    /**
     * Sets the {@link CustomUserDetailsService} for this configuration.
     *
     * @param userDetailsService the custom user details service to set
     */
    public void setUserDetailsService(
            CustomUserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    /**
     * Configures the HTTP security filter chain,
     * disabling CSRF protection, permitting
     * unauthenticated access to {@code /api/auth/**}
     * endpoints, requiring authentication
     * for all other requests, and enabling HTTP Basic authentication.
     *
     * @param security the {@link HttpSecurity} builder to configure
     * @return the built {@link SecurityFilterChain}
     * @throws Exception if an error occurs while configuring HTTP security
     */
    @Bean
    SecurityFilterChain filterChain(HttpSecurity security)
            throws Exception {
        return security
                .cors(cors -> cors.configure(security))
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session
                                        .sessionCreationPolicy(
                                            SessionCreationPolicy.IF_REQUIRED)
                                    )
                .authorizeHttpRequests(auth -> auth
                                        .requestMatchers(
                                            "/api/auth/**").permitAll()
                                        .requestMatchers(
                                            HttpMethod.OPTIONS, "/**")
                                            .permitAll()
                                        .requestMatchers(
                                            "/api/students/**")
                                            .hasAnyAuthority("USER", "ADMIN")
                                        .anyRequest().authenticated())
                .httpBasic(Customizer.withDefaults())
                .build();
    }

    /**
     * Provides a {@link BCryptPasswordEncoder} bean
     * for hashing and verifying user passwords.
     *
     * @return a new {@link BCryptPasswordEncoder} instance
     */
    @Bean
    BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Exposes the {@link AuthenticationManager} bean from the Spring Security
     * {@link AuthenticationConfiguration}.
     *
     * @param authentication the {@link AuthenticationConfiguration}
     *                       used to retrieve the manager
     * @return the configured {@link AuthenticationManager}
     * @throws Exception if an error occurs while
     *                   retrieving the authentication manager
     */
    @Bean
    AuthenticationManager authenticationManager(
            AuthenticationConfiguration authentication) throws Exception {
        return authentication.getAuthenticationManager();
    }

    /**
     * Configures the Cross-Origin Resource Sharing (CORS)
     * settings to allow requests from the specified
     * frontend origins, HTTP methods, and headers.
     *
     * @return a {@link CorsConfigurationSource} containing
     *         the configured CORS policies
     */
    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        configuration.setAllowedOrigins(
            Arrays.asList(
                "http://localhost:3000", "http://192.168.137.215:3000", "http://localhost"));
        configuration.setAllowedMethods(
            Arrays.asList("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(
            Arrays.asList("Authorization", "Cache-Control", "Content-Type"));

        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = 
        new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
