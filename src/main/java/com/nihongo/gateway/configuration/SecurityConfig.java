package com.nihongo.gateway.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

@Configuration
@EnableReactiveMethodSecurity
public class SecurityConfig {

    @Bean
    SecurityWebFilterChain filterChain(
            ServerHttpSecurity http,
            JwtCookieWebFilter jwtCookieWebFilter
    ) {

        return http

                /* =========================
                   CORS
                ========================= */

                .cors(cors -> cors.configurationSource(
                        corsConfigurationSource()
                ))

                /* =========================
                   DISABLE CSRF
                ========================= */

                .csrf(ServerHttpSecurity.CsrfSpec::disable)

                /* =========================
                   JWT COOKIE FILTER
                ========================= */

                .addFilterBefore(
                        jwtCookieWebFilter,
                        SecurityWebFiltersOrder.AUTHENTICATION
                )

                /* =========================
                   AUTHORIZATION
                ========================= */

                .authorizeExchange(exchange -> exchange

                        /* preflight */
                        .pathMatchers(HttpMethod.OPTIONS)
                        .permitAll()

                        /* public api */
                        .pathMatchers("/api/auth/**")
                        .permitAll()

                        .pathMatchers("/api/active-user/**")
                        .permitAll()

                        .pathMatchers("/images/**")
                        .permitAll()

                        /* admin */
                        .pathMatchers("/api/admin/**")
                        .hasRole("ADMIN")

                        /* staff */
                        .pathMatchers("/api/staff/**")
                        .hasAnyRole("STAFF", "ADMIN")

                        /* authenticated */
                        .anyExchange()
                        .authenticated()
                )

                /* =========================
                   RESOURCE SERVER
                ========================= */

                .oauth2ResourceServer(resourceServer ->
                        resourceServer.jwt(jwt ->
                                jwt.jwtAuthenticationConverter(
                                        jwtAuthenticationConverter()
                                )
                        )
                )

                .build();
    }

    @Bean
    public Converter<Jwt, Mono<AbstractAuthenticationToken>>
    jwtAuthenticationConverter() {

        JwtGrantedAuthoritiesConverter defaultConverter =
                new JwtGrantedAuthoritiesConverter();

        defaultConverter.setAuthorityPrefix("ROLE_");

        return jwt -> {

            Collection<GrantedAuthority> authorities =
                    new ArrayList<>(
                            defaultConverter.convert(jwt)
                    );

            Map<String, Object> realmAccess =
                    jwt.getClaim("realm_access");

            if (realmAccess != null) {

                List<String> roles =
                        (List<String>) realmAccess.get("roles");

                if (roles != null) {

                    roles.forEach(role ->
                            authorities.add(
                                    new SimpleGrantedAuthority(
                                            "ROLE_" + role
                                    )
                            )
                    );
                }
            }

            return Mono.just(
                    new JwtAuthenticationToken(
                            jwt,
                            authorities
                    )
            );
        };
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {

        CorsConfiguration config =
                new CorsConfiguration();

        config.setAllowedOrigins(List.of(
                "http://localhost:5173"
        ));

        config.setAllowedMethods(List.of(
                "GET",
                "POST",
                "PUT",
                "DELETE",
                "PATCH",
                "OPTIONS"
        ));

        config.setAllowedHeaders(List.of("*"));

        config.setExposedHeaders(List.of("*"));

        config.setAllowCredentials(true);

        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source =
                new UrlBasedCorsConfigurationSource();

        source.registerCorsConfiguration(
                "/**",
                config
        );

        return source;
    }
}