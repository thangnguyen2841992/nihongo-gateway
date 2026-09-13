package com.nihongo.gateway.configuration;

import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
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
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.util.ArrayList;
import java.util.List;

@Configuration
@EnableReactiveMethodSecurity
public class SecurityConfig {

    @Bean
    SecurityWebFilterChain filterChain(ServerHttpSecurity http, JwtCookieWebFilter jwtCookieWebFilter) {

        return http

                /*
                 * ==============================
                 * CORS
                 * ==============================
                 */.cors(cors -> cors.configurationSource(corsConfigurationSource()))

                /*
                 * ==============================
                 * CSRF
                 * ==============================
                 *
                 * JWT authentication
                 * nên disable CSRF.
                 */.csrf(ServerHttpSecurity.CsrfSpec::disable)

                /*
                 * ==============================
                 * JWT COOKIE
                 * ==============================
                 *
                 * accessToken trong Cookie
                 * ↓
                 * JwtCookieWebFilter
                 * ↓
                 * Authorization: Bearer xxx
                 */.addFilterBefore(jwtCookieWebFilter, SecurityWebFiltersOrder.AUTHENTICATION)

                /*
                 * ==============================
                 * AUTHORIZATION
                 * ==============================
                 */.authorizeExchange(exchange -> exchange

                        /*
                         * OPTIONS
                         */.pathMatchers(HttpMethod.OPTIONS).permitAll()

                        /*
                         * LOGIN / REGISTER / AUTH
                         */.pathMatchers("/api/auth/**").permitAll()

                        /*
                         * ACTIVE USER
                         */.pathMatchers("/api/active-user/**").permitAll()

                        /*
                         * IMAGES
                         */.pathMatchers("/images/**").permitAll()

                        /*
                         * ADMIN
                         */.pathMatchers("/api/admin/**").hasRole("ADMIN")

                        /*
                         * STAFF / ADMIN / USER
                         */.pathMatchers("/api/staff/**").hasAnyRole("STAFF", "ADMIN", "USER")

                        /*
                         * USER SERVICE
                         */.pathMatchers("/api/nihongo-user/**").hasAnyRole("STAFF", "ADMIN", "USER")

                        /*
                         * Các API còn lại
                         */.anyExchange().authenticated())

                /*
                 * ==============================
                 * RESOURCE SERVER
                 * ==============================
                 *
                 * Gateway tự verify JWT.
                 */.oauth2ResourceServer(resourceServer -> resourceServer.jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter())))

                .build();
    }

    /*
     * ==========================================
     * REACTIVE JWT DECODER
     * ==========================================
     *
     * Gateway dùng secret này để verify JWT.
     *
     * QUAN TRỌNG:
     *
     * jwt.secret của Gateway
     * PHẢI GIỐNG
     * jwt.secret của user-service.
     */
    @Bean
    public ReactiveJwtDecoder jwtDecoder(@Value("${jwt.secret}") String secret) {

        byte[] keyBytes = Decoders.BASE64.decode(secret);

        SecretKey key = Keys.hmacShaKeyFor(keyBytes);

        return NimbusReactiveJwtDecoder.withSecretKey(key).macAlgorithm(MacAlgorithm.HS256).build();
    }

    /*
     * ==========================================
     * JWT → AUTHORITIES
     * ==========================================
     *
     * JWT:
     *
     * {
     *   "sub": "...",
     *   "email": "...",
     *   "role": "USER"
     * }
     *
     * ↓
     *
     * ROLE_USER
     *
     * Vì vậy:
     *
     * hasRole("USER")
     *
     * sẽ match:
     *
     * ROLE_USER
     */
    @Bean
    public Converter<Jwt, Mono<AbstractAuthenticationToken>> jwtAuthenticationConverter() {

        return jwt -> {

            List<GrantedAuthority> authorities = new ArrayList<>();

            List<String> roles = jwt.getClaimAsStringList("roles");

            if (roles != null) {

                roles.forEach(role -> {

                    if (role != null && !role.isBlank()) {

                        authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
                    }
                });
            }

            return Mono.just(new JwtAuthenticationToken(jwt, authorities));
        };
    }

    /*
     * ==========================================
     * CORS
     * ==========================================
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {

        CorsConfiguration config = new CorsConfiguration();

        config.setAllowedOrigins(List.of("http://localhost:5173"));

        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));

        config.setAllowedHeaders(List.of("*"));

        config.setExposedHeaders(List.of("*"));

        /*
         * Cho phép Browser gửi Cookie
         */
        config.setAllowCredentials(true);

        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();

        source.registerCorsConfiguration("/**", config);

        return source;
    }
}