package com.nihongo.gateway.configuration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.Duration;

@Component
public class SessionValidationFilter implements GlobalFilter, Ordered {
    private final WebClient client;
    private final String validationUrl;

    public SessionValidationFilter(WebClient.Builder builder,
            @Value("${auth.session-validation-url:http://127.0.0.1:8081/api/auth/session/validate}") String validationUrl) {
        this.client = builder.build();
        this.validationUrl = validationUrl;
    }

    @Override public int getOrder() { return -10; }

    @Override public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // Auth endpoints validate their own cookies; login and refresh have no access JWT.
        if (exchange.getRequest().getPath().value().startsWith("/api/auth/")) return chain.filter(exchange);
        return exchange.getPrincipal().flatMap(principal -> {
            if (!(principal instanceof JwtAuthenticationToken auth)) return Mono.just(true);
            var jwt = auth.getToken();
            if (!"access".equals(jwt.getClaimAsString("type")) || jwt.getClaimAsString("sessionId") == null)
                return Mono.just(false);
            return client.get().uri(validationUrl)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwt.getTokenValue())
                    .exchangeToMono(response -> {
                        if (response.statusCode().is2xxSuccessful()) return Mono.just(true);
                        if (response.statusCode().value() == 401) return Mono.just(false);
                        return Mono.error(new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                                "Session validation unavailable"));
                    })
                    .timeout(Duration.ofSeconds(3))
                    .onErrorMap(error -> !(error instanceof ResponseStatusException),
                            error -> new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                                    "Session validation unavailable", error));
        }).defaultIfEmpty(true).flatMap(valid -> {
            if (valid) return chain.filter(exchange);
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            exchange.getResponse().getHeaders().set("X-Auth-Failure", "session-invalid");
            return exchange.getResponse().setComplete();
        });
    }
}
