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
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

@Component
public class SessionValidationFilter implements GlobalFilter, Ordered {
    private final WebClient client;
    private final String validationUrl;
    private final com.nihongo.security.InternalCredentials credentials;
    private final long cacheTtlMillis;
    private final int maxCacheEntries;
    private final ConcurrentHashMap<String, Long> validSessions = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Mono<Boolean>> inFlight = new ConcurrentHashMap<>();
    private final AtomicInteger requests = new AtomicInteger();

    public SessionValidationFilter(WebClient.Builder builder, String validationUrl,
            com.nihongo.security.InternalCredentials credentials) {
        this(builder, validationUrl, credentials, 5_000, 20_000);
    }

    @org.springframework.beans.factory.annotation.Autowired
    public SessionValidationFilter(WebClient.Builder builder,
            @Value("${auth.session-validation-url:http://127.0.0.1:8081/api/auth/session/validate}") String validationUrl,
            com.nihongo.security.InternalCredentials credentials,
            @Value("${auth.session-cache-ttl:5000}") long cacheTtlMillis,
            @Value("${auth.session-cache-max-entries:20000}") int maxCacheEntries) {
        this.client = builder.build();
        this.validationUrl = validationUrl;
        this.credentials = credentials;
        this.cacheTtlMillis = Math.max(0, cacheTtlMillis);
        this.maxCacheEntries = Math.max(100, maxCacheEntries);
    }

    @Override public int getOrder() { return -10; }

    @Override public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // Auth endpoints validate their own cookies; login and refresh have no access JWT.
        if (com.nihongo.security.SecurityRequestPaths.canonical(exchange.getRequest().getURI()).startsWith("/api/auth/")) return chain.filter(exchange);
        return exchange.getPrincipal().flatMap(principal -> {
            if (!(principal instanceof JwtAuthenticationToken auth)) return Mono.just(true);
            var jwt = auth.getToken();
            if (!"access".equals(jwt.getClaimAsString("type")) || jwt.getClaimAsString("sessionId") == null)
                return Mono.just(false);
            String cacheKey = jwt.getSubject() + ':' + jwt.getClaimAsString("sessionId") + ':'
                    + String.valueOf(jwt.getClaims().get("roles"));
            long now = System.currentTimeMillis();
            Long cachedUntil = validSessions.get(cacheKey);
            if (cachedUntil != null && cachedUntil > now) return Mono.just(true);
            if (cachedUntil != null) validSessions.remove(cacheKey, cachedUntil);
            if ((requests.incrementAndGet() & 255) == 0) validSessions.entrySet().removeIf(entry -> entry.getValue() <= now);
            Mono<Boolean> validation = Mono.defer(() -> validate(jwt.getTokenValue()))
                    .doOnNext(valid -> { if (valid) remember(cacheKey, jwt.getExpiresAt() == null ? Long.MAX_VALUE : jwt.getExpiresAt().toEpochMilli()); })
                    .cache();
            Mono<Boolean> existing = inFlight.putIfAbsent(cacheKey, validation);
            Mono<Boolean> selected = existing == null ? validation : existing;
            return selected.doFinally(signal -> inFlight.remove(cacheKey, selected));
        }).defaultIfEmpty(true).flatMap(valid -> {
            if (valid) return chain.filter(exchange);
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            exchange.getResponse().getHeaders().set("X-Auth-Failure", "session-invalid");
            return exchange.getResponse().setComplete();
        });
    }

    private Mono<Boolean> validate(String token) {
        return client.get().uri(validationUrl)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .header(com.nihongo.security.InternalCredentials.HEADER,credentials.value())
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
    }

    private void remember(String key, long tokenExpiry) {
        if (cacheTtlMillis == 0) return;
        long now = System.currentTimeMillis();
        if (validSessions.size() >= maxCacheEntries) {
            validSessions.entrySet().removeIf(entry -> entry.getValue() <= now);
            if (validSessions.size() >= maxCacheEntries) return;
        }
        validSessions.put(key, Math.min(tokenExpiry, now + cacheTtlMillis));
    }
}
