package com.nihongo.gateway.configuration;

import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.Ordered;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class SessionValidationFilter implements GlobalFilter, Ordered {
    private final ReactiveStringRedisTemplate redis;
    public SessionValidationFilter(ReactiveStringRedisTemplate redis) { this.redis = redis; }
    @Override public int getOrder() { return -10; }
    @Override public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // Auth endpoints validate their own cookies; login/refresh must work without access JWT.
        if (exchange.getRequest().getPath().value().startsWith("/api/auth/")) return chain.filter(exchange);
        return exchange.getPrincipal().flatMap(principal -> {
            if (!(principal instanceof JwtAuthenticationToken auth)) return Mono.just(true);
            var jwt = auth.getToken();
            String sid = jwt.getClaimAsString("sessionId");
            if (!"access".equals(jwt.getClaimAsString("type")) || sid == null) return Mono.just(false);
            return redis.opsForHash().multiGet("auth:session:v2:" + jwt.getSubject(), java.util.List.of("sid", "expires", "idle"))
                .map(state -> {
                    long now = System.currentTimeMillis();
                    try {
                        return state.size() == 3 && sid.equals(state.get(0)) && Long.parseLong(String.valueOf(state.get(1))) > now
                            && Long.parseLong(String.valueOf(state.get(2))) > now;
                    } catch (NumberFormatException e) { return false; }
                });
        }).defaultIfEmpty(true)
          .onErrorMap(org.springframework.dao.DataAccessException.class, e -> new org.springframework.web.server.ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Session storage unavailable", e))
          .flatMap(valid -> {
              if (valid) return chain.filter(exchange);
              exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
              return exchange.getResponse().setComplete();
          });
    }
}
