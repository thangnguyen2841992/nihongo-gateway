package com.nihongo.gateway.configuration;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import static org.springframework.cloud.gateway.support.ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR;

/** Legacy test fixture. Runtime limits are persisted by SharedRateLimitFilter. */
@Deprecated // Explicit development/test fallback only; production uses SharedRateLimitFilter.
public class InMemoryRateLimitFilter implements GlobalFilter, Ordered {
    private static final int MAX_BUCKETS = 20000;
    private static final long IDLE_MILLIS = 600000;
    private final ConcurrentHashMap<String, Bucket> buckets = new ConcurrentHashMap<>();
    private final AtomicInteger requests = new AtomicInteger();

    @Override public int getOrder() { return -5; }

    @Override public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        Route route = exchange.getAttribute(GATEWAY_ROUTE_ATTR);
        if (route == null) return chain.filter(exchange);
        boolean ai = exchange.getRequest().getPath().value().endsWith("/api/nihongo-user/japanese");
        var address = exchange.getRequest().getRemoteAddress();
        String remote = address == null ? "unknown" : address.getHostString();
        return exchange.getPrincipal().map(principal -> principal.getName()).defaultIfEmpty(remote)
                .flatMap(identity -> {
                    if ((requests.incrementAndGet() & 255) == 0) removeIdleBuckets();
                    String key = route.getId() + ':' + identity;
                    if (buckets.size() >= MAX_BUCKETS && !buckets.containsKey(key)) return reject(exchange);
                    Bucket bucket = buckets.computeIfAbsent(key, ignored -> new Bucket(ai ? 60 : 20));
                    if (!bucket.consume(ai ? 1 : 10, ai ? 60 : 20, ai ? 10 : 1)) return reject(exchange);
                    return chain.filter(exchange);
                });
    }

    private Mono<Void> reject(ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(HttpStatus.TOO_MANY_REQUESTS);
        return exchange.getResponse().setComplete();
    }

    private void removeIdleBuckets() {
        long cutoff = System.currentTimeMillis() - IDLE_MILLIS;
        buckets.forEach((key, bucket) -> {
            if (bucket.lastUsed < cutoff) buckets.remove(key, bucket);
        });
    }

    private static final class Bucket {
        private double tokens;
        private long lastRefill = System.nanoTime();
        private volatile long lastUsed = System.currentTimeMillis();

        private Bucket(int capacity) { tokens = capacity; }

        private synchronized boolean consume(int refillPerSecond, int capacity, int cost) {
            long now = System.nanoTime();
            tokens = Math.min(capacity, tokens + Math.max(0, now - lastRefill) / 1_000_000_000d * refillPerSecond);
            lastRefill = now;
            lastUsed = System.currentTimeMillis();
            if (tokens < cost) return false;
            tokens -= cost;
            return true;
        }
    }
}
