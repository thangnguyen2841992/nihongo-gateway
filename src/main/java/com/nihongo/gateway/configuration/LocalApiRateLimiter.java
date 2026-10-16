package com.nihongo.gateway.configuration;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/** Fast bounded limiter for ordinary API traffic; sensitive actions still use the shared store. */
final class LocalApiRateLimiter {
    record Result(boolean allowed, long retryAfter) {}

    private static final int MAX_BUCKETS = 50_000;
    private static final long IDLE_MILLIS = 10 * 60_000L;
    private final ConcurrentHashMap<String, Bucket> buckets = new ConcurrentHashMap<>();
    private final AtomicInteger requests = new AtomicInteger();

    Result consume(String category, String identity) {
        if ((requests.incrementAndGet() & 255) == 0) removeIdleBuckets();
        String key = category + ':' + identity;
        if (buckets.size() >= MAX_BUCKETS && !buckets.containsKey(key)) return new Result(false, 1);
        double capacity = "API_USER".equals(category) ? 100 : 60;
        double refill = "API_USER".equals(category) ? 50 : 10;
        return buckets.computeIfAbsent(key, ignored -> new Bucket(capacity)).consume(capacity, refill);
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

        private Bucket(double capacity) { tokens = capacity; }

        private synchronized Result consume(double capacity, double refill) {
            long now = System.nanoTime();
            tokens = Math.min(capacity, tokens + Math.max(0, now - lastRefill) / 1_000_000_000d * refill);
            lastRefill = now;
            lastUsed = System.currentTimeMillis();
            if (tokens >= 1) {
                tokens -= 1;
                return new Result(true, 0);
            }
            return new Result(false, Math.max(1, (long) Math.ceil((1 - tokens) / refill)));
        }
    }
}
