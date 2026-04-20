package com.nihongo.gateway.configuration;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.Base64;

@Component
public class JwtCookieWebFilter implements WebFilter {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {

        var request = exchange.getRequest();
        String path = request.getURI().getPath();

        // ✅ 1. Bỏ qua auth API (login, refresh...)
        if (path.startsWith("/api/auth")) {
            return chain.filter(exchange);
        }

        // ✅ 2. Nếu frontend đã gửi token → không đụng
        if (request.getHeaders().containsKey("Authorization")) {
            return chain.filter(exchange);
        }

        var cookie = request.getCookies().getFirst("accessToken");

        if (cookie != null) {
            String token = cookie.getValue();

            // 🔥 3. CHECK TOKEN EXPIRED
            if (isTokenExpired(token)) {
                // ❗ KHÔNG inject token hết hạn
                return chain.filter(exchange);
            }

            ServerHttpRequest mutatedRequest = request.mutate()
                    .header("Authorization", "Bearer " + token)
                    .build();

            return chain.filter(exchange.mutate().request(mutatedRequest).build());
        }

        return chain.filter(exchange);
    }

    // 🔥 Decode JWT để check exp
    private boolean isTokenExpired(String token) {
        try {
            String[] parts = token.split("\\.");
            String payload = new String(Base64.getDecoder().decode(parts[1]));

            // extract exp (simple cách)
            long exp = Long.parseLong(payload.split("\"exp\":")[1].split(",")[0]);

            long now = System.currentTimeMillis() / 1000;

            return exp < now;

        } catch (Exception e) {
            return true; // lỗi → coi như hết hạn
        }
    }
}