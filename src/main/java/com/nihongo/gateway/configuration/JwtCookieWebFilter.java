package com.nihongo.gateway.configuration;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

@Component
public class JwtCookieWebFilter implements WebFilter {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {

        var request = exchange.getRequest();

        String path = request.getURI().getPath();

        /*
         * Auth API:
         * login
         * refresh
         * logout
         * checkLogin
         * checkEmail
         *
         * Không inject accessToken ở đây.
         */
        if (path.startsWith("/api/auth")) {
            return chain.filter(exchange);
        }

        /*
         * Nếu request đã có Authorization
         * thì giữ nguyên.
         */
        if (request.getHeaders().containsKey("Authorization")) {
            return chain.filter(exchange);
        }

        /*
         * Lấy JWT từ HttpOnly Cookie.
         */
        var cookie = request.getCookies().getFirst("accessToken");

        if (cookie == null) {
            return chain.filter(exchange);
        }

        String token = cookie.getValue();

        if (token.isBlank()) {
            return chain.filter(exchange);
        }

        /*
         * Cookie:
         *
         * accessToken=xxxxx
         *
         * chuyển thành:
         *
         * Authorization: Bearer xxxxx
         */
        ServerHttpRequest mutatedRequest = request.mutate().header("Authorization", "Bearer " + token).build();

        return chain.filter(exchange.mutate().request(mutatedRequest).build());
    }
}