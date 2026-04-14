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

        if (path.startsWith("/api/auth")) {
            return chain.filter(exchange);
        }

        if (request.getHeaders().containsKey("Authorization")) {
            return chain.filter(exchange);
        }

        var cookies = request.getCookies().getFirst("accessToken");

        if (cookies != null) {
            String token = cookies.getValue();

            ServerHttpRequest mutatedRequest = request.mutate()
                    .header("Authorization", "Bearer " + token)
                    .build();

            return chain.filter(exchange.mutate().request(mutatedRequest).build());
        }

        return chain.filter(exchange);
    }
}
