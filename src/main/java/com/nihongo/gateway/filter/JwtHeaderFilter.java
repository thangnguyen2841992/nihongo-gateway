package com.nihongo.gateway.filter;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.security.Principal;

@Component
public class JwtHeaderFilter extends AbstractGatewayFilterFactory<JwtHeaderFilter.Config> {

    public JwtHeaderFilter() {
        super(Config.class);
    }

    @Value("${api.key}")
    private String interPrivateKey;

    @Override
    public GatewayFilter apply(JwtHeaderFilter.Config config) {

        return (exchange, chain) ->
                exchange.getPrincipal()
                        .flatMap(principal -> process(exchange, chain, principal))
                        .switchIfEmpty(process(exchange, chain, null));
    }

    private Mono<Void> process(ServerWebExchange exchange, GatewayFilterChain chain, Principal principal) {

        ServerHttpRequest.Builder requestBuilder = exchange.getRequest().mutate();

        requestBuilder.header("X-Gateway-Token", interPrivateKey);

        if (principal instanceof JwtAuthenticationToken jwtAuth) {
            var claims = jwtAuth.getToken().getClaims();

            var userId = claims.get("sub") != null ? claims.get("sub").toString() : "";
            var username = claims.get("preferred_username") != null ? claims.get("preferred_username").toString() : "";

            System.out.println("Setting headers X-User-Id: " + userId + " X-Username: " + username);

            requestBuilder
                    .header("X-User-Id", userId)
                    .header("X-Username", username);
        }

        ServerHttpRequest mutatedRequest = requestBuilder.build();
        ServerWebExchange mutatedExchange = exchange.mutate().request(mutatedRequest).build();

        return chain.filter(mutatedExchange);
    }

    static class Config {
    }
}