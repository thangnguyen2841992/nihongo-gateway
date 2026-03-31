package com.nihongo.gateway.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.security.Principal;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@Component
public class JwtHeaderFilter extends AbstractGatewayFilterFactory<JwtHeaderFilter.Config> {

    public JwtHeaderFilter() {
        super(Config.class);
    }

    @Value("${api.key}")
    private String apiKey;

    @Value("${api.client-id}")
    private String clientId;

    private static final Logger log = LoggerFactory.getLogger(JwtHeaderFilter.class);

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {

            String path = exchange.getRequest().getURI().getPath();

            // ✅ BỎ QUA auth endpoints
            if (path.startsWith("/api/auth/")) {
                return chain.filter(exchange);
            }

            String key = exchange.getRequest().getHeaders().getFirst("X-API-Key");

            if (key == null) {
                return handleException(exchange, "Missing API Key", HttpStatus.UNAUTHORIZED);
            }

            if (!apiKey.equals(key)) {
                return handleException(exchange, "Invalid API Key", HttpStatus.FORBIDDEN);
            }

            return exchange.getPrincipal()
                    .flatMap(principal -> process(exchange, chain, principal))
                    .switchIfEmpty(Mono.defer(() ->
                            handleException(exchange, "Missing JWT", HttpStatus.UNAUTHORIZED)
                    ));
        };
    }

//    @Override
//    public GatewayFilter apply(Config config) {
//
//        return (exchange, chain) -> {
//
//            // 🔐 1. Check API KEY (từ client)
//            List<String> apiKeyHeaders = exchange.getRequest().getHeaders().get("apiKey");
//
//            if (apiKeyHeaders == null || apiKeyHeaders.isEmpty()) {
//                return handleException(exchange, "Missing API Key", HttpStatus.UNAUTHORIZED);
//            }
//
//            String key = apiKeyHeaders.get(0);
//
//            if (!apiKey.equals(key)) {
//                return handleException(exchange, "Invalid API Key", HttpStatus.FORBIDDEN);
//            }
//
//            // 👉 2. Xử lý JWT + add header
//            return exchange.getPrincipal()
//                    .flatMap(principal -> process(exchange, chain, principal))
//                    .switchIfEmpty(process(exchange, chain, null));
//        };
//    }

    private Mono<Void> process(ServerWebExchange exchange,
                               GatewayFilterChain chain,
                               Principal principal) {

        ServerHttpRequest.Builder requestBuilder = exchange.getRequest().mutate();


        if (!(principal instanceof JwtAuthenticationToken jwtAuth)) {
            return handleException(exchange, "Invalid JWT", HttpStatus.UNAUTHORIZED);
        }
        // 🔐 Internal token (giữa gateway ↔ service)
        requestBuilder.header("X-Gateway-Token", apiKey);
        var claims = jwtAuth.getToken().getClaims();

        String userId = Objects.toString(claims.get("sub"), "");
        String username = Objects.toString(claims.get("preferred_username"), "");

        log.debug("UserId: {}, Username: {}", userId, username);


        List<String> roles = new ArrayList<>();

        Object resourceAccessObj = claims.get("resource_access");

        if (resourceAccessObj instanceof Map<?, ?> resourceAccess) {
            Object clientObj = resourceAccess.get(clientId);

            if (clientObj instanceof Map<?, ?> client) {
                Object rolesObj = client.get("roles");

                if (rolesObj instanceof List<?> roleList) {
                    roles = roleList.stream()
                            .map(Object::toString)
                            .toList();
                }
            }
        }

//        if (resourceAccess != null) {
//            Map<String, Object> client =
//                    (Map<String, Object>) resourceAccess.get(clientId);
//
//            if (client != null && client.get("roles") != null) {
//                roles = (List<String>) client.get("roles");
//            }
//        }

        String roleHeader = String.join(",", roles);
//        System.out.println("Roles: " + roleHeader);
        log.debug("Roles: {}", roleHeader);

        requestBuilder
                .header("X-User-Id", userId)
                .header("X-Username", username)
                .header("X-Roles", roleHeader);

        ServerHttpRequest mutatedRequest = requestBuilder.build();
        return chain.filter(exchange.mutate().request(mutatedRequest).build());
    }

    private Mono<Void> handleException(ServerWebExchange exchange,
                                       String message,
                                       HttpStatus status) {

        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(status);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        String errorResponse = String.format(
                "{\"timestamp\": \"%s\", \"status\": %d, \"error\": \"%s\", \"message\": \"%s\", \"path\": \"%s\"}",
                ZonedDateTime.now(),
                status.value(),
                status.getReasonPhrase(),
                message,
                exchange.getRequest().getURI().getPath()
        );

        return response.writeWith(
                Mono.just(response.bufferFactory().wrap(errorResponse.getBytes()))
        );
    }

    static class Config {}
}