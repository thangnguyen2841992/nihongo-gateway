package com.nihongo.gateway;

import com.nihongo.gateway.configuration.SessionValidationFilter;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class SessionValidationTest {
    private final GatewayFilterChain chain = mock(GatewayFilterChain.class);

    private org.springframework.web.server.ServerWebExchange exchange(String type) {
        var jwt = Jwt.withTokenValue("signed-token").header("alg", "HS256")
                .subject("user").claim("type", type).claim("sessionId", "sid").build();
        return MockServerWebExchange.from(MockServerHttpRequest.get("/api/nihongo-user/wallets"))
                .mutate().principal(Mono.just(new JwtAuthenticationToken(jwt))).build();
    }

    @Test void validSessionPassesAndSendsSignedToken() {
        when(chain.filter(any())).thenReturn(Mono.empty());
        AtomicInteger calls = new AtomicInteger();
        var builder = WebClient.builder().exchangeFunction(request -> {
            assertEquals("Bearer signed-token", request.headers().getFirst("Authorization"));
            calls.incrementAndGet();
            return Mono.just(ClientResponse.create(HttpStatus.NO_CONTENT).build());
        });
        new SessionValidationFilter(builder, "http://127.0.0.1:8081/api/auth/session/validate")
                .filter(exchange("access"), chain).block();
        assertEquals(1, calls.get());
        verify(chain).filter(any());
    }

    @Test void revokedSessionIsRejected() {
        var builder = WebClient.builder().exchangeFunction(request ->
                Mono.just(ClientResponse.create(HttpStatus.UNAUTHORIZED).build()));
        var exchange = exchange("access");
        new SessionValidationFilter(builder, "http://127.0.0.1:8081/api/auth/session/validate")
                .filter(exchange, chain).block();
        assertEquals(401, exchange.getResponse().getStatusCode().value());
        assertEquals("session-invalid", exchange.getResponse().getHeaders().getFirst("X-Auth-Failure"));
        verifyNoInteractions(chain);
    }

    @Test void unavailableUserServiceFailsClosed() {
        var builder = WebClient.builder().exchangeFunction(request -> Mono.error(new IOException("offline")));
        var error = assertThrows(ResponseStatusException.class, () ->
                new SessionValidationFilter(builder, "http://127.0.0.1:8081/api/auth/session/validate")
                        .filter(exchange("access"), chain).block());
        assertEquals(503, error.getStatusCode().value());
        verifyNoInteractions(chain);
    }

    @Test void refreshTokenCannotAuthorizeApi() {
        var builder = WebClient.builder().exchangeFunction(request -> fail("Must not contact user-service"));
        var exchange = exchange("refresh");
        new SessionValidationFilter(builder, "http://127.0.0.1:8081/api/auth/session/validate")
                .filter(exchange, chain).block();
        assertEquals(401, exchange.getResponse().getStatusCode().value());
        verifyNoInteractions(chain);
    }
}
