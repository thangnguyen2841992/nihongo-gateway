package com.nihongo.gateway;

import com.nihongo.gateway.configuration.SessionValidationFilter;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.data.redis.core.ReactiveHashOperations;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import reactor.core.publisher.Mono;
import java.util.List;
import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;

class SessionValidationTest {
    ReactiveStringRedisTemplate redis = mock(ReactiveStringRedisTemplate.class);
    @SuppressWarnings("unchecked") ReactiveHashOperations<String, Object, Object> hashes = mock(ReactiveHashOperations.class);
    GatewayFilterChain chain = mock(GatewayFilterChain.class);
    SessionValidationFilter filter = new SessionValidationFilter(redis);
    org.springframework.web.server.ServerWebExchange exchange(String type) {
        var jwt = Jwt.withTokenValue("test").header("alg", "HS256").subject("user").claim("type", type).claim("sessionId", "sid").build();
        return MockServerWebExchange.from(MockServerHttpRequest.get("/api/nihongo-user/wallets")).mutate()
            .principal(Mono.just(new JwtAuthenticationToken(jwt))).build();
    }
    void state(long expiry, long idle, String sid) {
        when(redis.opsForHash()).thenReturn(hashes);
        when(hashes.multiGet(anyString(), anyCollection())).thenReturn(Mono.just(List.of(sid, Long.toString(expiry), Long.toString(idle))));
        when(chain.filter(any())).thenReturn(Mono.empty());
    }
    @Test void validSessionPassesWithoutExtendingIdle() {
        state(System.currentTimeMillis()+100000, System.currentTimeMillis()+10000, "sid");
        filter.filter(exchange("access"), chain).block();
        verify(chain).filter(any()); verify(hashes).multiGet(anyString(), anyCollection()); verifyNoMoreInteractions(hashes);
    }
    @Test void expiredIdleAndReplacedSessionsAreRejected() {
        for (boolean idle : new boolean[]{true, false}) {
            state(System.currentTimeMillis()+100000, idle ? 1 : System.currentTimeMillis()+10000, idle ? "sid" : "new-session");
            var exchange = exchange("access"); filter.filter(exchange, chain).block();
            assertEquals(401, exchange.getResponse().getStatusCode().value());
        }
        verify(chain, never()).filter(any());
    }
    @Test void redisFailureIs503AndDoesNotForwardRequest() {
        when(redis.opsForHash()).thenReturn(hashes);
        when(hashes.multiGet(anyString(), anyCollection())).thenReturn(Mono.error(new RedisConnectionFailureException("offline")));
        var error = assertThrows(org.springframework.web.server.ResponseStatusException.class, () -> filter.filter(exchange("access"), chain).block());
        assertEquals(503, error.getStatusCode().value()); verifyNoInteractions(chain);
    }
    @Test void refreshTokenCannotAuthorizeApi() {
        var exchange = exchange("refresh"); filter.filter(exchange, chain).block();
        assertEquals(401, exchange.getResponse().getStatusCode().value()); verifyNoInteractions(redis, chain);
    }
}
