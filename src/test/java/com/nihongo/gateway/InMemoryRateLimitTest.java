package com.nihongo.gateway;

import com.nihongo.gateway.configuration.InMemoryRateLimitFilter;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.InetSocketAddress;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.cloud.gateway.support.ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR;

class InMemoryRateLimitTest {
    @Test void aiRouteAllowsSixImmediateRequestsThenReturns429() {
        var filter = new InMemoryRateLimitFilter();
        GatewayFilterChain chain = mock(GatewayFilterChain.class);
        when(chain.filter(any())).thenReturn(Mono.empty());
        Route route = mock(Route.class);
        when(route.getId()).thenReturn("japanese-ai");
        for (int i = 0; i < 7; i++) {
            var exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/api/nihongo-user/japanese")
                    .remoteAddress(new InetSocketAddress("127.0.0.1", 12345)));
            exchange.getAttributes().put(GATEWAY_ROUTE_ATTR, route);
            filter.filter(exchange, chain).block();
            if (i == 6) assertEquals(429, exchange.getResponse().getStatusCode().value());
        }
        verify(chain, times(6)).filter(any());
    }
}
