package com.nihongo.gateway;

import com.nihongo.gateway.configuration.*;
import com.nihongo.security.*;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import java.net.InetSocketAddress;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicReference;
import reactor.core.publisher.Mono;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class LoginAddressFilterTest {
    InternalCredentials key() { return new InternalCredentials(new MockEnvironment().withProperty("security.internal.key", Base64.getEncoder().encodeToString(new byte[32]))); }
    MockEnvironment env(String... profiles) {
        var env = new MockEnvironment().withProperty("security.login-audit.capture-local-network", "true");
        env.setActiveProfiles(profiles); return env;
    }
    @Test void replacesBrowserSpoofingAndCapturesLanForDirectLocalhostOnly() {
        var local = mock(LocalNetworkAddresses.class); when(local.snapshot()).thenReturn("192.168.1.8");
        var filter = new LoginAddressFilter(key(), new ClientAddressResolver(""), local, env("local"));
        var exchange = MockServerWebExchange.from(MockServerHttpRequest.post("/api/auth/login")
            .remoteAddress(new InetSocketAddress("127.0.0.1", 1234))
            .header(LoginAddressEnvelope.HEADER, "forged").header("X-Forwarded-For", "8.8.8.8"));
        var captured = new AtomicReference<String>();
        filter.filter(exchange, e -> { captured.set(e.getRequest().getHeaders().getFirst(LoginAddressEnvelope.HEADER)); return Mono.empty(); }).block();
        var address = new LoginAddressEnvelope(key()).verify(captured.get(), "POST", "/api/auth/login").orElseThrow();
        assertEquals("127.0.0.1", address.ip()); assertEquals("192.168.1.8", address.localAddresses());
    }
    @Test void remoteUsersAndTrustedProxiesNeverReceiveGatewayLanAsTheirOwn() {
        for (boolean proxy : new boolean[]{false, true}) {
            var local = mock(LocalNetworkAddresses.class);
            var filter = new LoginAddressFilter(key(), new ClientAddressResolver(proxy ? "127.0.0.1/32" : ""), local, env("local"));
            var exchange = MockServerWebExchange.from(MockServerHttpRequest.post("/api/auth/login")
                .remoteAddress(new InetSocketAddress(proxy ? "127.0.0.1" : "192.168.1.9", 1234)).header("X-Forwarded-For", "192.168.1.9"));
            filter.filter(exchange, e -> {
                var address = new LoginAddressEnvelope(key()).verify(e.getRequest().getHeaders().getFirst(LoginAddressEnvelope.HEADER), "POST", "/api/auth/login").orElseThrow();
                assertEquals("192.168.1.9", address.ip()); assertEquals("", address.localAddresses()); return Mono.empty();
            }).block();
            verifyNoInteractions(local);
        }
    }
    @Test void productionNeverCapturesLocalNetworkEvenWhenPropertyIsEnabled() {
        for (String[] profiles : new String[][]{{"prod"}, {"local", "prod"}, {"production"}}) {
            var local = mock(LocalNetworkAddresses.class);
            var filter = new LoginAddressFilter(key(), new ClientAddressResolver(""), local, env(profiles));
            var exchange = MockServerWebExchange.from(MockServerHttpRequest.post("/api/auth/login").remoteAddress(new InetSocketAddress("127.0.0.1", 1234)));
            filter.filter(exchange, e -> {
                assertEquals("", new LoginAddressEnvelope(key()).verify(e.getRequest().getHeaders().getFirst(LoginAddressEnvelope.HEADER), "POST", "/api/auth/login").orElseThrow().localAddresses());
                return Mono.empty();
            }).block(); verifyNoInteractions(local);
        }
    }
}
