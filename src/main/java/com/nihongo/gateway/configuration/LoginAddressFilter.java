package com.nihongo.gateway.configuration;

import com.nihongo.security.*;
import org.springframework.cloud.gateway.filter.*;
import org.springframework.core.Ordered;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class LoginAddressFilter implements GlobalFilter, Ordered {
    private final LoginAddressEnvelope envelope;
    private final ClientAddressResolver resolver;
    private final LocalNetworkAddresses localNetwork;
    private final boolean captureLocalNetwork;

    public LoginAddressFilter(InternalCredentials credentials, ClientAddressResolver resolver,
                              LocalNetworkAddresses localNetwork, Environment env) {
        this.envelope = new LoginAddressEnvelope(credentials);
        this.resolver = resolver;
        this.localNetwork = localNetwork;
        this.captureLocalNetwork = env.matchesProfiles("local & !prod & !production")
            && env.getProperty("security.login-audit.capture-local-network", Boolean.class, false);
    }

    @Override public int getOrder() { return -15; }
    @Override public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        var request = exchange.getRequest();
        String path = SecurityRequestPaths.canonical(request.getURI());
        String signed = null;
        if (path.startsWith("/api/auth/")) {
            String ip = resolver.identity(exchange);
            if (!"unknown".equals(ip)) {
                String local = captureLocalNetwork && resolver.directLoopback(exchange) ? localNetwork.snapshot() : "";
                signed = envelope.sign(request.getMethod().name(), path, ip, local);
            }
        }
        final String header = signed;
        var forwarded = request.mutate().headers(headers -> {
            headers.remove(LoginAddressEnvelope.HEADER);
            if (header != null) headers.set(LoginAddressEnvelope.HEADER, header);
        }).build();
        return chain.filter(exchange.mutate().request(forwarded).build());
    }
}
