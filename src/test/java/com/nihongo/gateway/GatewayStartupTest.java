package com.nihongo.gateway;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.beans.factory.annotation.Value;
import java.net.URI;
import java.net.http.*;
import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "spring.config.import=", "eureka.client.enabled=false", "spring.cloud.discovery.enabled=false",
        "security.jwt.mode=rsa", "security.jwt.validate-claims=true", "security.origin-check.enabled=true",
        "security.session-validation.enabled=true",
        "auth.rate-limit-url=http://127.0.0.1:65530/api/auth/internal/rate-limit",
        "security.internal.key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
})
class GatewayStartupTest {
    @Value("${local.server.port}") int port;
    @Test void fullGatewayStartsAndLimiterOutageBlocksActualHttpRequests() throws Exception {
        var request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/api/nihongo-user/courses"))
                .timeout(java.time.Duration.ofSeconds(10)).GET().build();
        assertEquals(503, HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.discarding()).statusCode());
    }
}
