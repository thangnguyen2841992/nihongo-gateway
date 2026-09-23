package com.nihongo.gateway;

import com.nihongo.gateway.configuration.SecurityConfig;
import com.nihongo.gateway.configuration.JwtCookieWebFilter;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.*;

@WebFluxTest(controllers = PublicCoursesSecurityTest.ProbeController.class)
@Import({SecurityConfig.class, JwtCookieWebFilter.class, PublicCoursesSecurityTest.ProbeController.class})
class PublicCoursesSecurityTest {
    @Autowired WebTestClient client;
    @RestController static class ProbeController {
        @GetMapping("/api/nihongo-user/courses") String catalog() { return "catalog"; }
    }
    @Test void anonymousCatalogIsPublic() {
        client.get().uri("/api/nihongo-user/courses").exchange().expectStatus().isOk();
    }
    @Test void privateApisAndWritesRemainProtected() {
        client.get().uri("/api/nihongo-user/wallets").exchange().expectStatus().isUnauthorized();
        client.get().uri("/api/nihongo-user/my-courses-dto").exchange().expectStatus().isUnauthorized();
        client.post().uri("/api/nihongo-user/courses").exchange().expectStatus().isUnauthorized();
        client.post().uri("/api/nihongo-user/subscriptions").exchange().expectStatus().isUnauthorized();
    }
}
