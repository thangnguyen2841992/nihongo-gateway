package com.nihongo.gateway;

import com.nihongo.gateway.configuration.SecurityConfig;
import com.nihongo.gateway.configuration.JwtCookieWebFilter;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.*;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.*;
import java.nio.file.*;
import java.security.*;
import java.time.Instant;
import java.util.*;

@WebFluxTest(controllers = PublicCoursesSecurityTest.ProbeController.class,
        properties = {"spring.config.import=", "security.jwt.mode=rsa", "security.jwt.validate-claims=true",
            "security.origin-check.enabled=true", "FRONTEND_ORIGIN=http://localhost:5173",
            "security.internal.key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="})
@Import({SecurityConfig.class, JwtCookieWebFilter.class, PublicCoursesSecurityTest.ProbeController.class})
class PublicCoursesSecurityTest {
    @Autowired WebTestClient client;
    @BeforeEach void baseUrl() { client = client.mutate().baseUrl("http://localhost:8082").build(); }
    static final KeyPair pair;
    static final Path publicKey;
    static {
        try {
            var generator = KeyPairGenerator.getInstance("RSA"); generator.initialize(2048);
            pair = generator.generateKeyPair(); publicKey = Files.createTempFile("gateway-rsa-test", ".pem");
            Files.writeString(publicKey, "-----BEGIN PUBLIC KEY-----\n" + Base64.getMimeEncoder(64, new byte[]{10})
                    .encodeToString(pair.getPublic().getEncoded()) + "\n-----END PUBLIC KEY-----");
        } catch (Exception error) { throw new ExceptionInInitializerError(error); }
    }
    @DynamicPropertySource static void keys(DynamicPropertyRegistry registry) {
        registry.add("security.jwt.public-key-path", publicKey::toString);
    }
    @AfterAll static void removeKey() throws Exception { Files.deleteIfExists(publicKey); }
    @RestController static class ProbeController {
        @GetMapping("/api/nihongo-user/courses") String catalog() { return "catalog"; }
        @GetMapping("/api/staff/public/levels/1/syllabus") String syllabus() { return "syllabus"; }
        @GetMapping("/api/staff/types") String staff(@RequestHeader("Authorization") String authorization) { return authorization; }
        @GetMapping({"/api/admin/probe", "/api/nihongo-user/admin/probe", "/api/notification/admin/operations", "/api/staff/content/audit/probe",
                "/NIHONGO-USER-SERVICE/api/nihongo-user/japanese", "/api/auth/internal/probe", "/api/auth/session/validate"})
        String restricted() { return "private"; }
        @PostMapping("/api/nihongo-user/subscriptions") String purchase() { return "created"; }
    }
    String token(String role, String issuer, String type) throws Exception {
        var jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), new JWTClaimsSet.Builder()
                .subject("test-user").issuer(issuer).audience("nihongo-api")
                .claim("roles", List.of(role)).claim("type", type).claim("sessionId", "test-session")
                .expirationTime(Date.from(Instant.now().plusSeconds(60))).build());
        jwt.sign(new RSASSASigner(pair.getPrivate())); return jwt.serialize();
    }
    @Test void anonymousCatalogIsPublic() {
        client.get().uri("/api/nihongo-user/courses").exchange().expectStatus().isOk();
    }
    @Test void anonymousSyllabusIsPublicButOtherStaffApisAreNot() {
        client.get().uri("/api/staff/public/levels/1/syllabus").exchange().expectStatus().isOk();
        client.get().uri("/api/staff/types").exchange().expectStatus().isUnauthorized();
    }
    @Test void privateApisAndWritesRemainProtected() {
        client.get().uri("/api/nihongo-user/wallets").exchange().expectStatus().isUnauthorized();
        client.get().uri("/api/nihongo-user/my-courses-dto").exchange().expectStatus().isUnauthorized();
        client.post().uri("/api/nihongo-user/subscriptions").header("Origin", "http://localhost:5173")
                .exchange().expectStatus().isUnauthorized();
    }
    @Test void accessCookieIsVerifiedAndForwardedAsBearerForPrivateApis() throws Exception {
        String jwt = token("STAFF", "nihongo-auth", "access");
        client.get().uri("/api/staff/types").cookie("accessToken", jwt).exchange()
                .expectStatus().isOk().expectBody(String.class).isEqualTo("Bearer " + jwt);
    }
    @Test void cookieWritesRequireTrustedSource() throws Exception {
        String jwt = token("USER", "nihongo-auth", "access");
        client.post().uri("/api/nihongo-user/subscriptions").cookie("accessToken", jwt)
                .exchange().expectStatus().isForbidden();
        client.post().uri("/api/nihongo-user/subscriptions").cookie("accessToken", jwt)
                .header("Origin", "https://evil.example.com").exchange().expectStatus().isForbidden();
        client.post().uri("/api/nihongo-user/subscriptions").cookie("accessToken", jwt)
                .header("Origin", "http://localhost:5173").exchange().expectStatus().isOk();
    }
    @Test void discoveryAndInternalPathsRemainDeniedEvenToAdministrators() throws Exception {
        for (String path : List.of("/NIHONGO-USER-SERVICE/api/nihongo-user/japanese", "/api/auth/internal/probe", "/api/auth/session/validate"))
            client.get().uri(path).header("Authorization", "Bearer " + token("ADMIN", "nihongo-auth", "access"))
                    .header("X-Nihongo-Internal", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
                    .exchange().expectStatus().isForbidden();
    }
    @Test void adminFunctionsRejectStaffAndAcceptAdmin() throws Exception {
        for (String path : List.of("/api/admin/probe", "/api/nihongo-user/admin/probe", "/api/notification/admin/operations", "/api/staff/content/audit/probe")) {
            client.get().uri(path).cookie("accessToken", token("STAFF", "nihongo-auth", "access"))
                    .exchange().expectStatus().isForbidden();
            client.get().uri(path).cookie("accessToken", token("ADMIN", "nihongo-auth", "access"))
                    .exchange().expectStatus().isOk();
        }
    }
    @Test void wrongIssuerAndRefreshTokensCannotBeUsedAsAccessTokens() throws Exception {
        client.get().uri("/api/staff/types").cookie("accessToken", token("STAFF", "wrong", "access"))
                .exchange().expectStatus().isUnauthorized();
        client.get().uri("/api/staff/types").cookie("accessToken", token("STAFF", "nihongo-auth", "refresh"))
                .exchange().expectStatus().isUnauthorized();
    }
}
