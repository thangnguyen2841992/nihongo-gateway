package com.nihongo.gateway;
import com.nihongo.gateway.configuration.*;
import com.nihongo.security.*;
import org.junit.jupiter.api.*;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.http.*;
import org.springframework.core.io.buffer.*;
import org.springframework.web.reactive.function.client.*;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;
import java.net.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.cloud.gateway.support.ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR;

class GatewayHardeningTest {
 InternalCredentials key(){return new InternalCredentials(new MockEnvironment().withProperty("security.internal.key",Base64.getEncoder().encodeToString(new byte[32])));}
 @Test void forwardingHeadersAreUsedOnlyBehindExplicitTrustedProxies(){
  var request=MockServerHttpRequest.get("/api").remoteAddress(new InetSocketAddress("127.0.0.1",1234)).header("X-Forwarded-For","203.0.113.7, 10.0.0.2");var exchange=MockServerWebExchange.from(request);
  assertEquals("127.0.0.1",new ClientAddressResolver("").identity(exchange));assertEquals("203.0.113.7",new ClientAddressResolver("127.0.0.1/32,10.0.0.0/8").identity(exchange));
  var forged=MockServerWebExchange.from(MockServerHttpRequest.get("/api").remoteAddress(new InetSocketAddress("203.0.113.9",1234)).header("X-Forwarded-For","1.2.3.4"));assertEquals("203.0.113.9",new ClientAddressResolver("127.0.0.1/32").identity(forged));
 }
 @Test void ambiguousPathsAndUntrustedCookieOriginsAreRejectedBeforeRouting(){
  var guard=new BrowserOriginWebFilter(new BrowserOriginPolicy(new String[]{"http://localhost:5173"}),true);var chain=mock(org.springframework.web.server.WebFilterChain.class);
  for(String path:new String[]{"/api/nihongo-user/japanese;extra=1","/api/%2fnihongo-user/japanese","/api/%256eihongo-user/japanese"}){var e=MockServerWebExchange.from(MockServerHttpRequest.get(path));guard.filter(e,chain).block();assertEquals(400,e.getResponse().getStatusCode().value());}
  var e=MockServerWebExchange.from(MockServerHttpRequest.post("/api/auth/logout").cookie(new org.springframework.http.HttpCookie("accessToken","token")).header("Origin","http://evil.example"));guard.filter(e,chain).block();assertEquals(403,e.getResponse().getStatusCode().value());verifyNoInteractions(chain);
 }
 @Test void loginIsLimitedByIpAndAccountAndBodyIsPreserved()throws Exception{
  var captured=new AtomicReference<String>();var creds=key();var builder=WebClient.builder().exchangeFunction(request->{assertEquals(creds.value(),request.headers().getFirst(InternalCredentials.HEADER));return Mono.just(ClientResponse.create(HttpStatus.OK).header("Content-Type","application/json").body("{\"allowed\":true,\"retryAfter\":0}").build());});
  var filter=new SharedRateLimitFilter(builder,creds,new ClientAddressResolver(""),"http://127.0.0.1/internal");String body="{\"email\":\" TEST@example.com \",\"password\":\"secret\"}";var exchange=MockServerWebExchange.from(MockServerHttpRequest.post("/api/auth/login").remoteAddress(new InetSocketAddress("127.0.0.1",1234)).contentType(MediaType.APPLICATION_JSON).body(body));
  filter.filter(exchange,e->DataBufferUtils.join(e.getRequest().getBody()).doOnNext(b->{byte[] bytes=new byte[b.readableByteCount()];b.read(bytes);DataBufferUtils.release(b);captured.set(new String(bytes,java.nio.charset.StandardCharsets.UTF_8));}).then()).block();assertEquals(body,captured.get());
 }
 @Test void arbitraryRouteIdsCannotSkipLimiterAndDenialDoesNotReachBackend(){
  var builder=WebClient.builder().exchangeFunction(r->Mono.just(ClientResponse.create(HttpStatus.OK).header("Content-Type","application/json").body("{\"allowed\":false,\"retryAfter\":10}").build()));var f=new SharedRateLimitFilter(builder,key(),new ClientAddressResolver(""),"http://127.0.0.1/internal");var chain=mock(GatewayFilterChain.class);
  var e=MockServerWebExchange.from(MockServerHttpRequest.post("/api/nihongo-user/japanese").remoteAddress(new InetSocketAddress("127.0.0.1",1234)));e.getAttributes().put(GATEWAY_ROUTE_ATTR,Route.async().id("discovery-alternative").uri("http://127.0.0.1").asyncPredicate(x->Mono.just(true)).build());f.filter(e,chain).block();assertEquals(429,e.getResponse().getStatusCode().value());assertEquals("10",e.getResponse().getHeaders().getFirst("Retry-After"));verifyNoInteractions(chain);
 }
 @Test void limiterOutageFailsClosedWith503(){var builder=WebClient.builder().exchangeFunction(r->Mono.error(new java.io.IOException("offline")));var f=new SharedRateLimitFilter(builder,key(),new ClientAddressResolver(""),"http://127.0.0.1/internal");var chain=mock(GatewayFilterChain.class);var e=MockServerWebExchange.from(MockServerHttpRequest.get("/api/nihongo-user/courses"));var error=assertThrows(ResponseStatusException.class,()->f.filter(e,chain).block());assertEquals(503,error.getStatusCode().value());verifyNoInteractions(chain);}
}
