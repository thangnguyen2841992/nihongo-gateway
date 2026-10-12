package com.nihongo.gateway.configuration;
import com.nihongo.security.*;import org.springframework.web.server.*;import org.springframework.http.HttpStatus;import reactor.core.publisher.Mono;
public class BrowserOriginWebFilter implements WebFilter {
 private final BrowserOriginPolicy policy;private final boolean enabled;
 public BrowserOriginWebFilter(BrowserOriginPolicy policy,boolean enabled){this.policy=policy;this.enabled=enabled;}
 @Override public Mono<Void> filter(ServerWebExchange exchange,WebFilterChain chain){
  var r=exchange.getRequest();try{SecurityRequestPaths.canonical(r.getURI());}catch(IllegalArgumentException e){exchange.getResponse().setStatusCode(HttpStatus.BAD_REQUEST);return exchange.getResponse().setComplete();}boolean cookie=r.getCookies().containsKey("accessToken")||r.getCookies().containsKey("refreshToken");String bearer=r.getHeaders().getFirst("Authorization");
  if(enabled&&!policy.allowed(r.getMethod().name(),r.getHeaders().getOrigin(),r.getHeaders().getFirst("Referer"),cookie,bearer!=null&&bearer.startsWith("Bearer "))){exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);return exchange.getResponse().setComplete();}
  var clean=r.mutate().headers(h->{h.remove(InternalCredentials.HEADER);h.remove("X-Session-Validated");h.remove(LoginAddressEnvelope.HEADER);}).build();return chain.filter(exchange.mutate().request(clean).build());
 }
}
