package com.nihongo.gateway.configuration;
import com.nihongo.security.InternalCredentials;import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;import org.springframework.cloud.gateway.filter.*;import org.springframework.core.Ordered;import org.springframework.core.io.buffer.*;import org.springframework.http.*;import org.springframework.http.server.reactive.*;import org.springframework.stereotype.Component;import org.springframework.web.server.*;import org.springframework.web.reactive.function.client.WebClient;import reactor.core.publisher.*;import java.time.Duration;import java.util.*;
@Component public class SharedRateLimitFilter implements GlobalFilter,Ordered {
 public record Limit(String category,String identity){} public record Result(boolean allowed,long retryAfter){}
 private final WebClient client;private final String endpoint;private final InternalCredentials internal;private final ClientAddressResolver addresses;private final ObjectMapper json=new ObjectMapper();private final LocalApiRateLimiter local=new LocalApiRateLimiter();private final boolean localGeneralLimits;
 public SharedRateLimitFilter(WebClient.Builder builder,InternalCredentials internal,ClientAddressResolver addresses,String endpoint){this(builder,internal,addresses,endpoint,true);}
 @org.springframework.beans.factory.annotation.Autowired public SharedRateLimitFilter(WebClient.Builder builder,InternalCredentials internal,ClientAddressResolver addresses,@Value("${auth.rate-limit-url:http://127.0.0.1:8081/api/auth/internal/rate-limit}") String endpoint,@Value("${auth.local-general-rate-limit:true}") boolean localGeneralLimits){this.client=builder.build();this.internal=internal;this.addresses=addresses;this.endpoint=endpoint;this.localGeneralLimits=localGeneralLimits;}
 static final Set<String> SESSION_STATUS_PATHS=Set.of("/api/auth/checkLogin","/api/auth/activity");
 // Token refresh (every 15 min per user), logout and the email-format check are routine and touch no password:
 // they are limited in-process. Login, registration, recovery and the other auth endpoints keep the shared DB store.
 static final Set<String> SESSION_UPKEEP_PATHS=Set.of("/api/auth/refresh","/api/auth/logout","/api/auth/checkEmail");
 static final Set<String> LOCAL_CATEGORIES=Set.of("AUTH_SESSION_IP","AUTH_UPKEEP_IP");
 @Override public int getOrder(){return -20;}
 @Override public Mono<Void> filter(ServerWebExchange exchange,GatewayFilterChain chain){
  String path=com.nihongo.security.SecurityRequestPaths.canonical(exchange.getRequest().getURI());String ip=addresses.identity(exchange);
  if(path.equals("/api/auth/login")&&exchange.getRequest().getMethod()==HttpMethod.POST){
   return DataBufferUtils.join(exchange.getRequest().getBody(),16384).defaultIfEmpty(exchange.getResponse().bufferFactory().wrap(new byte[0])).flatMap(buffer->{
    byte[] bytes=new byte[buffer.readableByteCount()];buffer.read(bytes);DataBufferUtils.release(buffer);String email;
    try{var body=json.readTree(bytes);var e=body==null?null:body.get("email");if(e!=null&&!e.isTextual())return reject(exchange,400,0);email=e==null?"":e.asText().trim().toLowerCase(Locale.ROOT);if(email.length()>320)return reject(exchange,400,0);}catch(Exception e){return reject(exchange,400,0);}
    List<Limit> limits=new ArrayList<>();limits.add(new Limit("LOGIN_IP",ip));if(!email.isBlank())limits.add(new Limit("LOGIN_ACCOUNT",email));
    ServerHttpRequest request=new ServerHttpRequestDecorator(exchange.getRequest()){@Override public Flux<DataBuffer> getBody(){return Flux.defer(()->Flux.just(exchange.getResponse().bufferFactory().wrap(bytes)));}};
    return apply(exchange.mutate().request(request).build(),chain,limits);
   }).onErrorResume(DataBufferLimitException.class,e->reject(exchange,413,0));
  }
  return exchange.getPrincipal().map(p->p.getName()).defaultIfEmpty(ip).flatMap(identity->{
   // Session status checks are read-only and frequent; they use the in-process bucket, not the shared DB store.
   String category=SESSION_STATUS_PATHS.contains(path)?"AUTH_SESSION_IP":SESSION_UPKEEP_PATHS.contains(path)?"AUTH_UPKEEP_IP":path.startsWith("/api/auth/")||path.startsWith("/api/active-user/")?"AUTH_IP":path.equals("/api/nihongo-user/japanese")?"AI_USER":path.startsWith("/api/nihongo-user/wallets")&&exchange.getRequest().getMethod()!=HttpMethod.GET?"WALLET_USER":identity.equals(ip)?"API_IP":"API_USER";
   List<Limit> limits=new ArrayList<>();limits.add(new Limit(category,category.endsWith("_IP")?ip:identity));if(path.equals("/api/auth/register"))limits.add(new Limit("REGISTER_IP",ip));return apply(exchange,chain,limits);
  });
 }
 private Mono<Void> apply(ServerWebExchange exchange,GatewayFilterChain chain,List<Limit> limits){
  if(limits.size()==1&&LOCAL_CATEGORIES.contains(limits.get(0).category())||localGeneralLimits&&limits.size()==1&&(limits.get(0).category().equals("API_USER")||limits.get(0).category().equals("API_IP"))){var result=local.consume(limits.get(0).category(),limits.get(0).identity());return result.allowed()?chain.filter(exchange):reject(exchange,429,result.retryAfter());}
  return client.post().uri(endpoint).header(InternalCredentials.HEADER,internal.value()).bodyValue(limits).retrieve().bodyToMono(Result.class).timeout(Duration.ofSeconds(3)).onErrorMap(e->new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,"Request limiter unavailable"))
   .flatMap(result->result.allowed()?chain.filter(exchange):reject(exchange,429,result.retryAfter()));
 }
 private Mono<Void> reject(ServerWebExchange exchange,int status,long retry){exchange.getResponse().setStatusCode(HttpStatus.valueOf(status));if(retry>0)exchange.getResponse().getHeaders().set("Retry-After",String.valueOf(retry));return exchange.getResponse().setComplete();}
}
