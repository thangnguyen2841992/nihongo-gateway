package com.nihongo.gateway.configuration;
import com.nihongo.security.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.*;
import org.springframework.core.env.Environment;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.web.server.*;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.*;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import reactor.core.publisher.Mono;
import java.util.List;
@Configuration @EnableReactiveMethodSecurity
public class SecurityConfig {
 @Bean public org.springframework.beans.factory.InitializingBean productionSecurityPolicy(Environment env){return ()->ProductionSecurityPolicy.verify(env);}
 @Value("${FRONTEND_ORIGIN:http://localhost:5173}") private String[] origins;
 @Bean public InternalCredentials internalCredentials(Environment env){return new InternalCredentials(env);}
 @Bean public ReactiveJwtDecoder jwtDecoder(Environment env){return SecurityJwtDecoders.reactive(env);}
 @Bean SecurityWebFilterChain filterChain(ServerHttpSecurity http,JwtCookieWebFilter cookies,Environment env){
  var policy=new BrowserOriginPolicy(origins);
  return http.cors(c->c.configurationSource(corsConfigurationSource())).csrf(ServerHttpSecurity.CsrfSpec::disable)
   // Browser requests are protected by an explicit strict Origin/Referer policy before cookie-to-bearer conversion.
   .addFilterBefore(new BrowserOriginWebFilter(policy,env.getProperty("security.origin-check.enabled",Boolean.class,true)),SecurityWebFiltersOrder.AUTHENTICATION)
   .addFilterBefore(cookies,SecurityWebFiltersOrder.AUTHENTICATION)
   .authorizeExchange(a->a.pathMatchers(HttpMethod.OPTIONS).permitAll()
    .pathMatchers("/api/auth/internal/**","/api/auth/session/validate").denyAll()
    .pathMatchers("/api/auth/**","/api/active-user/**").permitAll()
    .pathMatchers(HttpMethod.GET,"/images/**","/api/nihongo-user/courses","/api/staff/public/**").permitAll()
    .pathMatchers(HttpMethod.HEAD,"/images/**").permitAll()
    .pathMatchers("/api/admin/**","/api/users/admin/**","/api/nihongo-user/admin/**","/api/notification/admin/**","/api/staff/content/audit/**").hasRole("ADMIN")
    .pathMatchers("/api/notification/staff/**").hasAnyRole("ADMIN","STAFF")
    .pathMatchers("/api/nihongo-user/staff/**","/api/users/staff/**","/api/users/staff-directory").hasAnyRole("ADMIN","STAFF")
    .pathMatchers("/api/notification/broadcasts","/api/notification/ws").hasAnyRole("ADMIN","STAFF","USER")
    .pathMatchers("/api/staff/content/reports","/api/staff/content/reports/mine").hasAnyRole("ADMIN","STAFF","USER")
    .pathMatchers("/api/staff/content/**").hasAnyRole("ADMIN","STAFF")
    .pathMatchers("/api/users/**","/api/staff/**","/api/nihongo-user/**","/ws/**","/images/**").hasAnyRole("ADMIN","STAFF","USER")
    .anyExchange().denyAll())
   .oauth2ResourceServer(o->o.jwt(j->j.jwtAuthenticationConverter(jwtAuthenticationConverter()))).build();
 }
 @Bean public Converter<Jwt,Mono<AbstractAuthenticationToken>> jwtAuthenticationConverter(){return jwt->{var converter=new JwtRoleConverter();return Mono.just(new JwtAuthenticationToken(jwt,converter.convert(jwt)));};}
 @Bean public CorsConfigurationSource corsConfigurationSource(){var c=new CorsConfiguration();c.setAllowedOrigins(List.of(origins));c.setAllowedMethods(List.of("GET","HEAD","POST","PUT","PATCH","DELETE","OPTIONS"));c.setAllowedHeaders(List.of("Content-Type","Authorization","Idempotency-Key","X-Requested-With"));c.setExposedHeaders(List.of("X-Auth-Failure","Retry-After"));c.setAllowCredentials(true);c.setMaxAge(3600L);var source=new UrlBasedCorsConfigurationSource();source.registerCorsConfiguration("/**",c);return source;}
}
