package com.nihongo.gateway.configuration;
import org.springframework.beans.factory.annotation.Value;import org.springframework.stereotype.Component;import org.springframework.web.server.ServerWebExchange;import java.net.*;import java.util.*;
@Component public class ClientAddressResolver {
 private final List<String> trusted;
 public ClientAddressResolver(@Value("${security.rate-limit.trusted-proxies:}") String value){trusted=value.isBlank()?List.of():Arrays.stream(value.split(",")).map(String::trim).toList();for(String cidr:trusted)if(!validCidr(cidr))throw new IllegalArgumentException("Trusted proxies must be numeric CIDR addresses");}
 public String identity(ServerWebExchange exchange){
  var remote=exchange.getRequest().getRemoteAddress();String ip=remote==null||remote.getAddress()==null?"unknown":remote.getAddress().getHostAddress();if(!trusted(ip))return ip;
  String header=exchange.getRequest().getHeaders().getFirst("X-Forwarded-For");if(header==null||header.length()>2048)return ip;String[] hops=header.split(",");if(hops.length>20)return ip;
  for(int i=hops.length-1;i>=0;i--){String hop=hops[i].trim();if(!numeric(hop))return ip;if(!trusted(hop))return hop;}return ip;
 }
 private boolean trusted(String ip){for(String c:trusted)if(in(ip,c))return true;return false;}
 public boolean directLoopback(ServerWebExchange exchange){var remote=exchange.getRequest().getRemoteAddress();return remote!=null&&remote.getAddress()!=null&&remote.getAddress().isLoopbackAddress()&&!trusted(remote.getAddress().getHostAddress());}
 private static boolean numeric(String ip){return ip!=null&&ip.matches("[0-9a-fA-F:.]{2,45}")&&(ip.contains(".")||ip.contains(":"));}
 private static boolean validCidr(String c){try{String[] x=c.split("/");if(x.length!=2||!numeric(x[0]))return false;int bits=Integer.parseInt(x[1]);return bits>=0&&bits<=InetAddress.getByName(x[0]).getAddress().length*8;}catch(Exception e){return false;}}
 private static boolean in(String ip,String cidr){try{if(!numeric(ip))return false;String[] parts=cidr.split("/");byte[] address=InetAddress.getByName(ip).getAddress(),network=InetAddress.getByName(parts[0]).getAddress();if(address.length!=network.length)return false;int bits=Integer.parseInt(parts[1]);for(int i=0;i<address.length;i++){int mask=bits>=8?255:bits<=0?0:(255<<(8-bits))&255;if((address[i]&mask)!=(network[i]&mask))return false;bits-=8;}return true;}catch(Exception e){return false;}}
}
