package com.nihongo.gateway.configuration;

import org.springframework.stereotype.Component;
import java.net.*;
import java.util.*;

@Component
public class LocalNetworkAddresses {
    /** Only used for direct loopback requests in the local profile. */
    public String snapshot() {
        SortedSet<String> addresses = new TreeSet<>();
        try {
            var interfaces = NetworkInterface.getNetworkInterfaces();
            if (interfaces == null) return "";
            for (var network : Collections.list(interfaces)) {
                if (!network.isUp() || network.isLoopback() || network.isVirtual() || network.isPointToPoint()) continue;
                for (var address : Collections.list(network.getInetAddresses())) {
                    if (address instanceof Inet4Address && address.isSiteLocalAddress() && !address.isLoopbackAddress())
                        addresses.add(address.getHostAddress());
                }
            }
        } catch (SocketException ignored) { return ""; }
        return String.join(",", addresses.stream().limit(8).toList());
    }
}
