package org.rssys.gost.jsse;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;

/**
 * Защита от SSRF-атак при HTTP-запросах по внешним URI.
 * <p>
 * Блокирует private/reserved IP-адреса после DNS-разрешения.
 * Используется как общий компонент для OCSP- и CRL-fetcher'ов.
 */
public final class SsrfGuard {

    private SsrfGuard() {
        // Утилитный класс
    }

    /**
     * Проверяет, что URI не указывает на private/reserved IP-адрес.
     *
     * @param uri проверяемый URI
     * @return true если адрес private/reserved, false если адрес публичный
     */
    public static boolean isPrivateAddress(URI uri) {
        String host = uri.getHost();
        if (host == null) return true;
        // Локальные имена (localhost, loopback) без резолва
        if ("localhost".equalsIgnoreCase(host)
                || "127.0.0.1".equals(host)
                || "[::1]".equals(host)
                || "0.0.0.0".equals(host)) {
            return true;
        }
        try {
            InetAddress addr = InetAddress.getByName(host);
            if (addr instanceof Inet6Address a6) {
                byte[] raw = a6.getAddress();
                if ((raw[0] & 0xFE) == 0xFC) {
                    return true; // fc00::/7 — Unique Local Address (RFC 4193)
                }
            }
            return addr.isLoopbackAddress()
                    || addr.isSiteLocalAddress()
                    || addr.isLinkLocalAddress()
                    || addr.isMulticastAddress()
                    || addr.isAnyLocalAddress();
        } catch (UnknownHostException e) {
            // Если хост не резолвится — блокируем (fail-closed)
            return true;
        }
    }
}
