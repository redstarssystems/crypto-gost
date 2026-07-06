package org.rssys.gost.pkix.util;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;

/**
 * Защита от SSRF-атак при HTTP-запросах по внешним URI.
 * <p>
 * Блокирует private/reserved IP-адреса после DNS-разрешения. Проверяются
 * <b>все</b> адреса, возвращённые резолвером (A/AAAA), fail-closed: любой
 * private-адрес в ответе -> блокировка. Это закрывает multi-A-record трюк,
 * когда публичный и приватный адреса возвращаются вместе.
 * <p>
 * <b>Остаточный риск (простыми словами):</b> мы проверяем адрес перед запросом,
 * но само соединение делает {@code HttpClient}, который заново спрашивает DNS —
 * независимо от нашей проверки. Между этими двумя моментами атакующий,
 * управляющий DNS для нужного домена, может на проверку отдать «нормальный
 * публичный адрес», а на реальное подключение — «внутренний» (127.0.0.1,
 * локальная сеть). Это DNS-rebinding TOCTOU. Закрыть его штатными средствами
 * нельзя: у {@code HttpClient} нет способа задать свой резолвер, а заголовок
 * {@code Host} Java запрещает выставлять руками. Полностью надёжно — только
 * через ручной HTTP по низкоуровневому сокету (raw socket + SNI); это отдельная
 * задача, которую мы пока не планируем делать.
 * <p>
 * На практике риск ограничен: даже при эксплуатации атакующий получит лишь факт
 * «внутренний адрес отвечает» (probing внутренней сети). Украсть данные нельзя —
 * ответ OCSP/CRL/TSP всегда проверяется по подписи и при несовпадении
 * отбрасывается.
 * <p>
 * Используется как общий компонент для OCSP-, CRL- и TSP-транспортов.
 */
public final class SsrfGuard {

    private SsrfGuard() {
        // Утилитный класс
    }

    // Туннельные/транслирующие IPv6-префиксы: встроенный IPv4 может указывать на
    // внутреннюю сеть, а штатные isSiteLocal/isLinkLocal/... их не детектируют.
    // Блокируем диапазоны целиком (fail-closed) — легитимные OCSP/CRL/TSP-эндпойнты
    // этих (в основном deprecated) механизмов не используют.

    /** NAT64 64:ff9b::/96 (RFC 6052) — network prefix, байты 0..11. */
    private static final byte[] NAT64_PREFIX = {
        0x00, 0x64, (byte) 0xFF, (byte) 0x9B, 0, 0, 0, 0, 0, 0, 0, 0
    };

    /** Teredo 2001::/32 (RFC 4380). */
    private static final byte[] TEREDO_PREFIX = {0x20, 0x01, 0x00, 0x00};

    /** 6to4 2002::/16 (RFC 3056). */
    private static final byte[] SIX_TO_FOUR_PREFIX = {0x20, 0x02};

    /** IPv4-mapped ::ffff:0:0/96 (RFC 4291) — байты 0..11. */
    private static final byte[] IPV4_MAPPED_PREFIX = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 0xFF, (byte) 0xFF
    };

    /**
     * Проверяет, что URI не указывает на private/reserved IP-адрес.
     *
     * @param uri проверяемый URI
     * @return true если адрес private/reserved (или хост не резолвится), false
     *     если <b>все</b> резолвнутые адреса публичные
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
            InetAddress[] addrs = InetAddress.getAllByName(host);
            if (addrs.length == 0) {
                // Резолв без адресов — блокируем (fail-closed)
                return true;
            }
            for (InetAddress addr : addrs) {
                if (isPrivate(addr)) {
                    return true;
                }
            }
            return false;
        } catch (UnknownHostException e) {
            // Если хост не резолвится — блокируем (fail-closed)
            return true;
        }
    }

    /**
     * Проверяет, относится ли адрес к private/reserved диапазонам.
     */
    private static boolean isPrivate(InetAddress addr) {
        if (addr instanceof Inet6Address a6) {
            byte[] raw = a6.getAddress();
            if ((raw[0] & 0xFE) == 0xFC) {
                return true; // fc00::/7 — Unique Local Address (RFC 4193)
            }
            if (matchesPrefix(raw, NAT64_PREFIX)
                    || matchesPrefix(raw, TEREDO_PREFIX)
                    || matchesPrefix(raw, SIX_TO_FOUR_PREFIX)
                    || matchesPrefix(raw, IPV4_MAPPED_PREFIX)) {
                return true;
            }
        }
        return addr.isLoopbackAddress()
                || addr.isSiteLocalAddress()
                || addr.isLinkLocalAddress()
                || addr.isMulticastAddress()
                || addr.isAnyLocalAddress();
    }

    /** Проверяет, что первые {@code prefix.length} байт адреса совпадают с префиксом. */
    private static boolean matchesPrefix(byte[] raw, byte[] prefix) {
        if (raw.length < prefix.length) {
            return false;
        }
        for (int i = 0; i < prefix.length; i++) {
            if (raw[i] != prefix[i]) {
                return false;
            }
        }
        return true;
    }
}
