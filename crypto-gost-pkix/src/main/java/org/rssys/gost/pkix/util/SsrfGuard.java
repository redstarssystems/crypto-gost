package org.rssys.gost.pkix.util;

import java.net.Inet4Address;
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
 * Диапазоны IPv4 задаются таблицей RFC 6890. Для IPv6 перечислены префиксы, встроенный IPv4
 * которых может указывать на внутреннюю сеть, и документационные, тестовые и discard-диапазоны;
 * список не претендует на полноту реестра IANA IPv6 Special-Purpose Address.
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

    /** Число старших нулевых байт IPv4-совместимого адреса {@code ::a.b.c.d}. */
    private static final int IPV4_COMPATIBLE_ZERO_BYTES = 12;

    /** Документация 2001:db8::/32 (RFC 3849). */
    private static final byte[] DOCUMENTATION_PREFIX = {0x20, 0x01, 0x0D, (byte) 0xB8};

    /** Тестовые стенды производительности 2001:2::/48 (RFC 5180). */
    private static final byte[] IPV6_BENCHMARKING_PREFIX = {0x20, 0x01, 0x00, 0x02, 0, 0};

    /** Discard-only 100::/64 (RFC 6666). */
    private static final byte[] DISCARD_PREFIX = {0x01, 0, 0, 0, 0, 0, 0, 0};

    /** Локальный NAT64 64:ff9b:1::/48 (RFC 8215): встроенный IPv4 может быть внутренним. */
    private static final byte[] LOCAL_NAT64_PREFIX = {0x00, 0x64, (byte) 0xFF, (byte) 0x9B, 0, 1};

    /** IPv4-mapped ::ffff:0:0/96 (RFC 4291) — байты 0..11. */
    private static final byte[] IPV4_MAPPED_PREFIX = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 0xFF, (byte) 0xFF
    };

    /**
     * Адреса IPv4, не являющиеся глобально маршрутизируемыми (IANA IPv4 Special-Purpose Address
     * Registry, RFC 6890, колонка Globally Reachable = False), которые штатные
     * {@code isSiteLocal/isLinkLocal/isLoopback/isMulticast/isAnyLocal} JDK не покрывают.
     * Единая таблица вместо отдельных заплаток: новый диапазон добавляется строкой, а не
     * отдельной проверкой. Формат строки: {сетевой адрес, длина префикса в битах}.
     */
    private static final int[][] NON_GLOBAL_IPV4 = {
        {ipv4(0, 0, 0, 0), 8}, // "this network" (RFC 791 §3.2)
        {ipv4(100, 64, 0, 0), 10}, // shared address space, CGN (RFC 6598)
        {ipv4(192, 0, 0, 0), 24}, // IETF protocol assignments (RFC 6890)
        {ipv4(192, 0, 2, 0), 24}, // TEST-NET-1 (RFC 5737)
        {ipv4(192, 88, 99, 0), 24}, // 6to4 relay anycast, устарел (RFC 7526)
        {ipv4(198, 18, 0, 0), 15}, // benchmarking (RFC 2544)
        {ipv4(198, 51, 100, 0), 24}, // TEST-NET-2 (RFC 5737)
        {ipv4(203, 0, 113, 0), 24}, // TEST-NET-3 (RFC 5737)
        {ipv4(240, 0, 0, 0), 4}, // reserved, включая 255.255.255.255 (RFC 1112, RFC 919)
    };

    private static int ipv4(int a, int b, int c, int d) {
        return (a << 24) | (b << 16) | (c << 8) | d;
    }

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
        if (addr instanceof Inet4Address a4 && isNonGlobalIpv4(a4.getAddress())) {
            return true;
        }
        if (addr instanceof Inet6Address a6) {
            byte[] raw = a6.getAddress();
            if ((raw[0] & 0xFE) == 0xFC) {
                return true; // fc00::/7 — Unique Local Address (RFC 4193)
            }
            // IPv4-совместимый ::a.b.c.d устарел (RFC 4291 §2.5.5.1), и OCSP/CRL/TSP-адресов в
            // этой форме никто не публикует. Встроенный IPv4 может быть и публичным, и
            // внутренним; на Linux такой адрес не маршрутизируется в IPv4, но другие стеки
            // могли бы, поэтому блокируем форму целиком
            if (hasZeroPrefix(raw, IPV4_COMPATIBLE_ZERO_BYTES)) {
                return true;
            }
            if (matchesPrefix(raw, NAT64_PREFIX)
                    || matchesPrefix(raw, LOCAL_NAT64_PREFIX)
                    || matchesPrefix(raw, DOCUMENTATION_PREFIX)
                    || matchesPrefix(raw, IPV6_BENCHMARKING_PREFIX)
                    || matchesPrefix(raw, DISCARD_PREFIX)
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

    /** Проверяет, что первые {@code count} байт адреса нулевые. */
    private static boolean hasZeroPrefix(byte[] raw, int count) {
        for (int i = 0; i < count; i++) {
            if (raw[i] != 0) {
                return false;
            }
        }
        return true;
    }

    /** Проверяет вхождение IPv4-адреса в {@link #NON_GLOBAL_IPV4}. */
    private static boolean isNonGlobalIpv4(byte[] raw) {
        int address = ipv4(raw[0] & 0xFF, raw[1] & 0xFF, raw[2] & 0xFF, raw[3] & 0xFF);
        for (int[] range : NON_GLOBAL_IPV4) {
            // Префикс /0 здесь не допускается: сдвиг на 32 в Java берётся по модулю 32 и дал бы
            // маску из единиц вместо нулевой, то есть совпадение одного адреса вместо «всех»
            int mask = -1 << (Integer.SIZE - range[1]);
            if ((address & mask) == (range[0] & mask)) {
                return true;
            }
        }
        return false;
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
