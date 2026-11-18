package org.rssys.gost.pkix.util;

import static org.junit.jupiter.api.Assertions.*;

import java.net.URI;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Тесты SSRF-защиты {@link SsrfGuard#isPrivateAddress(URI)}.
 * <p>
 * Проверяет блокировку private/reserved адресов:
 * loopback, site-local, link-local, multicast, any-local (::, 0.0.0.0),
 * а также Unique Local Address fc00::/7 (RFC 4193).
 */
@DisplayName("SsrfGuard: защита от SSRF")
class SsrfGuardTest {

    @ParameterizedTest(name = "[{index}] {0} -> заблокирован")
    @ValueSource(
            strings = {
                "http://127.0.0.1/",
                "http://[::1]/",
                "http://localhost/",
                "http://0.0.0.0/",
                "http://[::]/",
                "http://[fd12:3456:789a::50]/",
                "http://[fc00::1]/",
                "http://[fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]/",
                "http://10.0.0.1/",
                "http://169.254.1.1/",
                "http://[fe80::1]/",
                "http://[ff02::1]/",
                "http://192.168.0.1/",
                "http://172.16.0.1/",
                "http://[64:ff9b::1]/",
                "http://[2001::1]/",
                "http://[2002::1]/",
                "http://[::ffff:10.0.0.1]/",
            })
    @DisplayName("Private/reserved адреса блокируются")
    void shouldBlockPrivateAddresses(String url) {
        URI uri = URI.create(url);
        assertTrue(SsrfGuard.isPrivateAddress(uri), () -> "Адрес должен блокироваться: " + url);
    }

    @ParameterizedTest(name = "[{index}] {0} -> разрешён")
    @ValueSource(
            strings = {
                "http://93.184.216.34/",
                "http://[2001:4860:4860::8888]/",
                "http://1.1.1.1/",
            })
    @DisplayName("Публичные адреса не блокируются")
    void shouldAllowPublicAddresses(String url) {
        URI uri = URI.create(url);
        assertFalse(
                SsrfGuard.isPrivateAddress(uri),
                () -> "Публичный адрес не должен блокироваться: " + url);
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "http://127.0.0.1:8080/path?q=1",
                "http://[::]:9090/ocsp",
                "http://[fd12:3456:789a::50]:443/api",
            })
    @DisplayName("Адреса с портом и путём блокируются")
    void shouldBlockWithPortAndPath(String url) {
        URI uri = URI.create(url);
        assertTrue(
                SsrfGuard.isPrivateAddress(uri),
                () -> "Адрес с портом/путём должен блокироваться: " + url);
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "http://[FC00::1]/",
                "http://[FD12::]/",
                "http://LOCALHOST/",
            })
    @DisplayName("Регистр не влияет на блокировку")
    void shouldBlockRegardlessOfCase(String url) {
        URI uri = URI.create(url);
        assertTrue(
                SsrfGuard.isPrivateAddress(uri),
                () -> "Регистр не должен влиять на блокировку: " + url);
    }

    @ParameterizedTest(name = "[{index}] {0} -> заблокирован (граница диапазона RFC 6890)")
    @ValueSource(
            strings = {
                // 0.0.0.0/8: «эта сеть», кроме 0.0.0.0, который ловит isAnyLocalAddress
                "http://0.0.0.1/",
                "http://0.255.255.255/",
                // 100.64.0.0/10: общее адресное пространство CGN
                "http://100.64.0.0/",
                "http://100.127.255.255/",
                // 192.0.0.0/24, TEST-NET-1/2/3, 6to4-реле
                "http://192.0.0.0/",
                "http://192.0.0.255/",
                "http://192.0.2.0/",
                "http://192.0.2.255/",
                "http://192.88.99.0/",
                "http://192.88.99.255/",
                "http://198.51.100.0/",
                "http://198.51.100.255/",
                "http://203.0.113.0/",
                "http://203.0.113.255/",
                // 198.18.0.0/15: тестовые стенды производительности
                "http://198.18.0.0/",
                "http://198.19.255.255/",
                // 240.0.0.0/4: зарезервировано, включая широковещательный адрес
                "http://240.0.0.0/",
                "http://255.255.255.254/",
                "http://255.255.255.255/",
            })
    @DisplayName("Не глобально маршрутизируемые IPv4-диапазоны блокируются по обоим краям")
    void shouldBlockNonGlobalIpv4Ranges(String url) {
        assertTrue(
                SsrfGuard.isPrivateAddress(URI.create(url)),
                () -> "Адрес из не глобального диапазона должен блокироваться: " + url);
    }

    @ParameterizedTest(name = "[{index}] {0} -> разрешён (сосед диапазона)")
    @ValueSource(
            strings = {
                "http://1.0.0.0/",
                "http://100.63.255.255/",
                "http://100.128.0.0/",
                "http://192.0.1.0/",
                "http://192.0.3.0/",
                "http://192.88.98.255/",
                "http://192.88.100.0/",
                "http://198.17.255.255/",
                "http://198.20.0.0/",
                "http://198.51.99.255/",
                "http://198.51.101.0/",
                "http://203.0.112.255/",
                "http://203.0.114.0/",
                "http://223.255.255.255/",
            })
    @DisplayName("Соседние с зарезервированными публичные адреса не блокируются")
    void shouldAllowNeighboursOfNonGlobalRanges(String url) {
        assertFalse(
                SsrfGuard.isPrivateAddress(URI.create(url)),
                () -> "Публичный сосед диапазона не должен блокироваться: " + url);
    }

    @ParameterizedTest(name = "[{index}] {0} -> заблокирован (IPv4-совместимый)")
    @ValueSource(
            strings = {
                "http://[::127.0.0.1]/",
                "http://[::10.0.0.1]/",
                "http://[::8.8.8.8]/",
                "http://[::0.0.0.2]/",
            })
    @DisplayName("IPv4-совместимые адреса ::a.b.c.d блокируются целиком")
    void shouldBlockIpv4CompatibleAddresses(String url) {
        assertTrue(
                SsrfGuard.isPrivateAddress(URI.create(url)),
                () -> "IPv4-совместимый адрес должен блокироваться: " + url);
    }

    @ParameterizedTest(name = "[{index}] {0} -> заблокирован (mapped в IPv4-диапазон)")
    @ValueSource(
            strings = {
                "http://[::ffff:100.64.0.1]/",
                "http://[::ffff:198.18.0.1]/",
                "http://[::ffff:240.0.0.1]/",
                "http://[::ffff:0.0.0.1]/",
            })
    @DisplayName("IPv4-mapped адрес проходит ту же таблицу диапазонов")
    void shouldBlockMappedNonGlobalIpv4(String url) {
        assertTrue(
                SsrfGuard.isPrivateAddress(URI.create(url)),
                () -> "Mapped-адрес из не глобального диапазона должен блокироваться: " + url);
    }

    @ParameterizedTest(name = "[{index}] {0} -> заблокирован (IPv6 не глобальный)")
    @ValueSource(
            strings = {
                "http://[2001:db8::1]/",
                "http://[2001:db8:ffff:ffff:ffff:ffff:ffff:ffff]/",
                "http://[100::1]/",
                "http://[100::ffff:ffff:ffff:ffff]/",
                "http://[2001:2::1]/",
                "http://[2001:2:0:ffff::1]/",
                "http://[64:ff9b:1::1]/",
                "http://[64:ff9b:1:ffff:ffff:ffff:ffff:ffff]/",
            })
    @DisplayName("IPv6: документация, discard и локальный NAT64 блокируются")
    void shouldBlockNonGlobalIpv6(String url) {
        assertTrue(
                SsrfGuard.isPrivateAddress(URI.create(url)),
                () -> "Не глобальный IPv6 должен блокироваться: " + url);
    }

    @ParameterizedTest(name = "[{index}] {0} -> разрешён (сосед IPv6-диапазона)")
    @ValueSource(
            strings = {
                "http://[2001:db9::1]/",
                "http://[2001:db7:ffff::1]/",
                "http://[100:0:0:1::1]/",
                "http://[2001:2:1::1]/",
                "http://[64:ff9b:2::1]/",
            })
    @DisplayName("Соседи IPv6-диапазонов не блокируются")
    void shouldAllowNeighboursOfNonGlobalIpv6(String url) {
        assertFalse(
                SsrfGuard.isPrivateAddress(URI.create(url)),
                () -> "Публичный сосед IPv6-диапазона не должен блокироваться: " + url);
    }
}
