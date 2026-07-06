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
}
