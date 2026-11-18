package org.rssys.gost.pkix.util;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import java.net.URI;
import java.net.URISyntaxException;

/**
 * Fuzz-тест для {@link SsrfGuard#isPrivateAddress(URI)}.
 *
 * <p>Единственная публичная точка входа SSRF-защиты. Принимает {@code URI}
 * (из AIA/CDP/OCSP-ответа), резолвит хост через {@code InetAddress.getAllByName()},
 * проверяет все адреса на private/reserved диапазоны.</p>
 *
 * <p>Проверяет фиксы 0.6.1/0.6.2:
 * <ul>
 *   <li>IPv6 туннельные диапазоны: NAT64 {@code 64:ff9b::/96}, Teredo {@code 2001::/32},
 *       6to4 {@code 2002::/16}, IPv4-mapped {@code ::ffff:0:0/96}</li>
 *   <li>{@code [::]} unspecified, {@code fc00::/7} ULA</li>
 *   <li>Multi-A-record: проверка всех резолвнутых адресов</li>
 * </ul>
 *
 * <p>{@code URISyntaxException} на невалидном URI — ожидаемо, не баг.
 * AIOOBE / NPE — баг.</p>
 */
class SsrfGuardFuzzTest {

    @FuzzTest
    void fuzzIsPrivateAddress(FuzzedDataProvider data) {
        String rawUri = data.consumeRemainingAsString();
        if (rawUri.isEmpty()) return;
        URI uri;
        try {
            uri = new URI(rawUri);
        } catch (URISyntaxException e) {
            // Невалидный URI — ожидаемо для фаззера, не баг
            return;
        }
        try {
            SsrfGuard.isPrivateAddress(uri);
        } catch (RuntimeException e) {
            FuzzTestUtils.rethrowIfBug(e);
        }
    }
}
