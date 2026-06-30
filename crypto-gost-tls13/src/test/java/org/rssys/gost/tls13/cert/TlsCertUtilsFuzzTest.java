package org.rssys.gost.tls13.cert;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsTestHelper;
import org.rssys.gost.tls13.config.OIDFilter;

/**
 * Fuzz-тесты для {@link TlsCertUtils#matchesOidFilter}.
 * <p>
 * Атакуем парсинг filterValues из oid_filters CertificateRequest (RFC 8446 §4.2.5):
 * противник (сервер) шлёт произвольные filterOid + filterValues, клиент проверяет
 * сертификат на соответствие фильтру.
 * <p>
 * CP-ветка: добавлена поддержка CertificatePolicies с
 * {@code Arrays.copyOfRange(filterValues, oidTlv[0], oidTlv[1])} и {@code readTlv}
 * на недоверенных filterValues — ни одной fuzz-проверки границ.
 * <p>
 * ПОЧЕМУ ловим RuntimeException: GostDerParser НЕ проверяет границы массивов —
 * любой битый filterValues гарантированно даст AIOOBE или NPE.
 */
class TlsCertUtilsFuzzTest {

    /**
     * Сертификат с EKU OID для активации EKU-ветки + CP OID KC1 для CP-ветки.
     * Статическая фикстура (не из fuzzer) — валидный объект, фаззится только фильтр.
     */
    private static final GostCertificate CERT;

    static {
        // @BeforeAll не поддерживается Jazzer
        ECParameters params = ECParameters.tc26a256();
        TlsTestHelper.CertBundle bundle =
                TlsTestHelper.createCertWithKey(
                        params,
                        "20250101000000Z",
                        "21010101000000Z",
                        null,
                        null,
                        new String[] {"1.3.6.1.5.5.7.3.2"}, // id-kp-clientAuth
                        null,
                        new String[] {"1.2.643.100.113.1"}); // KC1 CertificatePolicy
        CERT = bundle.cert;
    }

    /**
     * Подаёт случайные filterOid + filterValues в matchesOidFilter.
     * <p>
     * Покрывает все ветки: KU (BA), EKU (readTlv + Arrays.copyOfRange),
     * CP (readTlv + Arrays.copyOfRange), known extension OID,
     * unknown OID.
     */
    @FuzzTest
    void fuzzMatchesOidFilter(FuzzedDataProvider data) {
        byte[] filterOid = data.consumeBytes(data.consumeInt(1, 32));
        byte[] filterValues = data.consumeBytes(data.consumeInt(0, 4096));
        // consumeBytes может вернуть пустой массив при исчерпании данных фаззера —
        // OIDFilter требует непустой extensionOid
        if (filterOid.length == 0) return;
        OIDFilter filter = new OIDFilter(filterOid, filterValues);
        try {
            TlsCertUtils.matchesOidFilter(CERT, filter);
        } catch (RuntimeException e) {
            FuzzTestUtils.rethrowIfBug(e);
        }
    }
}
