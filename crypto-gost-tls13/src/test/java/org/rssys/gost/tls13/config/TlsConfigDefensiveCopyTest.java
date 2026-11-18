package org.rssys.gost.tls13.config;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsCiphersuite;

/**
 * Конфигурации хранят копии переданных данных: проверка при установке не обходится изменением
 * исходного списка или массива после неё, а изменение результата геттера не влияет на
 * конфигурацию.
 */
@DisplayName("TlsClientConfig и TlsServerConfig: защитное копирование")
class TlsConfigDefensiveCopyTest {

    private static final TlsCiphersuite SUITE =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
    private static final int ALPN_NAME_TOO_LONG = 300;

    private static PkixCertTestHelper.CertBundle first;
    private static PkixCertTestHelper.CertBundle second;

    @BeforeAll
    static void setUp() {
        ECParameters params = ECParameters.tc26a256();
        first = PkixCertTestHelper.createCertWithKey(params);
        second = PkixCertTestHelper.createCertWithKey(params);
    }

    private static TlsClientConfig client() {
        return new TlsClientConfig(SUITE, TrustAnchors.ofCertificate(first.cert));
    }

    private static TlsServerConfig server(List<GostCertificate> chain) {
        return new TlsServerConfig(SUITE, chain, first.priv);
    }

    private static byte[] ocsp() {
        return new byte[] {0x30, 0x03, 0x0A, 0x01, 0x00};
    }

    // ---- ALPN ----

    @Test
    @DisplayName("клиент: изменение исходного списка ALPN после установки не действует")
    void clientAlpnSourceMutationIgnored() {
        List<String> source = new ArrayList<>(List.of("h2"));
        TlsClientConfig config = client().withAlpnProtocols(source);

        source.add("x".repeat(ALPN_NAME_TOO_LONG));
        source.set(0, null);

        assertEquals(List.of("h2"), config.getAlpnProtocols());
    }

    @Test
    @DisplayName("сервер: изменение исходного списка ALPN после установки не действует")
    void serverAlpnSourceMutationIgnored() {
        List<String> source = new ArrayList<>(List.of("h2"));
        TlsServerConfig config = server(List.of(first.cert)).withAlpnProtocols(source);

        source.add("x".repeat(ALPN_NAME_TOO_LONG));

        assertEquals(List.of("h2"), config.getAlpnProtocols());
    }

    @Test
    @DisplayName("список ALPN из геттера неизменяем")
    void alpnGetterIsImmutable() {
        TlsClientConfig clientConfig = client().withAlpnProtocols(new ArrayList<>(List.of("h2")));
        TlsServerConfig serverConfig =
                server(List.of(first.cert)).withAlpnProtocols(new ArrayList<>(List.of("h2")));

        assertThrows(
                UnsupportedOperationException.class,
                () -> clientConfig.getAlpnProtocols().add("x"));
        assertThrows(
                UnsupportedOperationException.class,
                () -> serverConfig.getAlpnProtocols().add("x"));
    }

    // ---- OCSP ----

    @Test
    @DisplayName("изменение исходного массива OCSP после установки не действует (клиент и сервер)")
    void ocspSourceMutationIgnored() {
        byte[] clientSource = ocsp();
        byte[] serverSource = ocsp();
        TlsClientConfig clientConfig = client().withOcspStaplingResponse(clientSource);
        TlsServerConfig serverConfig =
                server(List.of(first.cert)).withOcspStaplingResponse(serverSource);

        clientSource[0] = 0x00;
        serverSource[0] = 0x00;

        assertArrayEquals(ocsp(), clientConfig.getOcspStaplingResponse());
        assertArrayEquals(ocsp(), serverConfig.getOcspStaplingResponse());
    }

    @Test
    @DisplayName("изменение массива OCSP, полученного из геттера, не влияет на конфигурацию")
    void ocspGetterReturnsCopy() {
        TlsClientConfig clientConfig = client().withOcspStaplingResponse(ocsp());
        TlsServerConfig serverConfig = server(List.of(first.cert)).withOcspStaplingResponse(ocsp());

        clientConfig.getOcspStaplingResponse()[0] = 0x00;
        serverConfig.getOcspStaplingResponse()[0] = 0x00;

        assertArrayEquals(ocsp(), clientConfig.getOcspStaplingResponse());
        assertArrayEquals(ocsp(), serverConfig.getOcspStaplingResponse());
    }

    @Test
    @DisplayName("OCSP = null по-прежнему принимается (без stapling)")
    void ocspNullAccepted() {
        assertNull(client().withOcspStaplingResponse(null).getOcspStaplingResponse());
        assertNull(
                server(List.of(first.cert))
                        .withOcspStaplingResponse(null)
                        .getOcspStaplingResponse());
    }

    // ---- Цепочки ----

    @Test
    @DisplayName(
            "клиент: изменение исходной цепочки и массива varargs после установки не действует")
    void clientChainSourceMutationIgnored() {
        List<GostCertificate> source = new ArrayList<>(List.of(first.cert));
        TlsClientConfig fromList = client().withClientCertificateChain(source);
        source.clear();

        GostCertificate[] array = {first.cert};
        TlsClientConfig fromVarargs = client().withClientCertificateChain(array);
        array[0] = second.cert;

        assertEquals(List.of(first.cert), fromList.getClientCertificateChain());
        assertSame(first.cert, fromVarargs.getClientCertificateChain().get(0));
    }

    @Test
    @DisplayName("сервер: изменение исходной цепочки после создания не действует")
    void serverChainSourceMutationIgnored() {
        List<GostCertificate> source = new ArrayList<>(List.of(first.cert));
        TlsServerConfig config = server(source);

        source.clear();
        source.add(second.cert);

        assertEquals(List.of(first.cert), config.getServerCertificateChain());
    }

    @Test
    @DisplayName("цепочки из геттеров неизменяемы")
    void chainGettersAreImmutable() {
        TlsClientConfig clientConfig =
                client().withClientCertificateChain(new ArrayList<>(List.of(first.cert)));
        TlsServerConfig serverConfig = server(new ArrayList<>(List.of(first.cert)));

        assertThrows(
                UnsupportedOperationException.class,
                () -> clientConfig.getClientCertificateChain().clear());
        assertThrows(
                UnsupportedOperationException.class,
                () -> serverConfig.getServerCertificateChain().clear());
    }

    @Test
    @DisplayName("клиентская цепочка = null по-прежнему принимается (режим без mTLS)")
    void clientChainNullAccepted() {
        TlsClientConfig config = client().withClientCertificateChain((List<GostCertificate>) null);

        assertNull(config.getClientCertificateChain());
    }

    @Test
    @DisplayName("null-элемент в цепочке или varargs = null -> IllegalArgumentException")
    void nullChainElementsRejected() {
        assertThrows(
                IllegalArgumentException.class,
                () -> client().withClientCertificateChain(Arrays.asList(first.cert, null)));
        assertThrows(
                IllegalArgumentException.class,
                () -> client().withClientCertificateChain((GostCertificate[]) null));
        assertThrows(
                IllegalArgumentException.class,
                () -> client().withClientCertificateChain(first.cert, null));
        assertThrows(IllegalArgumentException.class, () -> server(Arrays.asList(first.cert, null)));
    }

    @Test
    @DisplayName("список ALPN = null -> IllegalArgumentException")
    void nullAlpnListRejected() {
        assertThrows(IllegalArgumentException.class, () -> client().withAlpnProtocols(null));
        assertThrows(
                IllegalArgumentException.class,
                () -> server(List.of(first.cert)).withAlpnProtocols(null));
    }

    @Test
    @DisplayName("null-элемент в списке ALPN -> IllegalArgumentException")
    void nullAlpnElementRejected() {
        assertThrows(
                IllegalArgumentException.class,
                () -> client().withAlpnProtocols(Arrays.asList("h2", null)));
        assertThrows(
                IllegalArgumentException.class,
                () -> server(List.of(first.cert)).withAlpnProtocols(Arrays.asList("h2", null)));
    }

    // ---- oidFilters ----

    private static OIDFilter filter() {
        return new OIDFilter(new byte[] {0x55, 0x1D, 0x25}, new byte[0]);
    }

    @Test
    @DisplayName("сервер: изменение исходного списка oidFilters после установки не действует")
    void oidFiltersSourceMutationIgnored() {
        List<OIDFilter> source = new ArrayList<>(List.of(filter()));
        TlsServerConfig config = server(List.of(first.cert)).withOidFilters(source);

        source.clear();

        assertEquals(List.of(filter()), config.getOidFilters());
    }

    @Test
    @DisplayName("список oidFilters из геттера неизменяем, null принимается")
    void oidFiltersGetterImmutableAndNullAccepted() {
        TlsServerConfig config =
                server(List.of(first.cert)).withOidFilters(new ArrayList<>(List.of(filter())));

        assertThrows(UnsupportedOperationException.class, () -> config.getOidFilters().clear());
        assertNull(server(List.of(first.cert)).withOidFilters(null).getOidFilters());
    }

    @Test
    @DisplayName("null-элемент в oidFilters -> IllegalArgumentException")
    void nullOidFilterElementRejected() {
        assertThrows(
                IllegalArgumentException.class,
                () -> server(List.of(first.cert)).withOidFilters(Arrays.asList(filter(), null)));
    }
}
