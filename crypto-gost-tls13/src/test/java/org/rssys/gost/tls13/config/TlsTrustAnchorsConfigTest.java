package org.rssys.gost.tls13.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.PkixCertTestHelper.CertBundle;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsCiphersuite;

@DisplayName("TlsClientConfig/TlsServerConfig: режимы якорей и геттеры")
class TlsTrustAnchorsConfigTest {

    private static final TlsCiphersuite CS =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
    private static final ECParameters PARAMS = ECParameters.tc26a256();

    @Test
    @DisplayName("Клиент: cert-якорь доступен через getTrustAnchors")
    void testClientGetters() throws Exception {
        CertBundle root = PkixCertTestHelper.createRootCA(PARAMS);
        TlsClientConfig certConfig = new TlsClientConfig(CS, TrustAnchors.ofCertificate(root.cert));
        assertTrue(certConfig.hasTrustAnchors());
        assertEquals(1, certConfig.getTrustAnchors().certificates().size());
    }

    @Test
    @DisplayName("Сервер: по умолчанию mTLS выключен")
    void testServerDefaultNone() throws Exception {
        CertBundle root = PkixCertTestHelper.createRootCA(PARAMS);
        TlsServerConfig off = new TlsServerConfig(CS, List.of(root.cert), root.priv);
        assertEquals(ClientAuth.NONE, off.getClientAuthMode(), "Умолчание должно быть NONE");
        assertFalse(off.isClientAuthEnabled(), "mTLS по умолчанию выключен");
        assertNull(off.getTrustAnchors(), "Якорей при NONE быть не должно");
    }

    @Test
    @DisplayName("Сервер: needClientAuth и wantClientAuth задают режим вместе с якорями")
    void testServerModes() throws Exception {
        CertBundle root = PkixCertTestHelper.createRootCA(PARAMS);
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        TlsServerConfig need =
                new TlsServerConfig(CS, List.of(root.cert), root.priv).needClientAuth(anchors);
        assertEquals(ClientAuth.NEED, need.getClientAuthMode());
        assertTrue(need.isClientAuthEnabled());
        assertEquals(1, need.getTrustAnchors().certificates().size());

        TlsServerConfig want =
                new TlsServerConfig(CS, List.of(root.cert), root.priv).wantClientAuth(anchors);
        assertEquals(ClientAuth.WANT, want.getClientAuthMode());
        assertTrue(want.isClientAuthEnabled());
        assertEquals(1, want.getTrustAnchors().certificates().size());
    }

    @Test
    @DisplayName("Сервер: последний вызов заменяет режим и якоря целиком")
    void testServerLastCallWins() throws Exception {
        CertBundle root = PkixCertTestHelper.createRootCA(PARAMS);
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        TlsServerConfig config =
                new TlsServerConfig(CS, List.of(root.cert), root.priv)
                        .needClientAuth(anchors)
                        .wantClientAuth(anchors);
        assertEquals(ClientAuth.WANT, config.getClientAuthMode(), "Победил последний вызов");
        config.needClientAuth(anchors);
        assertEquals(ClientAuth.NEED, config.getClientAuthMode(), "Победил последний вызов");
    }
}
