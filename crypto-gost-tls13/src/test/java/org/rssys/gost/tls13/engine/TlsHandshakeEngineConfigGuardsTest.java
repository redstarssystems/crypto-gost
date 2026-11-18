package org.rssys.gost.tls13.engine;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.message.TlsMessageBuilder;

/** Защиты настройки {@link TlsHandshakeEngine}: ошибки разработчика отказывают сразу и явно. */
@DisplayName("TlsHandshakeEngine: проверки настройки")
class TlsHandshakeEngineConfigGuardsTest {

    private static final TlsCiphersuite SUITE =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;

    private static PkixCertTestHelper.CertBundle serverCert;

    @BeforeAll
    static void setUp() {
        serverCert = PkixCertTestHelper.createCertWithKey(ECParameters.tc26a256());
    }

    private static TlsHandshakeEngine server(int hashLen) {
        return new TlsHandshakeEngine(
                TlsHandshakeEngine.Role.SERVER,
                SUITE,
                new TlsMessageBuilder(
                        SUITE,
                        List.of(SUITE.getId()),
                        TlsConstants.GRP_GC256A,
                        TlsConstants.SIG_GOST_TC26_A_256,
                        serverCert.priv,
                        List.of(serverCert.cert),
                        TlsConstants.STREEBOG_256_HASH_LEN),
                ECParameters.tc26a256(),
                TlsConstants.GRP_GC256A,
                TlsConstants.SIG_GOST_TC26_A_256,
                hashLen,
                null,
                false,
                null);
    }

    @Test
    @DisplayName("длина хеша, не равная длине хеша набора шифров, отвергается при создании")
    void constructorRejectsHashLengthOfOtherSize() {
        assertThrows(
                IllegalArgumentException.class,
                () -> server(TlsConstants.STREEBOG_512_HASH_LEN),
                "Набор с хешем 32 и длина 64: ключи KeyUpdate вывелись бы по разным длинам");
    }

    @Test
    @DisplayName("setServerPsk(null): IllegalArgumentException, а не NullPointerException")
    void setServerPskRejectsNull() {
        TlsHandshakeEngine engine = server(TlsConstants.STREEBOG_256_HASH_LEN);

        assertThrows(IllegalArgumentException.class, () -> engine.setServerPsk(null));
    }
}
