package org.rssys.gost.pkix.cms;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import java.math.BigInteger;
import org.junit.jupiter.api.BeforeAll;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.signature.ECParameters;

/**
 * Fuzz-тесты для {@link CAdESExtender} и {@link CAdESAttributes}.
 *
 * <p>{@code CAdESExtender.embedTimestamp()} делает ручную DER-сборку SignedData
 * с инъекцией unsignedAttrs: decodeLength → contentOff = 1 + lenInfo[1] →
 * copyOfRange. При некорректной длине в DER contentOff выходит за границу.
 *
 * <p>{@code CAdESExtender.verify()} — полный пайплайн верификации CAdES-T:
 * CMS-верификация + разбор unsignedAttrs + парсинг TimeStampToken +
 * проверка signingCertificateV2.
 *
 * <p>ПОЧЕМУ два независимых входа для fuzzEmbedTimestamp: Jazzer мутирует
 * один сплошной блок при {@code consumeRemainingAsBytes()}. С {@code consumeBytes(n)}
 * + {@code consumeRemainingAsBytes()} покрываются комбинации «первый валидный,
 * второй битый» и наоборот.
 */
class CAdESFuzzTest {

    private static GostCertificate cert;

    @BeforeAll
    static void setUp() {
        java.security.Security.insertProviderAt(new org.rssys.gost.jca.RssysGostProvider(), 1);
        ECParameters params = ECParameters.tc26a256();
        var kp = KeyGenerator.generateKeyPair(params);
        cert =
                CmsTestUtils.createSelfSignedCert(
                        kp.getPrivate(),
                        kp.getPublic(),
                        BigInteger.valueOf(System.currentTimeMillis()));
    }

    @FuzzTest
    void fuzzEmbedTimestamp(FuzzedDataProvider data) {
        byte[] cadesBes = data.consumeBytes(data.consumeInt(0, 65536));
        byte[] tsToken = data.consumeRemainingAsBytes();
        if (cadesBes.length == 0 || tsToken.length == 0) return;
        try {
            CAdESExtender.embedTimestamp(cadesBes, tsToken);
        } catch (PkixException e) {
            // ожидаемо: битый DER, неверная структура
        } catch (RuntimeException e) {
            FuzzTestUtils.rethrowIfBug(e);
        }
    }

    @FuzzTest
    void fuzzVerifyCAdES(FuzzedDataProvider data) {
        byte[] der = data.consumeRemainingAsBytes();
        if (der.length == 0) return;
        try {
            CAdESExtender.verifyCAdEST(der, cert);
        } catch (PkixException e) {
            // ожидаемо: битый DER, неверная подпись, нет timestamp
        } catch (RuntimeException e) {
            FuzzTestUtils.rethrowIfBug(e);
        }
    }
}
