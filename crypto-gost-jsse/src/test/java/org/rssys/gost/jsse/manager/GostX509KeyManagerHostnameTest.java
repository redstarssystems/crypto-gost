package org.rssys.gost.jsse.manager;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.security.Security;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.GostJsseConstants;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;

/**
 * Выбор записи менеджера ключей по имени (SNI) и по типу ключа. Имя сопоставляется с
 * сертификатом так же, как при его проверке клиентом: регистр, завершающая точка и wildcard.
 */
@DisplayName("GostX509KeyManager: выбор по имени и по типу ключа")
class GostX509KeyManagerHostnameTest {

    private static GostX509KeyManager keyManager;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        ECParameters params = ECParameters.tc26a256();
        PkixCertTestHelper.CertBundle root = PkixCertTestHelper.createRootCA(params);
        keyManager = new GostX509KeyManager();
        addEntry("exact", params, root, "api.example.com");
        addEntry("wildcard", params, root, "*.example.org");
    }

    /** Ключ и цепочка записи берутся из одного сертификата, чтобы запись была пригодна к рукопожатию. */
    private static void addEntry(
            String alias, ECParameters params, PkixCertTestHelper.CertBundle root, String dnsName)
            throws Exception {
        PkixCertTestHelper.CertBundle leaf = leaf(params, root, dnsName);
        keyManager.addKeyEntry(alias, CertificateBridge.toJca(List.of(leaf.cert)), leaf.priv);
    }

    private static PkixCertTestHelper.CertBundle leaf(
            ECParameters params, PkixCertTestHelper.CertBundle root, String dnsName) {
        try {
            return PkixCertTestHelper.createCertSignedBy(
                    params,
                    root.priv,
                    root.cert.getPublicKey(),
                    root.subjectDn,
                    "240501120000Z",
                    "21060101120000Z",
                    new String[] {dnsName},
                    new byte[] {(byte) 0x80},
                    null,
                    false,
                    null);
        } catch (Exception e) {
            throw new IllegalStateException("не удалось создать тестовый сертификат", e);
        }
    }

    @Test
    @DisplayName("Регистр и завершающая точка в имени не мешают совпадению")
    void caseAndTrailingDotAreNormalized() {
        assertEquals("exact", keyManager.chooseAliasForHostname("API.Example.COM"));
        assertEquals("exact", keyManager.chooseAliasForHostname("api.example.com."));
    }

    @Test
    @DisplayName("Wildcard покрывает ровно одну метку слева")
    void wildcardCoversExactlyOneLabel() {
        assertEquals("wildcard", keyManager.chooseAliasForHostname("www.example.org"));
        assertNull(
                keyManager.chooseAliasForHostname("a.b.example.org"),
                "две метки слева wildcard не покрывает");
        assertNull(
                keyManager.chooseAliasForHostname("example.org"),
                "сам домен wildcard не покрывает");
    }

    @Test
    @DisplayName("Неизвестное имя даёт null, а отсутствие имени - первый алиас")
    void unknownNameAndMissingName() {
        assertNull(keyManager.chooseAliasForHostname("other.example.net"));
        assertEquals("exact", keyManager.chooseAliasForHostname(null));
    }

    @Test
    @DisplayName("Тип ключа: общий тип подходит ключу любого размера, размерные - по размеру")
    void keyTypeFiltering() {
        assertArrayEquals(
                new String[] {"exact", "wildcard"},
                keyManager.getClientAliases(GostJsseConstants.KEY_ALG_ECGOST_2012, null),
                "общий тип без размера подходит 256-битным ключам");
        assertArrayEquals(
                new String[] {"exact", "wildcard"},
                keyManager.getClientAliases(GostJsseConstants.KEY_TYPE_ECGOST_256, null),
                "256-битные ключи подходят типу 256");
        assertEquals(
                0,
                keyManager.getClientAliases(GostJsseConstants.KEY_TYPE_ECGOST_512, null).length,
                "512-битных ключей нет");
        assertEquals(
                0, keyManager.getServerAliases("RSA", null).length, "чужой тип ключа не подходит");
        assertEquals(
                "exact",
                keyManager.chooseServerAlias(GostJsseConstants.KEY_ALG_ECGOST_2012, null, null),
                "серверный выбор по общему типу");
    }
}
