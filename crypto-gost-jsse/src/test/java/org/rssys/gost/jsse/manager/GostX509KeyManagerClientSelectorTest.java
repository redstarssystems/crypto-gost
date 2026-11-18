package org.rssys.gost.jsse.manager;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.security.Security;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.config.ClientCertificateRequest;
import org.rssys.gost.tls13.config.ClientCertificateSelector;
import org.rssys.gost.tls13.config.TlsClientCredentials;

/**
 * Выбор клиентского сертификата по CertificateRequest: схемы подписи сервера, список CA, схемы
 * подписей цепочки (RFC 8446 §4.2.3, §4.2.4, §4.4.2.3, §4.4.3).
 */
@DisplayName("GostX509KeyManager.asClientCertificateSelector: выбор по запросу сервера")
class GostX509KeyManagerClientSelectorTest {

    private static final int SIG_256 = TlsConstants.SIG_GOST_TC26_A_256;
    private static final int SIG_512 = TlsConstants.SIG_GOST_TC26_512_A;

    /** rsa_pss_rsae_sha256: схема, которой у ГОСТ-ключей нет. */
    private static final int SIG_NON_GOST = 0x0804;

    private static PkixCertTestHelper.CertBundle root256;
    private static PkixCertTestHelper.CertBundle root512;
    private static PkixCertTestHelper.CertBundle leaf256;
    private static PkixCertTestHelper.CertBundle leaf512;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        root256 = PkixCertTestHelper.createRootCA(ECParameters.tc26a256());
        root512 = PkixCertTestHelper.createRootCA(ECParameters.tc26a512());
        leaf256 = leaf(ECParameters.tc26a256(), root256);
        leaf512 = leaf(ECParameters.tc26a512(), root512);
    }

    private static PkixCertTestHelper.CertBundle leaf(
            ECParameters params, PkixCertTestHelper.CertBundle ca) throws Exception {
        return PkixCertTestHelper.createCertSignedBy(
                params,
                ca.priv,
                ca.cert.getPublicKey(),
                ca.subjectDn,
                "240501120000Z",
                "21060101120000Z",
                null,
                new byte[] {(byte) 0x80},
                null,
                false,
                null);
    }

    private static void add(
            GostX509KeyManager km,
            String alias,
            PkixCertTestHelper.CertBundle leaf,
            PkixCertTestHelper.CertBundle ca)
            throws Exception {
        km.addKeyEntry(alias, CertificateBridge.toJca(List.of(leaf.cert, ca.cert)), leaf.priv);
    }

    private static GostX509KeyManager both() throws Exception {
        GostX509KeyManager km = new GostX509KeyManager();
        add(km, "k256", leaf256, root256);
        add(km, "k512", leaf512, root512);
        return km;
    }

    private static ClientCertificateRequest request(List<byte[]> caDns, int... schemes) {
        return new ClientCertificateRequest(caDns, List.of(), false, schemes, schemes);
    }

    private static TlsClientCredentials select(GostX509KeyManager km, ClientCertificateRequest r) {
        ClientCertificateSelector selector = km.asClientCertificateSelector();
        return selector.select(r);
    }

    @Test
    @DisplayName("Сервер предлагает только 512: выбран 512-битный сертификат, хотя 256 идёт первым")
    void onlyScheme512PicksSecondEntry() throws Exception {
        TlsClientCredentials selected = select(both(), request(List.of(), SIG_512));
        assertNotNull(selected, "подходящий сертификат есть");
        assertEquals(leaf512.cert, selected.chain().get(0), "должен быть 512-битный лист");
    }

    @Test
    @DisplayName("Схема листа обязательна, даже если подписи цепочки первой записи предложены")
    void leafSchemeIsRequiredRegardlessOfChainSchemes() throws Exception {
        // Подписи обеих цепочек сервер принимает, но подписывать CertificateVerify разрешил
        // только схемой 512: 256-битный лист нельзя отправлять, хотя он идёт первым
        ClientCertificateRequest request =
                new ClientCertificateRequest(
                        List.of(),
                        List.of(),
                        false,
                        new int[] {SIG_512},
                        new int[] {SIG_256, SIG_512});
        TlsClientCredentials selected = select(both(), request);
        assertEquals(leaf512.cert, selected.chain().get(0), "лист 256 не подходит по схеме");
    }

    @Test
    @DisplayName("Сервер предлагает только 256: выбран 256-битный сертификат")
    void onlyScheme256PicksFirstEntry() throws Exception {
        TlsClientCredentials selected = select(both(), request(List.of(), SIG_256));
        assertNotNull(selected, "подходящий сертификат есть");
        assertEquals(leaf256.cert, selected.chain().get(0), "должен быть 256-битный лист");
    }

    @Test
    @DisplayName("Сервер предлагает обе схемы: берётся первая запись")
    void bothSchemesPickFirstEntry() throws Exception {
        TlsClientCredentials selected = select(both(), request(List.of(), SIG_512, SIG_256));
        assertEquals(leaf256.cert, selected.chain().get(0), "порядок записей, а не сервера");
    }

    @Test
    @DisplayName("Сервер предлагает только не-ГОСТ схемы: null, то есть пустой Certificate")
    void onlyNonGostSchemesGiveNull() throws Exception {
        assertNull(select(both(), request(List.of(), SIG_NON_GOST)), "подходящих нет");
    }

    @Test
    @DisplayName("Пустой список CA не фильтрует, список с издателем фильтрует по нему")
    void authoritiesFilter() throws Exception {
        GostX509KeyManager km = both();
        int[] all = {SIG_256, SIG_512};

        TlsClientCredentials noFilter = select(km, request(List.of(), all));
        assertEquals(leaf256.cert, noFilter.chain().get(0), "пустой список CA не фильтрует");

        TlsClientCredentials byIssuer512 = select(km, request(List.of(root512.subjectDn), all));
        assertEquals(leaf512.cert, byIssuer512.chain().get(0), "лист выпущен корнем 512");

        assertNull(
                select(km, request(List.of(buildForeignDn()), all)),
                "ни один издатель не совпал: пустой Certificate, а не первый попавшийся");
    }

    @Test
    @DisplayName("CA сопоставляется по издателю любого сертификата цепочки, не только листа")
    void authorityMatchesIssuerOfIntermediate() throws Exception {
        PkixCertTestHelper.CertBundle intermediate =
                PkixCertTestHelper.createCertSignedBy(
                        ECParameters.tc26a256(),
                        root256.priv,
                        root256.cert.getPublicKey(),
                        root256.subjectDn,
                        "240501120000Z",
                        "21060101120000Z",
                        null,
                        new byte[] {(byte) 0x04},
                        null,
                        true,
                        null);
        PkixCertTestHelper.CertBundle leaf = leaf(ECParameters.tc26a256(), intermediate);
        GostX509KeyManager km = new GostX509KeyManager();
        km.addKeyEntry(
                "deep", CertificateBridge.toJca(List.of(leaf.cert, intermediate.cert)), leaf.priv);

        // Издатель листа - промежуточный, но сервер доверяет корню: издатель промежуточного
        assertNotNull(
                select(km, request(List.of(root256.subjectDn), SIG_256)),
                "корень издал промежуточный сертификат цепочки");
        assertNotNull(
                select(km, request(List.of(intermediate.subjectDn), SIG_256)),
                "промежуточный издал лист");
    }

    @Test
    @DisplayName(
            "Битый DN от сервера пропускается: исключения нет, совпадение с годным DN остаётся")
    void malformedAuthorityIsSkipped() throws Exception {
        GostX509KeyManager km = both();
        int[] all = {SIG_256, SIG_512};
        byte[] broken = {0x30, 0x05, 0x01};

        assertNull(
                select(km, request(List.of(broken), all)),
                "список не пуст, но ни один DN не разобрался: пустой Certificate");
        TlsClientCredentials selected =
                select(km, request(List.of(broken, root512.subjectDn), all));
        assertNotNull(selected, "годный DN рядом с битым совпадает");
        assertEquals(leaf512.cert, selected.chain().get(0), "совпал корень 512");
    }

    @Test
    @DisplayName(
            "Подписи цепочки: предпочитается запись, чьи схемы предложены, но это мягкий критерий")
    void chainSchemesArePreferenceNotRequirement() throws Exception {
        // Подпись листа проверяется ключом корня: у первой записи нужна схема 256, у второй 512.
        // Сборщик сертификатов смешанных по кривым цепочек не строит, поэтому различие задаёт
        // корень.
        GostX509KeyManager km = both();
        int[] bothLeaf = {SIG_256, SIG_512};

        ClientCertificateRequest chain512Only =
                new ClientCertificateRequest(
                        List.of(), List.of(), false, bothLeaf, new int[] {SIG_512});
        assertEquals(
                leaf512.cert,
                select(km, chain512Only).chain().get(0),
                "предложена схема цепочки второй записи: она предпочтительнее первой");

        ClientCertificateRequest noChainSchemes =
                new ClientCertificateRequest(List.of(), List.of(), false, bothLeaf, new int[0]);
        assertEquals(
                leaf256.cert,
                select(km, noChainSchemes).chain().get(0),
                "схем цепочки не предложено нигде: первая подошедшая по листу, а не отказ");
    }

    private static byte[] buildForeignDn() throws Exception {
        return PkixCertTestHelper.createRootCA(ECParameters.tc26a256()).subjectDn;
    }
}
