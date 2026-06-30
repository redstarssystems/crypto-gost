package org.rssys.gost.tls13.cert;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostPkcs12Builder;
import org.rssys.gost.pkix.cert.GostPkcs12Loader;
import org.rssys.gost.pkix.cert.GostPkcs12Mac;
import org.rssys.gost.pkix.cert.GostPkcs12Parser;
import org.rssys.gost.pkix.cert.GostPkcs12Parser.*;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsTestHelper;

@DisplayName("GostPkcs12Builder — создание PFX-контейнеров ГОСТ")
class GostPkcs12BuilderTest {

    private static final char[] PASSWORD = "changeit".toCharArray();
    private static final int TEST_ITER = 100;

    // ========================================================================
    // Roundtrip: build -> load
    // ========================================================================

    @Test
    @DisplayName("Roundtrip OMAC: build -> load -> ключ и цепочка совпадают")
    void testRoundtripOmac() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(params);

        byte[] pfx =
                GostPkcs12Builder.create()
                        .key(bundle.priv)
                        .certificate(bundle.cert)
                        .password(PASSWORD)
                        .iterations(TEST_ITER)
                        .build();

        GostPkcs12Loader.Result result = GostPkcs12Loader.load(pfx, PASSWORD, true);

        assertNotNull(result.getPrivateKey(), "приватный ключ");
        assertNotNull(result.getCertificateChain(), "цепочка");
        assertFalse(result.getCertificateChain().isEmpty(), "цепочка не пуста");

        byte[] origKeyDer = GostDerCodec.encodePrivateKey(bundle.priv);
        byte[] loadedKeyDer = GostDerCodec.encodePrivateKey(result.getPrivateKey());
        assertArrayEquals(origKeyDer, loadedKeyDer, "ключи совпадают");

        byte[] origCertDer = bundle.cert.getEncoded();
        byte[] loadedCertDer = result.getCertificateChain().get(0).getEncoded();
        assertArrayEquals(origCertDer, loadedCertDer, "сертификаты совпадают");
    }

    @Test
    @DisplayName("Roundtrip CTR-ACPKM (без OMAC) -> load проходит")
    void testRoundtripNoOmac() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(params);

        byte[] pfx =
                GostPkcs12Builder.create()
                        .key(bundle.priv)
                        .certificate(bundle.cert)
                        .password(PASSWORD)
                        .encScheme(GostOids.KUZ_CTR_ACPKM)
                        .iterations(TEST_ITER)
                        .build();

        GostPkcs12Loader.Result result = GostPkcs12Loader.load(pfx, PASSWORD, true);
        assertNotNull(result.getPrivateKey(), "приватный ключ");
        assertNotNull(result.getCertificateChain(), "цепочка");
    }

    // ========================================================================
    // MAC verification
    // ========================================================================

    @Test
    @DisplayName("MAC: verify проходит после build")
    void testMacVerification() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(params);

        byte[] pfx =
                GostPkcs12Builder.create()
                        .key(bundle.priv)
                        .certificate(bundle.cert)
                        .password(PASSWORD)
                        .iterations(TEST_ITER)
                        .build();

        // Разобрать PFX и проверить MAC
        PfxData parsed = GostPkcs12Parser.parsePfx(pfx);
        assertNotNull(parsed.getMacData(), "MacData присутствует");

        byte[] passwordBytes =
                new String(PASSWORD).getBytes(java.nio.charset.StandardCharsets.UTF_8);
        assertDoesNotThrow(
                () ->
                        GostPkcs12Mac.verify(
                                parsed.getMacData(), passwordBytes, parsed.getAuthSafeRawContent()),
                "MAC верификация проходит");
    }

    // ========================================================================
    // Цепочка сертификатов (CA + leaf)
    // ========================================================================

    @Test
    @DisplayName("Cert chain: builder с 2 CA -> цепочка из 3 сертификатов")
    void testCertChain() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        TlsTestHelper.CertBundle ca = TlsTestHelper.createRootCA(params);
        TlsTestHelper.CertBundle leaf =
                TlsTestHelper.createCertSignedBy(
                        params,
                        ca.priv,
                        ca.cert.getPublicKey(),
                        ca.subjectDn,
                        "20250101000000Z",
                        "21060101120000Z",
                        null,
                        null,
                        null,
                        null,
                        false,
                        null);

        byte[] pfx =
                GostPkcs12Builder.create()
                        .key(leaf.priv)
                        .certificate(leaf.cert)
                        .caCertificate(ca.cert)
                        .password(PASSWORD)
                        .iterations(TEST_ITER)
                        .build();

        GostPkcs12Loader.Result result = GostPkcs12Loader.load(pfx, PASSWORD, true);
        List<GostCertificate> chain = result.getCertificateChain();

        assertEquals(2, chain.size(), "в цепочке 2 сертификата");
        assertArrayEquals(leaf.cert.getEncoded(), chain.get(0).getEncoded(), "конечный (не CA)");
        assertArrayEquals(ca.cert.getEncoded(), chain.get(1).getEncoded(), "УЦ");
    }

    // ========================================================================
    // friendlyName
    // ========================================================================

    @Test
    @DisplayName("friendlyName: build -> parse -> атрибут присутствует у ключа и leaf")
    void testFriendlyName() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(params);

        byte[] pfx =
                GostPkcs12Builder.create()
                        .key(bundle.priv)
                        .certificate(bundle.cert)
                        .password(PASSWORD)
                        .friendlyName("test-cert")
                        .iterations(TEST_ITER)
                        .build();

        PfxData parsed = GostPkcs12Parser.parsePfx(pfx);
        ContentInfoData ci = parsed.getAuthSafe().getContentInfos().get(0);
        byte[] safeContentsDer = GostPkcs12Parser.unwrapOctetString(ci.getContent());
        List<SafeBagData> bags = GostPkcs12Parser.parseSafeContents(safeContentsDer);

        // Первый bag — keyBag, должен иметь friendlyName
        List<BagAttribute> keyAttrs = bags.get(0).getAttributes();
        assertNotNull(keyAttrs, "keyBag имеет атрибуты");
        boolean hasFriendlyName =
                keyAttrs.stream().anyMatch(a -> GostOids.ATTR_FRIENDLY_NAME.equals(a.getAttrId()));
        assertTrue(hasFriendlyName, "keyBag содержит friendlyName");

        // Второй bag — leaf certBag, должен иметь friendlyName
        List<BagAttribute> certAttrs = bags.get(1).getAttributes();
        assertNotNull(certAttrs, "certBag имеет атрибуты");
        hasFriendlyName =
                certAttrs.stream().anyMatch(a -> GostOids.ATTR_FRIENDLY_NAME.equals(a.getAttrId()));
        assertTrue(hasFriendlyName, "certBag содержит friendlyName");
    }

    // ========================================================================
    // Пустой пароль (RFC 2104 §2 — пустой ключ HMAC допустим)
    // ========================================================================

    @Test
    @DisplayName("Пустой пароль: build -> load проходит")
    void testEmptyPassword() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(params);

        byte[] pfx =
                GostPkcs12Builder.create()
                        .key(bundle.priv)
                        .certificate(bundle.cert)
                        .password(new char[0])
                        .iterations(TEST_ITER)
                        .build();

        GostPkcs12Loader.Result result = GostPkcs12Loader.load(pfx, new char[0], true);
        assertNotNull(result.getPrivateKey(), "приватный ключ с пустым паролем");
        assertNotNull(result.getCertificateChain(), "цепочка с пустым паролем");
    }

    @Test
    @DisplayName("password=null -> преобразуется в пустой -> load проходит")
    void testNullPassword() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(params);

        byte[] pfx =
                GostPkcs12Builder.create()
                        .key(bundle.priv)
                        .certificate(bundle.cert)
                        .password(null)
                        .iterations(TEST_ITER)
                        .build();

        GostPkcs12Loader.Result result = GostPkcs12Loader.load(pfx, new char[0], true);
        assertNotNull(result.getPrivateKey(), "null пароль: ключ загружен");
    }

    // ========================================================================
    // localKeyId
    // ========================================================================

    @Test
    @DisplayName("localKeyId: ключ и leaf имеют одинаковый localKeyId")
    void testLocalKeyId() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(params);

        byte[] pfx =
                GostPkcs12Builder.create()
                        .key(bundle.priv)
                        .certificate(bundle.cert)
                        .password(PASSWORD)
                        .iterations(TEST_ITER)
                        .build();

        PfxData parsed = GostPkcs12Parser.parsePfx(pfx);
        ContentInfoData ci = parsed.getAuthSafe().getContentInfos().get(0);
        byte[] safeContentsDer = GostPkcs12Parser.unwrapOctetString(ci.getContent());
        List<SafeBagData> bags = GostPkcs12Parser.parseSafeContents(safeContentsDer);

        byte[] keyLocalKeyId = GostPkcs12Parser.findLocalKeyId(bags.get(0).getAttributes());
        byte[] certLocalKeyId = GostPkcs12Parser.findLocalKeyId(bags.get(1).getAttributes());

        assertNotNull(keyLocalKeyId, "keyBag имеет localKeyId");
        assertNotNull(certLocalKeyId, "leaf certBag имеет localKeyId");
        assertArrayEquals(keyLocalKeyId, certLocalKeyId, "localKeyId совпадает");
    }

    // ========================================================================
    // Повреждённые данные
    // ========================================================================

    @Test
    @DisplayName("Повреждённые данные: мутация байта -> load падает с ошибкой")
    void testCorruptedData() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(params);

        byte[] pfx =
                GostPkcs12Builder.create()
                        .key(bundle.priv)
                        .certificate(bundle.cert)
                        .password(PASSWORD)
                        .iterations(TEST_ITER)
                        .build();

        // Мутируем один байт
        pfx[pfx.length / 2] ^= 0xFF;

        assertThrows(
                Exception.class,
                () -> GostPkcs12Loader.load(pfx, PASSWORD, true),
                "повреждённые данные: load падает");
    }

    // ========================================================================
    // buildAndWriteTo (file I/O)
    // ========================================================================

    @Test
    @DisplayName("buildAndWriteTo: запись -> чтение файла -> load проходит")
    void testBuildAndWriteTo() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(params);

        Path tmpFile = Files.createTempFile("pfx-test-", ".p12");
        try {
            GostPkcs12Builder.create()
                    .key(bundle.priv)
                    .certificate(bundle.cert)
                    .password(PASSWORD)
                    .iterations(TEST_ITER)
                    .buildAndWriteTo(tmpFile);

            byte[] fromFile = Files.readAllBytes(tmpFile);
            assertTrue(fromFile.length > 0, "файл не пуст");

            GostPkcs12Loader.Result result = GostPkcs12Loader.load(fromFile, PASSWORD, true);
            assertNotNull(result.getPrivateKey(), "ключ из файла");
        } finally {
            Files.deleteIfExists(tmpFile);
        }
    }

    // ========================================================================
    // Проверка ошибок валидации
    // ========================================================================

    @Test
    @DisplayName("отсутствует ключ -> IllegalStateException")
    void testMissingKey() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(params);
        assertThrows(
                IllegalStateException.class,
                () ->
                        GostPkcs12Builder.create()
                                .certificate(bundle.cert)
                                .password(PASSWORD)
                                .build());
    }

    @Test
    @DisplayName("нулевое число итераций -> исключение")
    void testInvalidIterations() {
        assertThrows(
                IllegalArgumentException.class, () -> GostPkcs12Builder.create().iterations(0));
    }

    @Test
    @DisplayName("отрицательное число итераций -> исключение")
    void testNegativeIterations() {
        assertThrows(
                IllegalArgumentException.class, () -> GostPkcs12Builder.create().iterations(-1));
    }

    @Test
    @DisplayName("friendlyName > 64 UTF-8 байт -> IllegalArgumentException")
    void testFriendlyNameTooLong() {
        String longName = "a".repeat(65);
        assertThrows(
                IllegalArgumentException.class,
                () -> GostPkcs12Builder.create().friendlyName(longName));
    }
}
