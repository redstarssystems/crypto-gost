package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.LogCapture;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.util.CryptoRandom;
import org.rssys.gost.util.DerCodec;

@DisplayName("GostPkcs12Loader — фильтрация по localKeyId и сортировка цепочки")
class GostPkcs12LoaderFilterTest {

    private static final char[] PASSWORD = "changeit".toCharArray();
    private static final int TEST_ITER = 100;

    // ========================================================================
    // Фильтрация по localKeyId
    // ========================================================================

    @Test
    @DisplayName(
            "certBag с localKeyId физически до keyBag — отфильтрован, chain пуст -> IllegalArgumentException")
    void testCertBagBeforeKeyBagWrongLocalKeyId() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        PkixCertTestHelper.CertBundle bundle = PkixCertTestHelper.createCertWithKey(params);

        byte[] keyLkid = new byte[] {0x01, 0x02, 0x03};
        byte[] certLkid = new byte[] {0x0A, 0x0B, 0x0C};

        byte[] pfx = buildPfxCertFirst(bundle.priv, keyLkid, bundle.cert, certLkid);

        assertThrows(
                IllegalArgumentException.class,
                () -> GostPkcs12Loader.load(pfx, PASSWORD, true, 50),
                "должно упасть с пустой цепочкой после фильтрации");
    }

    @Test
    @DisplayName("certBag без localKeyId физически до keyBag — проходит (CA-сертификат)")
    void testCertBagWithoutLocalKeyIdBeforeKeyBag() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        PkixCertTestHelper.CertBundle bundle = PkixCertTestHelper.createCertWithKey(params);

        byte[] keyLkid = new byte[] {0x01, 0x02, 0x03};

        byte[] pfx = buildPfxCertFirst(bundle.priv, keyLkid, bundle.cert, null);

        GostPkcs12Loader.Result result = GostPkcs12Loader.load(pfx, PASSWORD, true, 50);
        assertNotNull(result.getPrivateKey(), "ключ загружен");
        assertNotNull(result.getCertificateChain(), "цепочка не null");
        assertFalse(result.getCertificateChain().isEmpty(), "цепочка не пуста");
    }

    @Test
    @DisplayName("ключ без localKeyId — все сертификаты проходят (нет регрессии)")
    void testKeyWithoutLocalKeyId() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        PkixCertTestHelper.CertBundle bundle = PkixCertTestHelper.createCertWithKey(params);

        byte[] certLkid = new byte[] {0x0A, 0x0B, 0x0C};

        byte[] pfx = buildPfx(bundle.priv, null, new CertBagDef(bundle.cert, certLkid));

        GostPkcs12Loader.Result result = GostPkcs12Loader.load(pfx, PASSWORD, true, 50);
        assertNotNull(result.getPrivateKey(), "ключ загружен");
        assertEquals(1, result.getCertificateChain().size(), "сертификат загружен");
    }

    // ========================================================================
    // Сортировка цепочки leaf-first
    // ========================================================================

    @Test
    @DisplayName("CA перед leaf — цепочка leaf-first")
    void testCaBeforeLeaf() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        PkixCertTestHelper.CertBundle ca = PkixCertTestHelper.createRootCA(params);
        PkixCertTestHelper.CertBundle leaf =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        ca.priv,
                        ca.cert.getPublicKey(),
                        ca.subjectDn,
                        "20240501120000Z",
                        "21060101120000Z",
                        null,
                        null,
                        null,
                        null,
                        false,
                        null);

        byte[] keyLkid = new byte[20];
        CryptoRandom.INSTANCE.nextBytes(keyLkid);

        byte[] pfx =
                buildPfx(
                        leaf.priv,
                        keyLkid,
                        new CertBagDef(ca.cert, null),
                        new CertBagDef(leaf.cert, keyLkid));

        GostPkcs12Loader.Result result = GostPkcs12Loader.load(pfx, PASSWORD, true, 50);
        List<GostCertificate> chain = result.getCertificateChain();
        assertEquals(2, chain.size());
        assertFalse(chain.get(0).isCA(), "chain[0] — leaf (не CA)");
        assertTrue(chain.get(1).isCA(), "chain[1] — УЦ");
    }

    @Test
    @DisplayName("intermediate CA — топологическая сортировка leaf->intermediate->root")
    void testIntermediateCa() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        PkixCertTestHelper.CertBundle root = PkixCertTestHelper.createRootCA(params);
        PkixCertTestHelper.CertBundle intermediate =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "20240501120000Z",
                        "21060101120000Z",
                        null,
                        null,
                        null,
                        null,
                        true,
                        null);
        PkixCertTestHelper.CertBundle leaf =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        intermediate.priv,
                        intermediate.cert.getPublicKey(),
                        intermediate.subjectDn,
                        "20240501120000Z",
                        "21060101120000Z",
                        null,
                        null,
                        null,
                        null,
                        false,
                        null);

        byte[] keyLkid = new byte[20];
        CryptoRandom.INSTANCE.nextBytes(keyLkid);

        byte[] pfx =
                buildPfx(
                        leaf.priv,
                        keyLkid,
                        new CertBagDef(root.cert, null),
                        new CertBagDef(intermediate.cert, null),
                        new CertBagDef(leaf.cert, keyLkid));

        GostPkcs12Loader.Result result = GostPkcs12Loader.load(pfx, PASSWORD, true, 50);
        List<GostCertificate> chain = result.getCertificateChain();
        assertEquals(3, chain.size(), "три сертификата");
        assertFalse(chain.get(0).isCA(), "chain[0] — конечный (не CA)");
        assertTrue(chain.get(1).isCA(), "chain[1] — промежуточный");
        assertTrue(chain.get(2).isCA(), "chain[2] — корневой");

        // Проверка issuer->subject по DER-байтам
        assertArrayEquals(
                chain.get(0).getIssuerDnBytes(),
                chain.get(1).getSubjectDnBytes(),
                "издатель leaf = субъект intermediate");
        assertArrayEquals(
                chain.get(1).getIssuerDnBytes(),
                chain.get(2).getSubjectDnBytes(),
                "издатель intermediate = субъект root");
    }

    @Test
    @DisplayName("старый leaf без localKeyId перед актуальным — leaf выбирается по ключу")
    void testOldLeafBeforeCurrentLeaf() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        PkixCertTestHelper.CertBundle ca = PkixCertTestHelper.createRootCA(params);
        PkixCertTestHelper.CertBundle current =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        ca.priv,
                        ca.cert.getPublicKey(),
                        ca.subjectDn,
                        "20240501120000Z",
                        "21060101120000Z",
                        null,
                        null,
                        null,
                        null,
                        false,
                        null);
        PkixCertTestHelper.CertBundle old = PkixCertTestHelper.createCertWithKey(params);

        byte[] keyLkid = new byte[20];
        CryptoRandom.INSTANCE.nextBytes(keyLkid);

        byte[] pfx =
                buildPfx(
                        current.priv,
                        keyLkid,
                        new CertBagDef(old.cert, null),
                        new CertBagDef(current.cert, keyLkid),
                        new CertBagDef(ca.cert, null));

        GostPkcs12Loader.Result result = GostPkcs12Loader.load(pfx, PASSWORD, true, 50);
        List<GostCertificate> chain = result.getCertificateChain();
        assertEquals(2, chain.size(), "актуальный leaf и CA");
        assertArrayEquals(
                current.cert.getEncoded(),
                chain.get(0).getEncoded(),
                "выбран сертификат, совпадающий с ключом");
        assertEquals(1, result.getDroppedCertificateCount(), "старый leaf отброшен");
    }

    // ========================================================================
    // Граничные случаи orderChain
    // ========================================================================

    @Test
    @DisplayName(
            "два leaf с одинаковым localKeyId — остаётся только сертификат, совпадающий с ключом")
    void testTwoLeafSameLocalKeyId() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        PkixCertTestHelper.CertBundle leaf1 = PkixCertTestHelper.createCertWithKey(params);
        PkixCertTestHelper.CertBundle leaf2 = PkixCertTestHelper.createCertWithKey(params);

        byte[] keyLkid = new byte[20];
        CryptoRandom.INSTANCE.nextBytes(keyLkid);

        byte[] pfx =
                buildPfx(
                        leaf1.priv,
                        keyLkid,
                        new CertBagDef(leaf1.cert, keyLkid),
                        new CertBagDef(leaf2.cert, keyLkid));

        GostPkcs12Loader.Result result = GostPkcs12Loader.load(pfx, PASSWORD, true, 50);
        assertEquals(1, result.getCertificateChain().size(), "лишний сертификат отброшен");
        assertEquals(1, result.getDroppedCertificateCount(), "счётчик отброшенных");
    }

    @Test
    @DisplayName("только CA (без leaf) — как есть, без падения")
    void testOnlyCaNoLeaf() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        PkixCertTestHelper.CertBundle ca = PkixCertTestHelper.createRootCA(params);

        byte[] keyLkid = new byte[20];
        CryptoRandom.INSTANCE.nextBytes(keyLkid);

        byte[] pfx = buildPfx(ca.priv, keyLkid, new CertBagDef(ca.cert, null));

        GostPkcs12Loader.Result result = GostPkcs12Loader.load(pfx, PASSWORD, true, 50);
        assertEquals(1, result.getCertificateChain().size(), "один CA-сертификат");
        assertTrue(result.getCertificateChain().get(0).isCA(), "это УЦ");
    }

    @Test
    @DisplayName("нормальный порядок (keyBag, leaf, CA) — не сломан сортировкой")
    void testNormalOrderNotBroken() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        PkixCertTestHelper.CertBundle ca = PkixCertTestHelper.createRootCA(params);
        PkixCertTestHelper.CertBundle leaf =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        ca.priv,
                        ca.cert.getPublicKey(),
                        ca.subjectDn,
                        "20240501120000Z",
                        "21060101120000Z",
                        null,
                        null,
                        null,
                        null,
                        false,
                        null);

        byte[] keyLkid = new byte[20];
        CryptoRandom.INSTANCE.nextBytes(keyLkid);

        byte[] pfx =
                buildPfx(
                        leaf.priv,
                        keyLkid,
                        new CertBagDef(leaf.cert, keyLkid),
                        new CertBagDef(ca.cert, null));

        GostPkcs12Loader.Result result = GostPkcs12Loader.load(pfx, PASSWORD, true, 50);
        List<GostCertificate> chain = result.getCertificateChain();
        assertEquals(2, chain.size());
        assertFalse(chain.get(0).isCA(), "chain[0] — конечный (не CA)");
        assertTrue(chain.get(1).isCA(), "chain[1] — УЦ");
    }

    @Test
    @DisplayName("PKCS#12 без MacData: REQUIRED отклоняет, ALLOW_MISSING загружает")
    void testMissingMacPolicy() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        PkixCertTestHelper.CertBundle bundle = PkixCertTestHelper.createCertWithKey(params);
        byte[] pfx = buildPfxWithoutMac(bundle.priv, null, new CertBagDef(bundle.cert, null));

        assertThrows(
                IllegalArgumentException.class,
                () -> GostPkcs12Loader.load(pfx, PASSWORD, true, 50),
                "без MAC строгий режим должен отклонять");

        GostPkcs12Loader.Result result =
                GostPkcs12Loader.load(
                        pfx, PASSWORD, true, 50, GostPkcs12Loader.MacPolicy.ALLOW_MISSING);
        assertEquals(1, result.getCertificateChain().size(), "сертификат загружен");
    }

    @Test
    @DisplayName("PKCS#12: ключ не соответствует сертификату -> отказ")
    void testKeyDoesNotMatchCertificate() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        PkixCertTestHelper.CertBundle keyBundle = PkixCertTestHelper.createCertWithKey(params);
        PkixCertTestHelper.CertBundle certBundle = PkixCertTestHelper.createCertWithKey(params);

        byte[] pfx = buildPfx(keyBundle.priv, null, new CertBagDef(certBundle.cert, null));

        assertThrows(
                IllegalArgumentException.class,
                () -> GostPkcs12Loader.load(pfx, PASSWORD, true, 50),
                "несовпадение ключа и сертификата должно отклоняться");
    }

    @Test
    @DisplayName("PoC: удалён MAC и подменён CA в SafeContents — строгий load и trustCa отклоняют")
    void testPocMissingMacAndForeignCa() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        PkixCertTestHelper.CertBundle ca = PkixCertTestHelper.createRootCA(params);
        PkixCertTestHelper.CertBundle leaf =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        ca.priv,
                        ca.cert.getPublicKey(),
                        ca.subjectDn,
                        "20240501120000Z",
                        "21060101120000Z",
                        null,
                        null,
                        null,
                        null,
                        false,
                        null);
        PkixCertTestHelper.CertBundle foreignCa = PkixCertTestHelper.createRootCA(params);

        byte[] keyLkid = new byte[20];
        CryptoRandom.INSTANCE.nextBytes(keyLkid);
        byte[] pfx =
                buildPfxWithoutMac(
                        leaf.priv,
                        keyLkid,
                        new CertBagDef(leaf.cert, keyLkid),
                        new CertBagDef(foreignCa.cert, null));

        assertThrows(
                IllegalArgumentException.class,
                () -> GostPkcs12Loader.load(pfx, PASSWORD, true, 50),
                "без MAC строгий load должен отклонять");

        GostPkcs12Loader.Result result =
                GostPkcs12Loader.load(
                        pfx, PASSWORD, true, 50, GostPkcs12Loader.MacPolicy.ALLOW_MISSING);
        assertEquals(1, result.getCertificateChain().size(), "чужой CA не попал в цепочку");
        assertEquals(1, result.getDroppedCertificateCount(), "чужой CA отброшен");
    }

    // ========================================================================
    // CA-only контейнеры: ключ УЦ вместо конечного сертификата
    // ========================================================================

    @Test
    @DisplayName(
            "PFX промежуточного УЦ с обратным порядком [root, intermediate] -> [intermediate, root]")
    void testIntermediateCaKeyReverseOrder() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        PkixCertTestHelper.CertBundle root = PkixCertTestHelper.createRootCA(params);
        PkixCertTestHelper.CertBundle intermediate = createCaSignedBy(params, root);

        byte[] pfx =
                buildPfx(
                        intermediate.priv,
                        null,
                        new CertBagDef(root.cert, null),
                        new CertBagDef(intermediate.cert, null));

        GostPkcs12Loader.Result result = GostPkcs12Loader.load(pfx, PASSWORD, true, 50);
        List<GostCertificate> chain = result.getCertificateChain();
        assertEquals(2, chain.size(), "два звена");
        assertArrayEquals(
                intermediate.cert.getEncoded(),
                chain.get(0).getEncoded(),
                "chain[0] — сертификат, совпавший с ключом");
        assertArrayEquals(root.cert.getEncoded(), chain.get(1).getEncoded(), "chain[1] — корень");
        assertEquals(0, result.getDroppedCertificateCount(), "ничего не отброшено");
    }

    @Test
    @DisplayName(
            "CA-only с независимым корнем: в цепочке только ветка ключа, все CA в getAllCertificates")
    void testCaOnlyIndependentRootKeptOnlyInAll() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        PkixCertTestHelper.CertBundle root = PkixCertTestHelper.createRootCA(params);
        PkixCertTestHelper.CertBundle intermediate = createCaSignedBy(params, root);
        PkixCertTestHelper.CertBundle unrelatedRoot = PkixCertTestHelper.createRootCA(params);

        byte[] pfx =
                buildPfx(
                        intermediate.priv,
                        null,
                        new CertBagDef(unrelatedRoot.cert, null),
                        new CertBagDef(intermediate.cert, null),
                        new CertBagDef(root.cert, null));

        GostPkcs12Loader.Result result;
        try (LogCapture log = LogCapture.start(LogCapture.PKIX)) {
            result = GostPkcs12Loader.load(pfx, PASSWORD, true, 50);

            // Лишние сертификаты в контейнере обычны, на ключ и цепочку не влияют: только DEBUG
            assertEquals(
                    List.of(),
                    log.messagesAtOrAbove(Level.WARNING),
                    "отброшенные сертификаты не дают WARNING");
            assertTrue(
                    log.messages(Level.FINE).stream()
                            .anyMatch(m -> m.contains("1 unrelated certificate(s) dropped")),
                    "число отброшенных видно на DEBUG: " + log.messages(Level.FINE));
        }
        assertEquals(
                2, result.getCertificateChain().size(), "цепочка ключа без постороннего корня");
        assertEquals(1, result.getDroppedCertificateCount(), "посторонний корень не в цепочке");
        assertEquals(3, result.getAllCertificates().size(), "все CA доступны для trust-бандла");
    }

    @Test
    @DisplayName("CA-only: подмена на сертификат с чужим ключом отклоняется")
    void testCaOnlyKeyMismatchRejected() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        PkixCertTestHelper.CertBundle keyOwner = PkixCertTestHelper.createRootCA(params);
        PkixCertTestHelper.CertBundle foreignRoot = PkixCertTestHelper.createRootCA(params);

        byte[] pfx =
                buildPfx(
                        keyOwner.priv,
                        null,
                        new CertBagDef(foreignRoot.cert, null),
                        new CertBagDef(PkixCertTestHelper.createRootCA(params).cert, null));

        assertThrows(
                IllegalArgumentException.class,
                () -> GostPkcs12Loader.load(pfx, PASSWORD, true, 50),
                "ни один CA не соответствует ключу — контейнер должен отклоняться");
    }

    // ========================================================================
    // Хелперы сборки PFX
    // ========================================================================

    private static PkixCertTestHelper.CertBundle createCaSignedBy(
            ECParameters params, PkixCertTestHelper.CertBundle issuer) throws Exception {
        return PkixCertTestHelper.createCertSignedBy(
                params,
                issuer.priv,
                issuer.cert.getPublicKey(),
                issuer.subjectDn,
                "20240501120000Z",
                "21060101120000Z",
                null,
                null,
                null,
                null,
                true,
                null);
    }

    private static byte[] buildPfx(
            PrivateKeyParameters key, byte[] keyLocalKeyId, CertBagDef... certBags)
            throws Exception {
        byte[] passwordBytes = PkixCertTestHelper.toUtf8Bytes(PASSWORD);

        byte[] encryptedKeyBytes =
                GostPbes2.encryptKey(key, passwordBytes, GostOids.KUZ_CTR_ACPKM_OMAC, TEST_ITER);
        byte[] keyBag = buildKeyBagDer(encryptedKeyBytes, keyLocalKeyId);

        List<byte[]> bagDers = new ArrayList<>();
        bagDers.add(keyBag);
        for (CertBagDef cbd : certBags) {
            bagDers.add(buildCertBagDer(cbd.cert.getEncoded(), cbd.localKeyId));
        }

        byte[] safeContents = DerCodec.encodeSequence(bagDers.toArray(new byte[0][]));

        byte[] dataContentInfo =
                DerCodec.encodeSequence(
                        DerCodec.encodeOid(GostOids.PKCS7_DATA),
                        DerCodec.encodeContextConstructed(
                                0, DerCodec.encodeOctetString(safeContents)));

        byte[] authSafe = DerCodec.encodeSequence(dataContentInfo);

        byte[] outerContentInfo =
                DerCodec.encodeSequence(
                        DerCodec.encodeOid(GostOids.PKCS7_DATA),
                        DerCodec.encodeContextConstructed(0, DerCodec.encodeOctetString(authSafe)));

        byte[] salt = new byte[16];
        CryptoRandom.INSTANCE.nextBytes(salt);
        byte[] macData = GostPkcs12Mac.compute(authSafe, passwordBytes, TEST_ITER, salt);

        return DerCodec.encodeSequence(DerCodec.encodeInteger(3), outerContentInfo, macData);
    }

    private static byte[] buildPfxWithoutMac(
            PrivateKeyParameters key, byte[] keyLocalKeyId, CertBagDef... certBags)
            throws Exception {
        byte[] passwordBytes = PkixCertTestHelper.toUtf8Bytes(PASSWORD);

        byte[] encryptedKeyBytes =
                GostPbes2.encryptKey(key, passwordBytes, GostOids.KUZ_CTR_ACPKM_OMAC, TEST_ITER);
        byte[] keyBag = buildKeyBagDer(encryptedKeyBytes, keyLocalKeyId);

        List<byte[]> bagDers = new ArrayList<>();
        bagDers.add(keyBag);
        for (CertBagDef cbd : certBags) {
            bagDers.add(buildCertBagDer(cbd.cert.getEncoded(), cbd.localKeyId));
        }

        byte[] safeContents = DerCodec.encodeSequence(bagDers.toArray(new byte[0][]));

        byte[] dataContentInfo =
                DerCodec.encodeSequence(
                        DerCodec.encodeOid(GostOids.PKCS7_DATA),
                        DerCodec.encodeContextConstructed(
                                0, DerCodec.encodeOctetString(safeContents)));

        byte[] authSafe = DerCodec.encodeSequence(dataContentInfo);
        byte[] outerContentInfo =
                DerCodec.encodeSequence(
                        DerCodec.encodeOid(GostOids.PKCS7_DATA),
                        DerCodec.encodeContextConstructed(0, DerCodec.encodeOctetString(authSafe)));

        return DerCodec.encodeSequence(DerCodec.encodeInteger(3), outerContentInfo);
    }

    private static byte[] buildPfxCertFirst(
            PrivateKeyParameters key,
            byte[] keyLocalKeyId,
            GostCertificate cert,
            byte[] certLocalKeyId)
            throws Exception {
        byte[] passwordBytes = PkixCertTestHelper.toUtf8Bytes(PASSWORD);

        byte[] encryptedKeyBytes =
                GostPbes2.encryptKey(key, passwordBytes, GostOids.KUZ_CTR_ACPKM_OMAC, TEST_ITER);

        List<byte[]> bagDers = new ArrayList<>();
        bagDers.add(buildCertBagDer(cert.getEncoded(), certLocalKeyId));
        bagDers.add(buildKeyBagDer(encryptedKeyBytes, keyLocalKeyId));

        byte[] safeContents = DerCodec.encodeSequence(bagDers.toArray(new byte[0][]));

        byte[] dataContentInfo =
                DerCodec.encodeSequence(
                        DerCodec.encodeOid(GostOids.PKCS7_DATA),
                        DerCodec.encodeContextConstructed(
                                0, DerCodec.encodeOctetString(safeContents)));

        byte[] authSafe = DerCodec.encodeSequence(dataContentInfo);

        byte[] outerContentInfo =
                DerCodec.encodeSequence(
                        DerCodec.encodeOid(GostOids.PKCS7_DATA),
                        DerCodec.encodeContextConstructed(0, DerCodec.encodeOctetString(authSafe)));

        byte[] salt = new byte[16];
        CryptoRandom.INSTANCE.nextBytes(salt);
        byte[] macData = GostPkcs12Mac.compute(authSafe, passwordBytes, TEST_ITER, salt);

        return DerCodec.encodeSequence(DerCodec.encodeInteger(3), outerContentInfo, macData);
    }

    private static byte[] buildKeyBagDer(byte[] encryptedKeyDer, byte[] localKeyId) {
        byte[] bagValue = DerCodec.encodeContextConstructed(0, encryptedKeyDer);
        if (localKeyId != null) {
            byte[] attr = buildLocalKeyIdAttr(localKeyId);
            byte[] attrs = DerCodec.encodeSet(attr);
            return DerCodec.encodeSequence(
                    DerCodec.encodeOid(GostOids.BAG_PKCS8_SHROUDED_KEY), bagValue, attrs);
        }
        return DerCodec.encodeSequence(
                DerCodec.encodeOid(GostOids.BAG_PKCS8_SHROUDED_KEY), bagValue);
    }

    private static byte[] buildCertBagDer(byte[] certDer, byte[] localKeyId) {
        byte[] certBagContent =
                DerCodec.encodeSequence(
                        DerCodec.encodeOid(GostOids.PKCS9_X509_CERT),
                        DerCodec.encodeContextConstructed(0, DerCodec.encodeOctetString(certDer)));
        byte[] bagValue = DerCodec.encodeContextConstructed(0, certBagContent);
        if (localKeyId != null) {
            byte[] attr = buildLocalKeyIdAttr(localKeyId);
            byte[] attrs = DerCodec.encodeSet(attr);
            return DerCodec.encodeSequence(DerCodec.encodeOid(GostOids.BAG_CERT), bagValue, attrs);
        }
        return DerCodec.encodeSequence(DerCodec.encodeOid(GostOids.BAG_CERT), bagValue);
    }

    private static byte[] buildLocalKeyIdAttr(byte[] keyId) {
        return DerCodec.encodeSequence(
                DerCodec.encodeOid(GostOids.ATTR_LOCAL_KEY_ID),
                DerCodec.encodeSet(DerCodec.encodeOctetString(keyId)));
    }

    private static final class CertBagDef {
        final GostCertificate cert;
        final byte[] localKeyId;

        CertBagDef(GostCertificate cert, byte[] localKeyId) {
            this.cert = cert;
            this.localKeyId = localKeyId;
        }
    }
}
