package org.rssys.gost.tls13.cert;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.tls13.GostOids;
import org.rssys.gost.tls13.TlsTestHelper;
import org.rssys.gost.util.CryptoRandom;
import org.rssys.gost.util.DerCodec;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("GostPkcs12Loader — фильтрация по localKeyId и сортировка цепочки")
class GostPkcs12LoaderFilterTest {

    private static final char[] PASSWORD = "changeit".toCharArray();
    private static final int TEST_ITER = 100;

    // ========================================================================
    // Фильтрация по localKeyId
    // ========================================================================

    @Test
    @DisplayName("certBag с localKeyId физически до keyBag — отфильтрован, chain пуст → IllegalArgumentException")
    void testCertBagBeforeKeyBagWrongLocalKeyId() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(params);

        byte[] keyLkid = new byte[]{0x01, 0x02, 0x03};
        byte[] certLkid = new byte[]{0x0A, 0x0B, 0x0C};

        byte[] pfx = buildPfxCertFirst(bundle.priv, keyLkid, bundle.cert, certLkid);

        assertThrows(IllegalArgumentException.class,
            () -> GostPkcs12Loader.load(pfx, PASSWORD),
            "должно упасть с пустой цепочкой после фильтрации");
    }

    @Test
    @DisplayName("certBag без localKeyId физически до keyBag — проходит (CA-сертификат)")
    void testCertBagWithoutLocalKeyIdBeforeKeyBag() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(params);

        byte[] keyLkid = new byte[]{0x01, 0x02, 0x03};

        byte[] pfx = buildPfxCertFirst(bundle.priv, keyLkid, bundle.cert, null);

        GostPkcs12Loader.Result result = GostPkcs12Loader.load(pfx, PASSWORD);
        assertNotNull(result.getPrivateKey(), "ключ загружен");
        assertNotNull(result.getCertificateChain(), "цепочка не null");
        assertFalse(result.getCertificateChain().isEmpty(), "цепочка не пуста");
    }

    @Test
    @DisplayName("ключ без localKeyId — все сертификаты проходят (нет регрессии)")
    void testKeyWithoutLocalKeyId() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(params);

        byte[] certLkid = new byte[]{0x0A, 0x0B, 0x0C};

        byte[] pfx = buildPfx(bundle.priv, null,
            new CertBagDef(bundle.cert, certLkid));

        GostPkcs12Loader.Result result = GostPkcs12Loader.load(pfx, PASSWORD);
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
        TlsTestHelper.CertBundle ca = TlsTestHelper.createRootCA(params);
        TlsTestHelper.CertBundle leaf = TlsTestHelper.createCertSignedBy(
            params, ca.priv, ca.cert.getPublicKey(), ca.subjectDn,
            "20240501120000Z", "21060101120000Z",
            null, null, null, false, null);

        byte[] keyLkid = new byte[20];
        CryptoRandom.INSTANCE.nextBytes(keyLkid);

        byte[] pfx = buildPfx(leaf.priv, keyLkid,
            new CertBagDef(ca.cert, null),
            new CertBagDef(leaf.cert, keyLkid));

        GostPkcs12Loader.Result result = GostPkcs12Loader.load(pfx, PASSWORD);
        List<TlsCertificate> chain = result.getCertificateChain();
        assertEquals(2, chain.size());
        assertFalse(chain.get(0).isCA(), "chain[0] — leaf (не CA)");
        assertTrue(chain.get(1).isCA(), "chain[1] — CA");
    }

    @Test
    @DisplayName("intermediate CA — топологическая сортировка leaf→intermediate→root")
    void testIntermediateCa() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        TlsTestHelper.CertBundle root = TlsTestHelper.createRootCA(params);
        TlsTestHelper.CertBundle intermediate = TlsTestHelper.createCertSignedBy(
            params, root.priv, root.cert.getPublicKey(), root.subjectDn,
            "20240501120000Z", "21060101120000Z",
            null, null, null, true, null);
        TlsTestHelper.CertBundle leaf = TlsTestHelper.createCertSignedBy(
            params, intermediate.priv, intermediate.cert.getPublicKey(), intermediate.subjectDn,
            "20240501120000Z", "21060101120000Z",
            null, null, null, false, null);

        byte[] keyLkid = new byte[20];
        CryptoRandom.INSTANCE.nextBytes(keyLkid);

        byte[] pfx = buildPfx(leaf.priv, keyLkid,
            new CertBagDef(root.cert, null),
            new CertBagDef(intermediate.cert, null),
            new CertBagDef(leaf.cert, keyLkid));

        GostPkcs12Loader.Result result = GostPkcs12Loader.load(pfx, PASSWORD);
        List<TlsCertificate> chain = result.getCertificateChain();
        assertEquals(3, chain.size(), "три сертификата");
        assertFalse(chain.get(0).isCA(), "chain[0] — leaf");
        assertTrue(chain.get(1).isCA(), "chain[1] — intermediate");
        assertTrue(chain.get(2).isCA(), "chain[2] — root");

        // Проверка issuer→subject по DER-байтам
        assertArrayEquals(
            chain.get(0).getIssuerDnBytes(), chain.get(1).getSubjectDnBytes(),
            "leaf issuer = intermediate subject");
        assertArrayEquals(
            chain.get(1).getIssuerDnBytes(), chain.get(2).getSubjectDnBytes(),
            "intermediate issuer = root subject");
    }

    // ========================================================================
    // Граничные случаи orderChain
    // ========================================================================

    @Test
    @DisplayName("два leaf с одинаковым localKeyId — не падает, берётся первый")
    void testTwoLeafSameLocalKeyId() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        TlsTestHelper.CertBundle leaf1 = TlsTestHelper.createCertWithKey(params);
        TlsTestHelper.CertBundle leaf2 = TlsTestHelper.createCertWithKey(params);

        byte[] keyLkid = new byte[20];
        CryptoRandom.INSTANCE.nextBytes(keyLkid);

        byte[] pfx = buildPfx(leaf1.priv, keyLkid,
            new CertBagDef(leaf1.cert, keyLkid),
            new CertBagDef(leaf2.cert, keyLkid));

        GostPkcs12Loader.Result result = GostPkcs12Loader.load(pfx, PASSWORD);
        assertEquals(2, result.getCertificateChain().size(), "два сертификата");
    }

    @Test
    @DisplayName("только CA (без leaf) — как есть, без падения")
    void testOnlyCaNoLeaf() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        TlsTestHelper.CertBundle ca = TlsTestHelper.createRootCA(params);

        byte[] keyLkid = new byte[20];
        CryptoRandom.INSTANCE.nextBytes(keyLkid);

        byte[] pfx = buildPfx(ca.priv, keyLkid,
            new CertBagDef(ca.cert, null));

        GostPkcs12Loader.Result result = GostPkcs12Loader.load(pfx, PASSWORD);
        assertEquals(1, result.getCertificateChain().size(), "один CA-сертификат");
        assertTrue(result.getCertificateChain().get(0).isCA(), "это CA");
    }

    @Test
    @DisplayName("нормальный порядок (keyBag, leaf, CA) — не сломан сортировкой")
    void testNormalOrderNotBroken() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        TlsTestHelper.CertBundle ca = TlsTestHelper.createRootCA(params);
        TlsTestHelper.CertBundle leaf = TlsTestHelper.createCertSignedBy(
            params, ca.priv, ca.cert.getPublicKey(), ca.subjectDn,
            "20240501120000Z", "21060101120000Z",
            null, null, null, false, null);

        byte[] keyLkid = new byte[20];
        CryptoRandom.INSTANCE.nextBytes(keyLkid);

        byte[] pfx = buildPfx(leaf.priv, keyLkid,
            new CertBagDef(leaf.cert, keyLkid),
            new CertBagDef(ca.cert, null));

        GostPkcs12Loader.Result result = GostPkcs12Loader.load(pfx, PASSWORD);
        List<TlsCertificate> chain = result.getCertificateChain();
        assertEquals(2, chain.size());
        assertFalse(chain.get(0).isCA(), "chain[0] — leaf");
        assertTrue(chain.get(1).isCA(), "chain[1] — CA");
    }

    // ========================================================================
    // Хелперы сборки PFX
    // ========================================================================

    private static byte[] buildPfx(PrivateKeyParameters key, byte[] keyLocalKeyId,
                                   CertBagDef... certBags) throws Exception {
        byte[] passwordBytes = GostPkcs12Loader.toUtf8Bytes(PASSWORD);

        byte[] encryptedKeyBytes = GostPbes2.encryptKey(
            key, passwordBytes, GostOids.KUZ_CTR_ACPKM_OMAC, TEST_ITER);
        byte[] keyBag = buildKeyBagDer(encryptedKeyBytes, keyLocalKeyId);

        List<byte[]> bagDers = new ArrayList<>();
        bagDers.add(keyBag);
        for (CertBagDef cbd : certBags) {
            bagDers.add(buildCertBagDer(cbd.cert.getCertData(), cbd.localKeyId));
        }

        byte[] safeContents = DerCodec.encodeSequence(
            bagDers.toArray(new byte[0][]));

        byte[] dataContentInfo = DerCodec.encodeSequence(
            DerCodec.encodeOid(GostOids.PKCS7_DATA),
            DerCodec.encodeContextConstructed(0,
                DerCodec.encodeOctetString(safeContents)));

        byte[] authSafe = DerCodec.encodeSequence(dataContentInfo);

        byte[] outerContentInfo = DerCodec.encodeSequence(
            DerCodec.encodeOid(GostOids.PKCS7_DATA),
            DerCodec.encodeContextConstructed(0,
                DerCodec.encodeOctetString(authSafe)));

        byte[] salt = new byte[16];
        CryptoRandom.INSTANCE.nextBytes(salt);
        byte[] macData = GostPkcs12Mac.compute(authSafe, passwordBytes, TEST_ITER, salt);

        return DerCodec.encodeSequence(
            DerCodec.encodeInteger(3),
            outerContentInfo,
            macData);
    }

    private static byte[] buildPfxCertFirst(PrivateKeyParameters key, byte[] keyLocalKeyId,
                                             TlsCertificate cert, byte[] certLocalKeyId) throws Exception {
        byte[] passwordBytes = GostPkcs12Loader.toUtf8Bytes(PASSWORD);

        byte[] encryptedKeyBytes = GostPbes2.encryptKey(
            key, passwordBytes, GostOids.KUZ_CTR_ACPKM_OMAC, TEST_ITER);

        List<byte[]> bagDers = new ArrayList<>();
        bagDers.add(buildCertBagDer(cert.getCertData(), certLocalKeyId));
        bagDers.add(buildKeyBagDer(encryptedKeyBytes, keyLocalKeyId));

        byte[] safeContents = DerCodec.encodeSequence(
            bagDers.toArray(new byte[0][]));

        byte[] dataContentInfo = DerCodec.encodeSequence(
            DerCodec.encodeOid(GostOids.PKCS7_DATA),
            DerCodec.encodeContextConstructed(0,
                DerCodec.encodeOctetString(safeContents)));

        byte[] authSafe = DerCodec.encodeSequence(dataContentInfo);

        byte[] outerContentInfo = DerCodec.encodeSequence(
            DerCodec.encodeOid(GostOids.PKCS7_DATA),
            DerCodec.encodeContextConstructed(0,
                DerCodec.encodeOctetString(authSafe)));

        byte[] salt = new byte[16];
        CryptoRandom.INSTANCE.nextBytes(salt);
        byte[] macData = GostPkcs12Mac.compute(authSafe, passwordBytes, TEST_ITER, salt);

        return DerCodec.encodeSequence(
            DerCodec.encodeInteger(3),
            outerContentInfo,
            macData);
    }

    private static byte[] buildKeyBagDer(byte[] encryptedKeyDer, byte[] localKeyId) {
        byte[] bagValue = DerCodec.encodeContextConstructed(0, encryptedKeyDer);
        if (localKeyId != null) {
            byte[] attr = buildLocalKeyIdAttr(localKeyId);
            byte[] attrs = DerCodec.encodeSet(attr);
            return DerCodec.encodeSequence(
                DerCodec.encodeOid(GostOids.BAG_PKCS8_SHROUDED_KEY),
                bagValue, attrs);
        }
        return DerCodec.encodeSequence(
            DerCodec.encodeOid(GostOids.BAG_PKCS8_SHROUDED_KEY),
            bagValue);
    }

    private static byte[] buildCertBagDer(byte[] certDer, byte[] localKeyId) {
        byte[] certBagContent = DerCodec.encodeSequence(
            DerCodec.encodeOid(GostOids.PKCS9_X509_CERT),
            DerCodec.encodeContextConstructed(0,
                DerCodec.encodeOctetString(certDer)));
        byte[] bagValue = DerCodec.encodeContextConstructed(0, certBagContent);
        if (localKeyId != null) {
            byte[] attr = buildLocalKeyIdAttr(localKeyId);
            byte[] attrs = DerCodec.encodeSet(attr);
            return DerCodec.encodeSequence(
                DerCodec.encodeOid(GostOids.BAG_CERT),
                bagValue, attrs);
        }
        return DerCodec.encodeSequence(
            DerCodec.encodeOid(GostOids.BAG_CERT),
            bagValue);
    }

    private static byte[] buildLocalKeyIdAttr(byte[] keyId) {
        return DerCodec.encodeSequence(
            DerCodec.encodeOid(GostOids.ATTR_LOCAL_KEY_ID),
            DerCodec.encodeSet(DerCodec.encodeOctetString(keyId)));
    }

    private static final class CertBagDef {
        final TlsCertificate cert;
        final byte[] localKeyId;
        CertBagDef(TlsCertificate cert, byte[] localKeyId) {
            this.cert = cert;
            this.localKeyId = localKeyId;
        }
    }
}
