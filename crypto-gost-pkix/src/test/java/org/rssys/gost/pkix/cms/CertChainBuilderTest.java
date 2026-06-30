package org.rssys.gost.pkix.cms;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.pkix.cert.ChainValidator;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCertificateBuilder;
import org.rssys.gost.pkix.cert.GostDnParser;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;

@DisplayName("CertChainBuilder: построение цепочки сертификатов")
class CertChainBuilderTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();

    // ========================================================================
    // Happy path: валидная цепочка leaf -> intermediate -> root
    // ========================================================================

    @Test
    @DisplayName("Валидная цепочка из трёх сертификатов, успешное построение")
    void testHappyPath() throws Exception {
        CertBundle root = createRootCa();
        CertBundle intermediate = createIntermediateCa(root, null);
        CertBundle leaf = createLeaf(intermediate);

        List<GostCertificate> chain =
                CertChainBuilder.buildChain(
                        leaf.cert, List.of(intermediate.cert), List.of(root.cert));

        assertNotNull(chain);
        assertEquals(3, chain.size(), "Цепочка должна содержать 3 сертификата");
        assertEquals(leaf.cert, chain.get(0), "Первый — листовой сертификат");
        assertEquals(intermediate.cert, chain.get(1), "Второй — промежуточный CA");
        assertTrue(chain.get(2).isSelfSigned(), "Последний — самоподписанный корень");
    }

    // ========================================================================
    // INCOMPLETE_CHAIN: issuer не найден ни в pool, ни в trustedRoots
    // ========================================================================

    @Test
    @DisplayName("Issuer не найден -> INCOMPLETE_CHAIN")
    void testIncompleteChain() throws Exception {
        CertBundle trustedRoot = createRootCa();
        // Создаём промежуточный CA, подписанный корнем, но НЕ передаём его в pool.
        // Создаём leaf, подписанный этим промежуточным CA.
        CertBundle missingCA = createIntermediateCa(trustedRoot, null);
        CertBundle orphanLeaf = createLeaf(missingCA);

        // pool пуст, trustedRoots содержит только корень (с другим DN)
        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                CertChainBuilder.buildChain(
                                        orphanLeaf.cert,
                                        Collections.emptyList(),
                                        List.of(trustedRoot.cert)));

        assertEquals(
                PkixException.Reason.INCOMPLETE_CHAIN,
                ex.reason(),
                "Ожидается INCOMPLETE_CHAIN — issuer не найден");
    }

    // ========================================================================
    // CHAIN_LOOP: циклическая цепочка A <- B <- A
    // ========================================================================

    @Test
    @DisplayName("Цикл A <- B <- A -> CHAIN_LOOP")
    void testChainLoop() throws Exception {
        // Генерируем две пары ключей
        var kpA = KeyGenerator.generateKeyPair(PARAMS);
        var kpB = KeyGenerator.generateKeyPair(PARAMS);

        byte[] dnA = GostDnParser.encodeDn("CN=Cert A");
        byte[] dnB = GostDnParser.encodeDn("CN=Cert B");

        byte[] bcExt = GostCertificateBuilder.buildBasicConstraintsExtension(true, null);
        byte[] kuExt =
                GostCertificateBuilder.buildKeyUsageExtension(
                        GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN);

        // Сертификат A: subject=A, issuer=B, подписан ключом B
        byte[] tbsA =
                GostCertificateBuilder.create(PARAMS, dnA)
                        .publicKey(kpA.getPublic())
                        .notBefore("260101000000Z")
                        .notAfter("360101000000Z")
                        .additionalExtensions(concatExtensions(bcExt, kuExt))
                        .issuerDn(dnB)
                        .serial(BigInteger.ONE)
                        .buildTbs();
        GostCertificate certA = GostCertificateBuilder.assembleCert(tbsA, kpB.getPrivate(), PARAMS);

        // Сертификат B: subject=B, issuer=A, подписан ключом A
        byte[] tbsB =
                GostCertificateBuilder.create(PARAMS, dnB)
                        .publicKey(kpB.getPublic())
                        .notBefore("260101000000Z")
                        .notAfter("360101000000Z")
                        .additionalExtensions(concatExtensions(bcExt, kuExt))
                        .issuerDn(dnA)
                        .serial(BigInteger.TWO)
                        .buildTbs();
        GostCertificate certB = GostCertificateBuilder.assembleCert(tbsB, kpA.getPrivate(), PARAMS);

        // Посторонний доверенный корень — любой самоподписанный
        CertBundle trustedRoot = createRootCa();

        // Строим цепочку: leaf=certA, pool=[certA, certB]
        // certA нужен в pool — он же issuer для certB (перекрёстная подпись).
        // certA.issuer=certB -> certB в pool -> certB.issuer=certA -> certA в pool ->
        // certA DN уже в visited -> CHAIN_LOOP
        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                CertChainBuilder.buildChain(
                                        certA, List.of(certA, certB), List.of(trustedRoot.cert)));

        assertEquals(
                PkixException.Reason.CHAIN_LOOP,
                ex.reason(),
                "Ожидается CHAIN_LOOP — циклическая цепочка A->B->A");
    }

    // ========================================================================
    // CHAIN_TOO_LONG: превышение максимальной глубины цепочки
    // ========================================================================

    @Test
    @DisplayName("Цепочка из 10 несамоподписанных сертификатов -> CHAIN_TOO_LONG")
    void testChainTooLong() throws Exception {
        // Создаём корень и 10 несамоподписанных сертификатов:
        // leaf <- int[0] <- int[1] <- ... <- int[8] <- root
        // Каждый int[i] подписан следующим, int[8] подписан корнем.
        // Все int не self-signed (их ключ подписи != собственный pub).
        // После добавления int[8] цепочка содержит leaf + 9 int = 10 сертификатов,
        // и при попытке найти issuer для int[8] (корень) проверка
        // chain.size() >= MAX_CERT_CHAIN_LENGTH (10 >= 10) бросает CHAIN_TOO_LONG.

        CertBundle root = createRootCa();

        int chainLen = CmsConstants.MAX_CERT_CHAIN_LENGTH; // 10
        CertBundle[] intCerts = new CertBundle[chainLen - 1]; // 9 промежуточных

        // Создаём промежуточные сертификаты цепочкой: каждый подписан следующим,
        // последний подписан корнем
        for (int i = chainLen - 2; i >= 0; i--) {
            CertBundle issuer = (i == chainLen - 2) ? root : intCerts[i + 1];
            String cn = "CN=Intermediate " + i;
            intCerts[i] = createIntermediateCa(issuer, null, cn, BigInteger.valueOf(100 + i));
        }

        // leaf подписан int[0]
        CertBundle leaf = createLeaf(intCerts[0], BigInteger.valueOf(200));

        // pool = все промежуточные, trustedRoots = корень
        List<GostCertificate> pool = new java.util.ArrayList<>(chainLen - 1);
        for (CertBundle cb : intCerts) {
            pool.add(cb.cert);
        }

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () -> CertChainBuilder.buildChain(leaf.cert, pool, List.of(root.cert)));

        assertEquals(
                PkixException.Reason.CHAIN_TOO_LONG,
                ex.reason(),
                "Ожидается CHAIN_TOO_LONG — превышение лимита в " + chainLen + " сертификатов");
    }

    // ========================================================================
    // Дополнительная проверка: валидная цепочка проходит ChainValidator
    // ========================================================================

    @Test
    @DisplayName("Построенная цепочка успешно проходит ChainValidator")
    void testBuiltChainPassesValidation() throws Exception {
        CertBundle root = createRootCa();
        CertBundle intermediate = createIntermediateCa(root, null);
        CertBundle leaf = createLeaf(intermediate);

        List<GostCertificate> chain =
                CertChainBuilder.buildChain(
                        leaf.cert, List.of(intermediate.cert), List.of(root.cert));

        List<PublicKeyParameters> caKeys = List.of(root.cert.getPublicKey());
        assertDoesNotThrow(
                () -> ChainValidator.validateChain(chain, caKeys),
                "Построенная цепочка должна проходить PKIX-валидацию");
    }

    // ========================================================================
    // Вспомогательные методы
    // ========================================================================

    private static CertBundle createRootCa() throws Exception {
        var kp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] dn = GostDnParser.encodeDn("CN=Root CA");
        byte[] bc = GostCertificateBuilder.buildBasicConstraintsExtension(true, null);
        byte[] ku =
                GostCertificateBuilder.buildKeyUsageExtension(
                        GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN,
                        GostCertificateBuilder.KeyUsage.CRL_SIGN);
        byte[] ski = GostCertificateBuilder.buildSkiExtension(kp.getPublic());
        byte[] additional = concatExtensions(bc, ku, ski);
        byte[] tbs =
                GostCertificateBuilder.create(PARAMS, dn)
                        .publicKey(kp.getPublic())
                        .notBefore("260101000000Z")
                        .notAfter("360101000000Z")
                        .additionalExtensions(additional)
                        .issuerDn(dn)
                        .serial(BigInteger.ONE)
                        .buildTbs();
        return new CertBundle(
                kp.getPrivate(),
                kp.getPublic(),
                GostCertificateBuilder.assembleCert(tbs, kp.getPrivate(), PARAMS),
                dn);
    }

    private static CertBundle createIntermediateCa(CertBundle issuer, Integer pathLen)
            throws Exception {
        String cn = "CN=Intermediate CA" + (pathLen != null ? " pathLen=" + pathLen : "");
        return createIntermediateCa(issuer, pathLen, cn, BigInteger.ONE);
    }

    private static CertBundle createIntermediateCa(
            CertBundle issuer, Integer pathLen, String cn, BigInteger serial) throws Exception {
        var kp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] subjectDn = GostDnParser.encodeDn(cn);
        byte[] bc = GostCertificateBuilder.buildBasicConstraintsExtension(true, pathLen);
        byte[] ku =
                GostCertificateBuilder.buildKeyUsageExtension(
                        GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN);
        byte[] ski = GostCertificateBuilder.buildSkiExtension(kp.getPublic());
        byte[] aki = GostCertificateBuilder.buildAkiExtension(issuer.pub);
        byte[] additional = concatExtensions(bc, ku, ski, aki);
        byte[] tbs =
                GostCertificateBuilder.create(PARAMS, subjectDn)
                        .publicKey(kp.getPublic())
                        .notBefore("260101000000Z")
                        .notAfter("360101000000Z")
                        .additionalExtensions(additional)
                        .issuerDn(issuer.dn)
                        .serial(serial)
                        .buildTbs();
        return new CertBundle(
                kp.getPrivate(),
                kp.getPublic(),
                GostCertificateBuilder.assembleCert(tbs, issuer.priv, PARAMS),
                subjectDn);
    }

    private static CertBundle createLeaf(CertBundle issuer) throws Exception {
        return createLeaf(issuer, BigInteger.ONE);
    }

    private static CertBundle createLeaf(CertBundle issuer, BigInteger serial) throws Exception {
        var kp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] subjectDn = GostDnParser.encodeDn("CN=Leaf");
        byte[] ku =
                GostCertificateBuilder.buildKeyUsageExtension(
                        GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE);
        byte[] ski = GostCertificateBuilder.buildSkiExtension(kp.getPublic());
        byte[] aki = GostCertificateBuilder.buildAkiExtension(issuer.pub);
        byte[] additional = concatExtensions(ku, ski, aki);
        byte[] tbs =
                GostCertificateBuilder.create(PARAMS, subjectDn)
                        .publicKey(kp.getPublic())
                        .notBefore("260101000000Z")
                        .notAfter("360101000000Z")
                        .additionalExtensions(additional)
                        .issuerDn(issuer.dn)
                        .serial(serial)
                        .buildTbs();
        return new CertBundle(
                kp.getPrivate(),
                kp.getPublic(),
                GostCertificateBuilder.assembleCert(tbs, issuer.priv, PARAMS),
                subjectDn);
    }

    private static byte[] concatExtensions(byte[]... exts) {
        if (exts.length == 0) return null;
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        try {
            for (byte[] ext : exts) {
                out.write(ext);
            }
        } catch (java.io.IOException e) {
            throw new RuntimeException(e);
        }
        return out.toByteArray();
    }

    private static class CertBundle {
        final PrivateKeyParameters priv;
        final PublicKeyParameters pub;
        final GostCertificate cert;
        final byte[] dn;

        CertBundle(
                PrivateKeyParameters priv,
                PublicKeyParameters pub,
                GostCertificate cert,
                byte[] dn) {
            this.priv = priv;
            this.pub = pub;
            this.cert = cert;
            this.dn = dn;
        }
    }
}
