package org.rssys.gost.crossval.cms;

import java.io.*;
import java.math.BigInteger;
import java.nio.file.*;
import java.util.Arrays;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIf;
import org.rssys.gost.api.*;
import org.rssys.gost.crossval.util.CrossValUtils;
import org.rssys.gost.crossval.util.OpenSslChecker;
import org.rssys.gost.crossval.util.TempDirUtils;
import org.rssys.gost.jca.spec.GostCurves;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCertificateBuilder;
import org.rssys.gost.pkix.cms.*;
import org.rssys.gost.signature.*;
import org.rssys.gost.util.DerCodec;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("CMS кросс-валидация — диагностика")
class CmsCrossValidationTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static Path tmp;
    private static PrivateKeyParameters privKey;
    private static PublicKeyParameters pubKey;
    private static GostCertificate cert;

    @BeforeAll
    static void setUp() throws Exception {
        java.security.Security.insertProviderAt(new org.rssys.gost.jca.RssysGostProvider(), 1);
        tmp = Files.createTempDirectory("cms-diag");
        var kp = KeyGenerator.generateKeyPair(PARAMS);
        privKey = kp.getPrivate();
        pubKey = kp.getPublic();
        cert = makeCert(kp.getPrivate(), pubKey);
        Files.write(tmp.resolve("cert.der"), cert.getEncoded());
    }

    @Test
    @EnabledIf("opensslAvailable")
    @DisplayName("Полная диагностика SignedData")
    void fullDiagnostics() throws Exception {
        byte[] data = "diag".getBytes();

        byte[] signed = CmsSignedDataBuilder.create()
                .data(data).addSigner(privKey, cert).build();
        Files.write(tmp.resolve("s.p7s"), signed);

        VerifiedSignedData vr = CmsSignedDataVerifier.verifyAny(signed, cert);
        System.out.println("Self-verify via CmsSignedDataVerifier: passed");

        String asn1 = run(opensslBinary(), "asn1parse", "-in", tmp.resolve("s.p7s").toString(), "-inform", "DER");
        String[] asnLines = asn1.split("\n");
        System.out.println("\n=== ASN.1 SignerInfo секция ===");
        boolean inSi = false;
        for (String l : asnLines) {
            if (l.contains("d=3  hl=3") && l.contains("SET")) inSi = true;
            if (inSi) System.out.println(l);
        }
        System.out.println("=== конец ASN.1 ===");

        String vout = run(opensslBinary(), "cms", "-verify",
                "-in", tmp.resolve("s.p7s").toString(),
                "-inform", "DER", "-noverify", "-nosmimecap",
                "-md", "md_gost12_256",
                "-certfile", tmp.resolve("cert.der").toString(),
                "-out", tmp.resolve("out.txt").toString());
        System.out.println("\nOpenSSL verify: " + vout);

        if (cryptcpAvailable()) {
            Files.write(tmp.resolve("cp-data.bin"), data);
            run(cryptcpBinary(), "-instcert", "-f", tmp.resolve("cert.der").toString());
            String cpOut = run(cryptcpBinary(), "-verify", "-nochain",
                    "-f", tmp.resolve("s.p7s").toString(),
                    tmp.resolve("cp-data.bin").toString());
            System.out.println("cryptcp verify: " + cpOut);
        }

        // verify() throws PkixException on failure — no explicit assertion needed
    }

    @Test
    @EnabledIf("opensslAvailable")
    @DisplayName("EnvelopedData: структурная целостность DER и диагностика (openssl не поддерживает GOST EnvelopedData)")
    void envelopedDataDiagnostics() throws Exception {
        byte[] data = "CMS EnvelopedData structural test".getBytes();

        CmsKeyWrap keyWrap = new Kexp15CmsKeyWrap();
        byte[] encrypted = CmsEnvelopedDataBuilder.create()
                .data(data)
                .addRecipient(cert)
                .keyWrap(keyWrap)
                .build();
        Files.write(tmp.resolve("enc_lib.der"), encrypted);

        String asn1 = run(opensslBinary(), "asn1parse", "-in",
                tmp.resolve("enc_lib.der").toString(), "-inform", "DER");
        System.out.println("\n=== ASN.1 EnvelopedData ===");
        System.out.println(asn1);
        assertTrue(asn1.contains("kuznyechik-ctr-acpkm"),
                "ASN.1 должен содержать OID kuznyechik-ctr-acpkm");
        assertTrue(asn1.contains("kuznyechik-kexp15"),
                "ASN.1 должен содержать OID KExp15 key wrap");

        CmsContentInfo ci = CmsContentInfo.decode(encrypted);
        byte[][] envParts = DerCodec.parseSequenceContents(ci.content(), 0);
        byte[][] eciParts = DerCodec.parseSequenceContents(envParts[2], 0);
        byte[][] algParts = DerCodec.parseSequenceContents(eciParts[1], 0);
        assertEquals(DerCodec.TAG_SEQUENCE, algParts[1][0] & 0xFF,
                "Параметры контентного шифра должны быть SEQUENCE (RFC 9337 §7.3)");

        byte[] decrypted = CmsEnvelopedDataDecryptor.decrypt(encrypted, privKey, cert, keyWrap);
        assertArrayEquals(data, decrypted, "Roundtrip шифрование/расшифровка");

        System.out.println("EnvelopedData структурная проверка: OK");
        System.out.println("Примечание: openssl cms -decrypt не поддерживает GOST KeyAgreeRecipientInfo");
        System.out.println("Примечание: КриптоПРО использует KeyTransRecipientInfo (ГОСТ 28147-89, RFC 4490 §5),");
        System.out.println("библиотека — KeyAgreeRecipientInfo (RFC 5652 §6.2.2, VKO + KExp15):");
        System.out.println("совместимость на уровне RecipientInfo отсутствует");
    }

    @Test
    @EnabledIf("opensslAvailable")
    @DisplayName("SignedData L1+L2: asn1parse + библиотечная верификация (L3 openssl cms заблокирован ограничением OpenSSL 3.6.0-gost)")
    void testSignedDataL3Verify() throws Exception {
        TempDirUtils.withTempDir("cms-l3-", dir -> {
            CertPair pair = generateCaAndLeaf();
            byte[] data = "CMS SignedData L3 test data".getBytes();

            byte[] signedDer = CmsSignedDataBuilder.create()
                    .data(data)
                    .addSigner(pair.leafKey(), pair.leafCert())
                    .build();
            Path signedPath = dir.resolve("signed.der");
            Files.write(signedPath, signedDer);

            Path caPath = dir.resolve("ca.der");
            Files.write(caPath, pair.caCert().getEncoded());

            // L1: структурная валидация через asn1parse (без engine-флагов)
            String[] asn1Cmd = new String[] {
                    OpenSslChecker.resolveOpenSslBinary(), "asn1parse",
                    "-inform", "DER", "-in", signedPath.toString() };
            int asn1Exit = OpenSslChecker.run(asn1Cmd);
            assertEquals(0, asn1Exit, "openssl asn1parse SignedData должен пройти");

            // L2: библиотечная верификация
            VerifiedSignedData vr = CmsSignedDataVerifier.verifyAny(signedDer, pair.caCert());
            assertNotNull(vr, "Библиотечная верификация SignedData не должна вернуть null");

            // Примечание: openssl cms -verify c -CAfile не поддерживает
            // ГОСТ-подписи в OpenSSL 3.6.0-gost.
            // Полноценная L3 cross-val будет возможна после добавления
            // поддержки ГОСТ в CMS-модуль OpenSSL.
            // Альтернативно — raw-верификация через openssl dgst -verify
            // (см. x-validation-tests/sign).

            return null;
        });
    }

    @Test
    @EnabledIf("opensslAvailable")
    @DisplayName("SignedData detached: asn1parse + библиотечная верификация")
    void testSignedDataDetachedVerify() throws Exception {
        TempDirUtils.withTempDir("cms-det-", dir -> {
            CertPair pair = generateCaAndLeaf();
            byte[] data = "CMS detached SignedData L3 test data".getBytes();

            byte[] signedDer = CmsSignedDataBuilder.create()
                    .data(data)
                    .detached(true)
                    .addSigner(pair.leafKey(), pair.leafCert())
                    .build();
            Path signedPath = dir.resolve("signed.der");
            Files.write(signedPath, signedDer);

            // L1: структурная валидация (asn1parse, без engine-флагов)
            String[] asn1Cmd = new String[] {
                    OpenSslChecker.resolveOpenSslBinary(), "asn1parse",
                    "-inform", "DER", "-in", signedPath.toString() };
            int asn1Exit = OpenSslChecker.run(asn1Cmd);
            assertEquals(0, asn1Exit, "openssl asn1parse detached SignedData должен пройти");

            // L2: библиотечная верификация
            VerifiedSignedData vr = CmsSignedDataVerifier.verifyAny(signedDer, pair.caCert());
            assertNotNull(vr, "Библиотечная верификация detached SignedData не должна вернуть null");

            return null;
        });
    }

    /**
     * Генерирует self-signed CA + подписанный CA leaf сертификат через {@link GostCertificateBuilder}
     * (GeneralizedTime).
     */
    private static CertPair generateCaAndLeaf() {
        var caKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate caCert = GostCertificateBuilder.create(PARAMS, "CN=Test CA,O=Test Org,C=RU")
                .publicKey(caKp.getPublic())
                .notBefore("20250101000000Z")
                .notAfter("21250101000000Z")
                .keyUsage(GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN,
                        GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                .basicConstraints(true, null)
                .assembleCert(caKp.getPrivate());

        var leafKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate leafCert = GostCertificateBuilder.create(PARAMS, "CN=Test Leaf,O=Test Org,C=RU")
                .publicKey(leafKp.getPublic())
                .issuerDn(caCert.getSubjectDnBytes())
                .notBefore("20250101000000Z")
                .notAfter("20300101000000Z")
                .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                .assembleCert(caKp.getPrivate());

        return new CertPair(caCert, leafKp.getPrivate(), leafCert);
    }

    private record CertPair(GostCertificate caCert, PrivateKeyParameters leafKey, GostCertificate leafCert) {}

    static boolean opensslAvailable() { return Files.exists(Path.of(opensslBinary())); }
    static boolean cryptcpAvailable() { return Files.exists(Path.of(cryptcpBinary())); }
    static String opensslBinary() { return System.getProperty("openssl.binary", "/opt/openssl-3.6.0-gost/bin/openssl"); }
    static String cryptcpBinary() { return System.getProperty("cryptcp.binary", "/opt/cprocsp/bin/amd64/cryptcp"); }

    static String run(String... cmd) throws Exception {
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        String o = new String(p.getInputStream().readAllBytes()); p.waitFor(); return o;
    }

    static String hex(byte[] b, int max) {
        StringBuilder s = new StringBuilder(); int n = Math.min(b.length, max);
        for (int i = 0; i < n; i++) s.append(String.format("%02X", b[i] & 0xFF));
        if (b.length > max) s.append("...");
        return s.toString();
    }

    static byte[][] parseAttrs(byte[] data) {
        java.util.ArrayList<byte[]> l = new java.util.ArrayList<>();
        int pos = 0;
        while (pos < data.length) {
            int[] cl = DerCodec.decodeLength(data, pos + 1);
            int t = 1 + cl[1] + cl[0];
            l.add(Arrays.copyOfRange(data, pos, pos + t));
            pos += t;
        }
        return l.toArray(new byte[0][]);
    }

    static byte[][] parseSet(byte[] data) {
        if ((data[0] & 0xFF) != DerCodec.TAG_SET) throw new IllegalArgumentException("Not a SET");
        int[] sl = DerCodec.decodeLength(data, 1);
        int start = 1 + sl[1], end = start + sl[0];
        java.util.ArrayList<byte[]> l = new java.util.ArrayList<>();
        int pos = start;
        while (pos < end) {
            int[] cl = DerCodec.decodeLength(data, pos + 1);
            int t = 1 + cl[1] + cl[0];
            l.add(Arrays.copyOfRange(data, pos, pos + t));
            pos += t;
        }
        return l.toArray(new byte[0][]);
    }

    /**
     * Создаёт самоподписанный сертификат. Дублирует логику
     * {@code org.rssys.gost.pkix.cms.CmsTestUtils.createSelfSignedCert} —
     * этот модуль не зависит от crypto-gost-pkix:test-jar.
     */
    static GostCertificate makeCert(PrivateKeyParameters pk, PublicKeyParameters pub) throws Exception {
        byte[] spki = org.rssys.gost.jca.spec.GostDerCodec.encodePublicKey(pub);
        byte[] dn = buildDn("Test");
        byte[] ver = DerCodec.encodeContextConstructed(0, DerCodec.encodeInteger(2));
        byte[] sn = DerCodec.encodeInteger(BigInteger.valueOf(System.currentTimeMillis()));
        byte[] alg = CmsAlgorithmIdentifier.encode(GostOids.SIGN_ALG_256);
        byte[] nb = DerCodec.encodeTlv(DerCodec.TAG_UTC_TIME, "260101000000Z".getBytes());
        byte[] na = DerCodec.encodeTlv(DerCodec.TAG_UTC_TIME, "360101000000Z".getBytes());
        byte[] tbs = DerCodec.encodeSequence(ver, sn, alg, dn, DerCodec.encodeSequence(nb, na), dn.clone(), spki);
        byte[] h = Digest.digest256(tbs);
        byte[] sig = org.rssys.gost.util.DerCodec.encodeBitString(Signature.signHash(h, pk));
        byte[] der = DerCodec.encodeSequence(tbs, alg, sig);
        return GostCertificate.fromDer(der);
    }

    /**
     * Минимальный DN. Дублирует {@code org.rssys.gost.pkix.cms.CmsTestUtils.buildDn}.
     */
    static byte[] buildDn(String cn) {
        return DerCodec.encodeSequence(DerCodec.encodeSet(DerCodec.encodeSequence(
                DerCodec.encodeOid(GostOids.ATTR_CN), DerCodec.encodePrintableString(cn))));
    }
}
