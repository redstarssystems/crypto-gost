package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.GostSigner;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.signature.ECParameters;

@DisplayName("TrustAnchors: сертификаты-якоря и сравнение по DER")
class TrustAnchorsTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();

    @Test
    @DisplayName("Сертификатный якорь сравнивается по полному DER, а не по ключу")
    void testContainsCertificateUsesDerEquality() throws Exception {
        var kp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] dn = GostDnParser.encodeDn("CN=Same Key Root");
        GostCertificate first = selfSigned(kp, dn, BigInteger.ONE, "20240501120000Z");
        GostCertificate sameKeyOtherDer = selfSigned(kp, dn, BigInteger.TWO, "20240501120000Z");

        TrustAnchors anchors = TrustAnchors.ofCertificates(List.of(first));

        assertTrue(anchors.containsCertificate(first), "Тот же самый DER должен быть якорем");
        assertFalse(
                anchors.containsCertificate(sameKeyOtherDer),
                "Сертификат с тем же ключом, но другим DER не должен считаться якорем");
        assertFalse(anchors.containsCertificate(null), "null не должен быть якорем");
    }

    @Test
    @DisplayName(
            "Политика срока якоря: по умолчанию DEFAULT, withExpiryPolicy не меняет исходный набор")
    void testExpiryPolicyIsImmutableProperty() throws Exception {
        var kp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate root =
                selfSigned(
                        kp,
                        GostDnParser.encodeDn("CN=Policy Root"),
                        BigInteger.ONE,
                        "20240501120000Z");
        TrustAnchors original = TrustAnchors.ofCertificate(root);

        TrustAnchors strict = original.withExpiryPolicy(AnchorExpiryPolicy.REJECT);

        assertEquals(
                AnchorExpiryPolicy.DEFAULT,
                original.expiryPolicy(),
                "Исходный набор не должен меняться");
        assertEquals(AnchorExpiryPolicy.REJECT, strict.expiryPolicy());
        assertEquals(
                original.certificates(), strict.certificates(), "Сертификаты должны сохраняться");
        assertEquals(
                AnchorExpiryPolicy.DEFAULT,
                strict.withExpiryPolicy(AnchorExpiryPolicy.DEFAULT).expiryPolicy(),
                "DEFAULT должен работать как сброс");
        assertEquals(AnchorExpiryPolicy.DEFAULT, TrustAnchors.empty().expiryPolicy());
        assertThrows(
                IllegalArgumentException.class,
                () -> original.withExpiryPolicy(null),
                "null вместо политики должен отвергаться");
        assertTrue(
                strict.toString().contains("REJECT"),
                "toString должен показывать политику срока якоря");
    }

    @Test
    @DisplayName("Отпечаток не зависит от порядка якорей, но зависит от состава и политики срока")
    void testFingerprintCanonicalization() throws Exception {
        GostCertificate first = namedRoot("CN=Fingerprint Root 1");
        GostCertificate second = namedRoot("CN=Fingerprint Root 2");

        TrustAnchors ab = TrustAnchors.ofCertificates(List.of(first, second));
        TrustAnchors ba = TrustAnchors.ofCertificates(List.of(second, first));

        assertEquals(32, ab.fingerprint().length, "Отпечаток должен быть Стрибог-256");
        assertArrayEquals(
                ab.fingerprint(), ba.fingerprint(), "Порядок якорей не должен влиять на отпечаток");
        assertFalse(
                Arrays.equals(ab.fingerprint(), TrustAnchors.ofCertificate(first).fingerprint()),
                "Другой состав набора должен давать другой отпечаток");
        assertFalse(
                Arrays.equals(
                        ab.fingerprint(),
                        ab.withExpiryPolicy(AnchorExpiryPolicy.REJECT).fingerprint()),
                "Другая политика срока должна давать другой отпечаток");
        assertArrayEquals(
                ab.fingerprint(),
                ab.withExpiryPolicy(AnchorExpiryPolicy.DEFAULT).fingerprint(),
                "Сброс на DEFAULT должен возвращать тот же отпечаток");
        assertFalse(
                Arrays.equals(ab.fingerprint(), TrustAnchors.empty().fingerprint()),
                "Пустой набор должен отличаться от непустого");
    }

    @Test
    @DisplayName("fingerprint возвращает копию: изменение результата не портит набор")
    void testFingerprintIsDefensiveCopy() throws Exception {
        TrustAnchors anchors = TrustAnchors.ofCertificate(namedRoot("CN=Copy Root"));
        byte[] first = anchors.fingerprint();
        first[0] ^= (byte) 0xFF;

        assertFalse(
                Arrays.equals(first, anchors.fingerprint()),
                "Повторный вызов должен возвращать неискажённый отпечаток");
    }

    @Test
    @DisplayName("Фабрики отклоняют null, пустые списки и null-элементы")
    void testFactoriesRejectInvalidLists() {
        assertThrows(
                IllegalArgumentException.class,
                () -> TrustAnchors.ofCertificates((List<GostCertificate>) null),
                "null-список сертификатов должен быть отклонён");
        assertThrows(
                IllegalArgumentException.class,
                () -> TrustAnchors.ofCertificates(List.of()),
                "пустой список сертификатов должен быть отклонён");
        List<GostCertificate> withNull = new ArrayList<>();
        withNull.add(null);
        assertThrows(
                IllegalArgumentException.class,
                () -> TrustAnchors.ofCertificates(withNull),
                "null-элемент сертификата должен быть отклонён");
        assertThrows(
                IllegalArgumentException.class,
                () -> TrustAnchors.ofCertificate(null),
                "null-сертификат должен быть отклонён");
    }

    @Test
    @DisplayName("Списки якорей защищены от изменения извне")
    void testDefensiveCopies() throws Exception {
        var kp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] dn = GostDnParser.encodeDn("CN=Defensive Root");
        GostCertificate cert = selfSigned(kp, dn, BigInteger.ONE, "20240501120000Z");
        List<GostCertificate> source = new ArrayList<>();
        source.add(cert);

        TrustAnchors anchors = TrustAnchors.ofCertificates(source);
        source.clear();

        assertEquals(1, anchors.certificates().size(), "Исходный список не должен влиять на якоря");
        assertThrows(
                UnsupportedOperationException.class,
                () -> anchors.certificates().clear(),
                "Список сертификатов должен быть неизменяемым");
    }

    @Test
    @DisplayName("Пустой набор якорей: isEmpty и containsCertificate")
    void testEmpty() {
        TrustAnchors empty = TrustAnchors.empty();

        assertTrue(empty.isEmpty(), "empty() должен быть пустым");
        assertTrue(empty.certificates().isEmpty(), "Сертификатов быть не должно");
        assertEquals(
                "TrustAnchors{empty}", empty.toString(), "toString не должен раскрывать данные");
    }

    @Test
    @DisplayName("toString не раскрывает содержимое сертификата")
    void testToStringHasNoCertificateContent() throws Exception {
        var kp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] dn = GostDnParser.encodeDn("CN=ToString Root");
        GostCertificate cert = selfSigned(kp, dn, BigInteger.ONE, "20240501120000Z");

        String certText = TrustAnchors.ofCertificates(List.of(cert)).toString();

        assertEquals("TrustAnchors{certificates=1, expiryPolicy=DEFAULT}", certText);
        assertFalse(certText.contains("30"), "toString не должен содержать DER");
    }

    private static GostCertificate namedRoot(String dn) throws Exception {
        return selfSigned(
                KeyGenerator.generateKeyPair(PARAMS),
                GostDnParser.encodeDn(dn),
                BigInteger.ONE,
                "20240501120000Z");
    }

    private static GostCertificate selfSigned(
            org.rssys.gost.api.KeyPair kp, byte[] dn, BigInteger serial, String notBefore)
            throws Exception {
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
                        .notBefore(notBefore)
                        .notAfter("21060101120000Z")
                        .additionalExtensions(additional)
                        .issuerDn(dn)
                        .serial(serial)
                        .buildTbs();
        return GostCertificateBuilder.sign(tbs, GostSigner.of(kp.getPrivate()));
    }

    private static byte[] concatExtensions(byte[]... exts) {
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
}
