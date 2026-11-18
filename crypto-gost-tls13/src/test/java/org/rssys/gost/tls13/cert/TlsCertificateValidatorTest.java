package org.rssys.gost.tls13.cert;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.AnchorExpiryPolicy;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.PkixCertTestHelper.CertBundle;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;

@DisplayName("TlsCertificateValidator: якоря-сертификаты")
class TlsCertificateValidatorTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static final byte[] KU_DIGITAL_SIGNATURE = {(byte) 0x80};
    private static final byte[] KU_KEY_CERT_SIGN = {(byte) 0x04};
    private static final String[] EKU_SERVER_AUTH = {GostOids.EXT_SERVER_AUTH};
    private static final String[] EKU_CLIENT_AUTH = {GostOids.EXT_CLIENT_AUTH};
    private static final String NOT_BEFORE = "20250101000000Z";
    private static final String NOT_AFTER = "21010101000000Z";

    @Test
    @DisplayName("cert-якорь: NameConstraints корня применяются при опущенном корне")
    void testServerChainWithCertificateAnchorNameConstraints() throws Exception {
        CertBundle root =
                PkixCertTestHelper.createRootCAWithNameConstraints(
                        PARAMS, new String[] {"example.com"}, null);
        CertBundle intermediate = createIntermediate(root);
        TrustAnchors anchors = TrustAnchors.ofCertificates(List.of(root.cert));
        CertBundle goodLeaf = createServerLeaf(intermediate, "host.example.com");
        CertBundle evilLeaf = createServerLeaf(intermediate, "bank.ru");

        assertDoesNotThrow(
                () ->
                        TlsCertificateValidator.validate(
                                List.of(goodLeaf.cert, intermediate.cert),
                                TlsPeerPolicy.server("host.example.com", anchors)));

        TlsException ex =
                assertThrows(
                        TlsException.class,
                        () ->
                                TlsCertificateValidator.validate(
                                        List.of(evilLeaf.cert, intermediate.cert),
                                        TlsPeerPolicy.server("bank.ru", anchors)));
        assertEquals(TlsConstants.ALERT_BAD_CERTIFICATE, ex.getAlertCode());
    }

    @Test
    @DisplayName("Закреплённый leaf: срок, hostname и EKU всё равно проверяются")
    void testPinnedLeafStillValidated() throws Exception {
        CertBundle root = PkixCertTestHelper.createRootCA(PARAMS);
        CertBundle goodPinned = createServerLeaf(root, "host.example.com");
        TrustAnchors goodAnchors = TrustAnchors.ofCertificates(List.of(goodPinned.cert));

        assertDoesNotThrow(
                () ->
                        TlsCertificateValidator.validate(
                                List.of(goodPinned.cert),
                                TlsPeerPolicy.server("host.example.com", goodAnchors)));

        assertThrows(
                TlsException.class,
                () ->
                        TlsCertificateValidator.validate(
                                List.of(goodPinned.cert),
                                TlsPeerPolicy.server("other.example.com", goodAnchors)));

        CertBundle expired =
                PkixCertTestHelper.createCertSignedBy(
                        PARAMS,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "20200101000000Z",
                        "20210101000000Z",
                        new String[] {"host.example.com"},
                        null,
                        KU_DIGITAL_SIGNATURE,
                        EKU_SERVER_AUTH,
                        false,
                        null);
        TrustAnchors expiredAnchors = TrustAnchors.ofCertificates(List.of(expired.cert));
        TlsException expiredEx =
                assertThrows(
                        TlsException.class,
                        () ->
                                TlsCertificateValidator.validate(
                                        List.of(expired.cert),
                                        TlsPeerPolicy.server("host.example.com", expiredAnchors)));
        assertEquals(TlsConstants.ALERT_CERTIFICATE_EXPIRED, expiredEx.getAlertCode());

        CertBundle wrongEku =
                PkixCertTestHelper.createCertSignedBy(
                        PARAMS,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        NOT_BEFORE,
                        NOT_AFTER,
                        new String[] {"host.example.com"},
                        null,
                        KU_DIGITAL_SIGNATURE,
                        EKU_CLIENT_AUTH,
                        false,
                        null);
        TrustAnchors wrongEkuAnchors = TrustAnchors.ofCertificates(List.of(wrongEku.cert));
        assertThrows(
                TlsException.class,
                () ->
                        TlsCertificateValidator.validate(
                                List.of(wrongEku.cert),
                                TlsPeerPolicy.server("host.example.com", wrongEkuAnchors)));
    }

    @Test
    @DisplayName("cert-якорь: excluded dNSName не обходится wildcard-SAN")
    void testExcludedDnsWildcardSanRejected() throws Exception {
        CertBundle root =
                PkixCertTestHelper.createRootCAWithNameConstraints(
                        PARAMS, null, new String[] {"pay.example.com"});
        CertBundle intermediate = createIntermediate(root);
        CertBundle leaf = createServerLeaf(intermediate, "*.example.com");
        TrustAnchors anchors = TrustAnchors.ofCertificates(List.of(root.cert));

        TlsException ex =
                assertThrows(
                        TlsException.class,
                        () ->
                                TlsCertificateValidator.validate(
                                        List.of(leaf.cert, intermediate.cert),
                                        TlsPeerPolicy.server("pay.example.com", anchors)));
        assertEquals(TlsConstants.ALERT_BAD_CERTIFICATE, ex.getAlertCode());
    }

    @Test
    @DisplayName("Resolved-цепочка: 10 peer + локальный якорь допустимы, 11 peer отклоняются")
    void testPeerLimitExcludesAppendedAnchor() throws Exception {
        CertBundle root = PkixCertTestHelper.createRootCA(PARAMS);
        TrustAnchors anchors = TrustAnchors.ofCertificates(List.of(root.cert));

        List<GostCertificate> tenPeer = createPeerChain(root, 9, "host.example.com");
        assertEquals(10, tenPeer.size());
        assertDoesNotThrow(
                () ->
                        TlsCertificateValidator.validate(
                                tenPeer, TlsPeerPolicy.server("host.example.com", anchors)));

        List<GostCertificate> elevenPeer = createPeerChain(root, 10, "host.example.com");
        assertEquals(11, elevenPeer.size());
        TlsException ex =
                assertThrows(
                        TlsException.class,
                        () ->
                                TlsCertificateValidator.validate(
                                        elevenPeer,
                                        TlsPeerPolicy.server("host.example.com", anchors)));
        assertEquals(TlsConstants.ALERT_BAD_CERTIFICATE, ex.getAlertCode());
    }

    private static List<GostCertificate> createPeerChain(
            CertBundle root, int intermediateCount, String dnsName) throws Exception {
        CertBundle current = root;
        List<CertBundle> intermediates = new ArrayList<>();
        for (int i = 0; i < intermediateCount; i++) {
            current = createIntermediate(current);
            intermediates.add(current);
        }
        CertBundle leaf = createServerLeaf(current, dnsName);
        List<GostCertificate> chain = new ArrayList<>();
        chain.add(leaf.cert);
        for (int i = intermediates.size() - 1; i >= 0; i--) {
            chain.add(intermediates.get(i).cert);
        }
        return chain;
    }

    @Test
    @DisplayName(
            "Staple сервера без издателя: необязательный OCSP — принимать, обязательный — отказ")
    void testServerStapleWithoutIssuer() throws Exception {
        CertBundle root = PkixCertTestHelper.createRootCA(PARAMS);
        CertBundle leaf = createServerLeaf(root, "host.example.com");
        leaf.cert.setOcspResponse(PkixCertTestHelper.buildDummyOcspResponse());

        assertDoesNotThrow(
                () ->
                        TlsCertificateValidator.validateLeafOnly(
                                List.of(leaf.cert),
                                TlsPeerPolicy.serverLeafOnly("host.example.com")),
                "staple без издателя при необязательном OCSP игнорируется с WARNING");

        TlsException ex =
                assertThrows(
                        TlsException.class,
                        () ->
                                TlsCertificateValidator.validateLeafOnly(
                                        List.of(leaf.cert),
                                        TlsPeerPolicy.serverLeafOnly("host.example.com")
                                                .requireOcspStaple(true)),
                        "обязательный OCSP без издателя должен отклоняться");
        assertEquals(TlsConstants.ALERT_BAD_CERTIFICATE, ex.getAlertCode());
    }

    @Test
    @DisplayName(
            "Staple клиента без издателя: необязательный OCSP — принимать, обязательный — отказ")
    void testClientStapleWithoutIssuer() throws Exception {
        CertBundle root = PkixCertTestHelper.createRootCA(PARAMS);
        CertBundle leaf = createClientLeaf(root);
        leaf.cert.setOcspResponse(PkixCertTestHelper.buildDummyOcspResponse());

        assertDoesNotThrow(
                () ->
                        TlsCertificateValidator.validateLeafOnly(
                                List.of(leaf.cert), TlsPeerPolicy.clientLeafOnly()),
                "staple без издателя при необязательном OCSP игнорируется с WARNING");

        TlsException ex =
                assertThrows(
                        TlsException.class,
                        () ->
                                TlsCertificateValidator.validateLeafOnly(
                                        List.of(leaf.cert),
                                        TlsPeerPolicy.clientLeafOnly().requireOcspStaple(true)),
                        "обязательный OCSP без издателя должен отклоняться");
        assertEquals(TlsConstants.ALERT_BAD_CERTIFICATE, ex.getAlertCode());
    }

    @Test
    @DisplayName("Битый staple при наличии издателя отклоняется для сервера и клиента")
    void testBadStapleWithIssuerRejected() throws Exception {
        CertBundle root = PkixCertTestHelper.createRootCA(PARAMS);
        CertBundle serverLeaf = createServerLeaf(root, "host.example.com");
        serverLeaf.cert.setOcspResponse(PkixCertTestHelper.buildDummyOcspResponse());
        CertBundle clientLeaf = createClientLeaf(root);
        clientLeaf.cert.setOcspResponse(PkixCertTestHelper.buildDummyOcspResponse());

        assertThrows(
                TlsException.class,
                () ->
                        TlsCertificateValidator.validateRevocation(
                                List.of(serverLeaf.cert, root.cert),
                                TlsPeerPolicy.serverLeafOnlyWithoutHostnameVerification()),
                "невалидный staple сервера должен отклоняться");
        assertThrows(
                TlsException.class,
                () ->
                        TlsCertificateValidator.validateRevocation(
                                List.of(clientLeaf.cert, root.cert),
                                TlsPeerPolicy.clientLeafOnly()),
                "невалидный staple клиента должен отклоняться");
    }

    @Test
    @DisplayName("Сервер: staple промежуточного CA в полной цепочке проверяется")
    void testServerIntermediateStapleFullChain() throws Exception {
        CertBundle root = PkixCertTestHelper.createRootCA(PARAMS);
        CertBundle intermediate = createIntermediate(root);
        CertBundle leaf = createServerLeaf(intermediate, "host.example.com");
        intermediate.cert.setOcspResponse(validStaple(intermediate, root));

        List<GostCertificate> chain = List.of(leaf.cert, intermediate.cert, root.cert);
        assertDoesNotThrow(
                () ->
                        TlsCertificateValidator.validateRevocation(
                                chain, TlsPeerPolicy.serverLeafOnlyWithoutHostnameVerification()));

        intermediate.cert.setOcspResponse(PkixCertTestHelper.buildDummyOcspResponse());
        TlsException ex =
                assertThrows(
                        TlsException.class,
                        () ->
                                TlsCertificateValidator.validateRevocation(
                                        chain,
                                        TlsPeerPolicy.serverLeafOnlyWithoutHostnameVerification()));
        assertEquals(TlsConstants.ALERT_BAD_CERTIFICATE, ex.getAlertCode());
    }

    @Test
    @DisplayName("Сервер: издатель промежуточного берётся из локального якоря")
    void testServerIntermediateStapleIssuerFromAnchor() throws Exception {
        CertBundle root = PkixCertTestHelper.createRootCA(PARAMS);
        CertBundle intermediate = createIntermediate(root);
        CertBundle leaf = createServerLeaf(intermediate, "host.example.com");
        intermediate.cert.setOcspResponse(validStaple(intermediate, root));

        TrustAnchors anchors = TrustAnchors.ofCertificates(List.of(root.cert));
        List<GostCertificate> effective =
                TlsCertificateValidator.validateStructure(
                        List.of(leaf.cert, intermediate.cert),
                        TlsPeerPolicy.server("host.example.com", anchors));
        assertEquals(3, effective.size(), "эффективная цепочка должна включать локальный якорь");

        assertDoesNotThrow(
                () ->
                        TlsCertificateValidator.validateRevocation(
                                effective,
                                TlsPeerPolicy.serverLeafOnlyWithoutHostnameVerification()));

        intermediate.cert.setOcspResponse(PkixCertTestHelper.buildDummyOcspResponse());
        TlsException ex =
                assertThrows(
                        TlsException.class,
                        () ->
                                TlsCertificateValidator.validateRevocation(
                                        effective,
                                        TlsPeerPolicy.serverLeafOnlyWithoutHostnameVerification()));
        assertEquals(TlsConstants.ALERT_BAD_CERTIFICATE, ex.getAlertCode());
    }

    @Test
    @DisplayName("Клиент: staple промежуточного CA проверяется по локальному якорю")
    void testClientIntermediateStapleIssuerFromAnchor() throws Exception {
        CertBundle root = PkixCertTestHelper.createRootCA(PARAMS);
        CertBundle intermediate = createIntermediate(root);
        CertBundle leaf = createClientLeaf(intermediate);
        intermediate.cert.setOcspResponse(validStaple(intermediate, root));

        TrustAnchors anchors = TrustAnchors.ofCertificates(List.of(root.cert));
        List<GostCertificate> effective =
                TlsCertificateValidator.validateStructure(
                        List.of(leaf.cert, intermediate.cert), TlsPeerPolicy.client(anchors));

        assertDoesNotThrow(
                () ->
                        TlsCertificateValidator.validateRevocation(
                                effective, TlsPeerPolicy.clientLeafOnly()));

        intermediate.cert.setOcspResponse(PkixCertTestHelper.buildDummyOcspResponse());
        TlsException ex =
                assertThrows(
                        TlsException.class,
                        () ->
                                TlsCertificateValidator.validateRevocation(
                                        effective, TlsPeerPolicy.clientLeafOnly()));
        assertEquals(TlsConstants.ALERT_BAD_CERTIFICATE, ex.getAlertCode());
    }

    private static byte[] validStaple(CertBundle target, CertBundle issuer) throws Exception {
        return PkixCertTestHelper.buildOcspResponse(
                target.cert.getSerialNumber(),
                issuer.priv,
                issuer.cert.getPublicKey(),
                issuer.subjectDn);
    }

    @Test
    @DisplayName("Закреплённый истёкший промежуточный CA: по умолчанию принят, REJECT отклоняет")
    void testExpiredPinnedIntermediateFollowsAnchorExpiryPolicy() throws Exception {
        CertBundle root = PkixCertTestHelper.createRootCA(PARAMS);
        CertBundle expiredIntermediate =
                PkixCertTestHelper.createCertSignedBy(
                        PARAMS,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "20200101000000Z",
                        "20210101000000Z",
                        null,
                        null,
                        KU_KEY_CERT_SIGN,
                        null,
                        true,
                        null);
        CertBundle leaf = createServerLeaf(expiredIntermediate, "host.example.com");
        List<GostCertificate> chain = List.of(leaf.cert, expiredIntermediate.cert);
        TrustAnchors defaultAnchors = TrustAnchors.ofCertificate(expiredIntermediate.cert);
        TrustAnchors strictAnchors = defaultAnchors.withExpiryPolicy(AnchorExpiryPolicy.REJECT);

        assertDoesNotThrow(
                () ->
                        TlsCertificateValidator.validate(
                                chain, TlsPeerPolicy.server("host.example.com", defaultAnchors)),
                "По умолчанию (DEFAULT = WARN) истёкший якорь не блокирует соединение");
        TlsException ex =
                assertThrows(
                        TlsException.class,
                        () ->
                                TlsCertificateValidator.validate(
                                        chain,
                                        TlsPeerPolicy.server("host.example.com", strictAnchors)),
                        "Явный REJECT должен отклонять истёкший якорь");
        assertEquals(TlsConstants.ALERT_CERTIFICATE_EXPIRED, ex.getAlertCode());
    }

    private static CertBundle createIntermediate(CertBundle issuer) throws Exception {
        return PkixCertTestHelper.createCertSignedBy(
                PARAMS,
                issuer.priv,
                issuer.cert.getPublicKey(),
                issuer.subjectDn,
                NOT_BEFORE,
                NOT_AFTER,
                null,
                null,
                KU_KEY_CERT_SIGN,
                null,
                true,
                null);
    }

    private static CertBundle createServerLeaf(CertBundle issuer, String dnsName) throws Exception {
        return PkixCertTestHelper.createCertSignedBy(
                PARAMS,
                issuer.priv,
                issuer.cert.getPublicKey(),
                issuer.subjectDn,
                NOT_BEFORE,
                NOT_AFTER,
                new String[] {dnsName},
                null,
                KU_DIGITAL_SIGNATURE,
                EKU_SERVER_AUTH,
                false,
                null);
    }

    private static CertBundle createClientLeaf(CertBundle issuer) throws Exception {
        return PkixCertTestHelper.createCertSignedBy(
                PARAMS,
                issuer.priv,
                issuer.cert.getPublicKey(),
                issuer.subjectDn,
                NOT_BEFORE,
                NOT_AFTER,
                null,
                null,
                KU_DIGITAL_SIGNATURE,
                EKU_CLIENT_AUTH,
                false,
                null);
    }
}
