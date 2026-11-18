package org.rssys.gost.tls13.cert;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
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
import org.rssys.gost.tls13.TlsException;

@DisplayName("PeerTrustBoundary: граница доверия по сроку сертификатов цепочки")
class PeerTrustBoundaryTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static final byte[] KU_DIGITAL_SIGNATURE = {(byte) 0x80};
    private static final byte[] KU_KEY_CERT_SIGN = {(byte) 0x04};
    private static final String[] EKU_SERVER_AUTH = {GostOids.EXT_SERVER_AUTH};
    private static final String HOST = "host.example.com";
    private static final String NOT_BEFORE = "20250101000000Z";
    private static final String ROOT_NOT_AFTER = "20990101000000Z";
    private static final String INTERMEDIATE_NOT_AFTER = "20900101000000Z";
    private static final String LEAF_NOT_AFTER = "20950101000000Z";

    @Test
    @DisplayName("Промежуточный CA истекает раньше leaf: граница равна его notAfter")
    void intermediateExpiringBeforeLeafLowersBoundary() throws Exception {
        Chain c = new Chain(INTERMEDIATE_NOT_AFTER, LEAF_NOT_AFTER);
        List<GostCertificate> effective = c.validated(AnchorExpiryPolicy.DEFAULT);

        List<GostCertificate> boundary = PeerTrustBoundary.boundaryChain(effective, c.anchors);

        assertEquals(
                notAfterMillis(c.intermediate.cert),
                PeerTrustBoundary.validUntil(boundary),
                "граница должна равняться notAfter промежуточного сертификата");
    }

    @Test
    @DisplayName("Leaf истекает раньше промежуточного CA: граница равна notAfter leaf")
    void leafExpiringFirstDefinesBoundary() throws Exception {
        // leaf (2090) истекает раньше промежуточного CA (2095)
        Chain c = new Chain(LEAF_NOT_AFTER, INTERMEDIATE_NOT_AFTER);
        List<GostCertificate> effective = c.validated(AnchorExpiryPolicy.DEFAULT);

        long boundary =
                PeerTrustBoundary.validUntil(PeerTrustBoundary.boundaryChain(effective, c.anchors));

        assertEquals(
                notAfterMillis(c.leaf.cert), boundary, "граница должна равняться notAfter leaf");
    }

    @Test
    @DisplayName("Корень-якорь, срок которого валидатор игнорирует, в границу не входит")
    void toleratedAnchorIsExcluded() throws Exception {
        Chain c = new Chain(INTERMEDIATE_NOT_AFTER, LEAF_NOT_AFTER);
        List<GostCertificate> effective = c.validated(AnchorExpiryPolicy.DEFAULT);

        List<GostCertificate> boundary = PeerTrustBoundary.boundaryChain(effective, c.anchors);

        assertEquals(
                effective.size() - 1,
                boundary.size(),
                "локальный якорь должен быть исключён из цепочки границы");
        assertEquals(
                effective.subList(0, effective.size() - 1),
                boundary,
                "остальные сертификаты должны остаться в прежнем порядке");
    }

    @Test
    @DisplayName("Истёкший закреплённый промежуточный CA при DEFAULT границу не снижает")
    void expiredPinnedAnchorUnderWarnDoesNotLowerBoundary() throws Exception {
        CertBundle root = PkixCertTestHelper.createRootCA(PARAMS);
        CertBundle expiredIntermediate = caSignedBy(root, "20200101000000Z", "20210101000000Z");
        CertBundle leaf = leafSignedBy(expiredIntermediate, LEAF_NOT_AFTER);
        TrustAnchors anchors = TrustAnchors.ofCertificate(expiredIntermediate.cert);
        List<GostCertificate> effective =
                TlsCertificateValidator.validate(
                        List.of(leaf.cert, expiredIntermediate.cert),
                        TlsPeerPolicy.server(HOST, anchors));

        long boundary =
                PeerTrustBoundary.validUntil(PeerTrustBoundary.boundaryChain(effective, anchors));

        assertEquals(
                notAfterMillis(leaf.cert),
                boundary,
                "истёкший якорь, допущенный по RFC 5280 §6.1, не должен обнулять границу");
    }

    @Test
    @DisplayName("Якорь при REJECT входит в границу: его срок валидатор проверяет")
    void anchorUnderRejectPolicyIsIncluded() throws Exception {
        CertBundle root = PkixCertTestHelper.createRootCA(PARAMS);
        CertBundle shortRoot =
                PkixCertTestHelper.createReissuedRoot(PARAMS, root, NOT_BEFORE, "20800101000000Z");
        CertBundle intermediate = caSignedBy(root, NOT_BEFORE, INTERMEDIATE_NOT_AFTER);
        CertBundle leaf = leafSignedBy(intermediate, LEAF_NOT_AFTER);
        TrustAnchors anchors =
                TrustAnchors.ofCertificate(shortRoot.cert)
                        .withExpiryPolicy(AnchorExpiryPolicy.REJECT);
        List<GostCertificate> effective =
                TlsCertificateValidator.validate(
                        List.of(leaf.cert, intermediate.cert), TlsPeerPolicy.server(HOST, anchors));

        List<GostCertificate> boundary = PeerTrustBoundary.boundaryChain(effective, anchors);

        assertEquals(effective, boundary, "при REJECT якорь должен остаться в цепочке границы");
        assertEquals(
                notAfterMillis(shortRoot.cert),
                PeerTrustBoundary.validUntil(boundary),
                "граница должна равняться notAfter корня");
    }

    @Test
    @DisplayName("Одиночный закреплённый сертификат остаётся в цепочке: он же leaf")
    void singlePinnedCertificateIsKept() throws Exception {
        CertBundle pinned =
                PkixCertTestHelper.createCertWithKey(
                        PARAMS, NOT_BEFORE, LEAF_NOT_AFTER, new String[] {HOST});
        TrustAnchors anchors = TrustAnchors.ofCertificate(pinned.cert);
        List<GostCertificate> effective = List.of(pinned.cert);

        List<GostCertificate> boundary = PeerTrustBoundary.boundaryChain(effective, anchors);

        assertEquals(effective, boundary, "единственный сертификат не должен исключаться");
        assertEquals(
                notAfterMillis(pinned.cert),
                PeerTrustBoundary.validUntil(boundary),
                "граница должна равняться notAfter закреплённого сертификата");
    }

    @Test
    @DisplayName("Пустая цепочка границы отвергается: границу определить нельзя")
    void emptyChainIsRejected() {
        assertThrows(
                IllegalArgumentException.class,
                () -> PeerTrustBoundary.validUntil(List.of()),
                "для пустой цепочки границы нет, это ошибка вызывающего кода");
    }

    private static long notAfterMillis(GostCertificate cert) {
        Instant notAfter = cert.getNotAfter();
        return notAfter.toEpochMilli();
    }

    private static CertBundle caSignedBy(CertBundle issuer, String notBefore, String notAfter)
            throws Exception {
        return PkixCertTestHelper.createCertSignedBy(
                PARAMS,
                issuer.priv,
                issuer.cert.getPublicKey(),
                issuer.subjectDn,
                notBefore,
                notAfter,
                null,
                null,
                KU_KEY_CERT_SIGN,
                null,
                true,
                null);
    }

    private static CertBundle leafSignedBy(CertBundle issuer, String notAfter) throws Exception {
        return PkixCertTestHelper.createCertSignedBy(
                PARAMS,
                issuer.priv,
                issuer.cert.getPublicKey(),
                issuer.subjectDn,
                NOT_BEFORE,
                notAfter,
                new String[] {HOST},
                null,
                KU_DIGITAL_SIGNATURE,
                EKU_SERVER_AUTH,
                false,
                null);
    }

    /** Цепочка корень -> промежуточный CA -> leaf с заданными сроками. */
    private static final class Chain {
        final CertBundle root;
        final CertBundle intermediate;
        final CertBundle leaf;
        final TrustAnchors anchors;

        Chain(String intermediateNotAfter, String leafNotAfter) throws Exception {
            CertBundle generated = PkixCertTestHelper.createRootCA(PARAMS);
            this.root =
                    PkixCertTestHelper.createReissuedRoot(
                            PARAMS, generated, NOT_BEFORE, ROOT_NOT_AFTER);
            this.intermediate = caSignedBy(root, NOT_BEFORE, intermediateNotAfter);
            this.leaf = leafSignedBy(intermediate, leafNotAfter);
            this.anchors = TrustAnchors.ofCertificate(root.cert);
        }

        List<GostCertificate> validated(AnchorExpiryPolicy policy) throws TlsException {
            return TlsCertificateValidator.validate(
                    List.of(leaf.cert, intermediate.cert),
                    TlsPeerPolicy.server(HOST, anchors.withExpiryPolicy(policy)));
        }
    }
}
