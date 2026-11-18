package org.rssys.gost.pkix.cms;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.UnaryOperator;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostSignatureHelper;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.util.DerCodec;

/**
 * SignerInfo с содержимым, которое строитель не выпустит (он самопроверяет подписи), собирается
 * заменой частей в готовом DER. Все такие входы должны давать {@link PkixException}, а не
 * unchecked-исключение, и не мешать проверке других подписантов.
 */
@DisplayName("CMS SignedData: искажённые SignerInfo не прорывают контракт PkixException")
class CmsMalformedSignerInfoTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static final byte[] DATA = "Content under signature".getBytes();
    private static final BigInteger BAD_SIGNER_SERIAL = BigInteger.valueOf(1001);
    private static final BigInteger GOOD_SIGNER_SERIAL = BigInteger.valueOf(1002);
    private static final int SIGNER_INFO_DIGEST_ALG = 2;
    private static final int SIGNER_INFO_SIGNED_ATTRS = 3;
    private static final int SIGNER_INFO_SIGNATURE = 5;

    private static GostCertificate badCert;
    private static GostCertificate goodCert;
    private static byte[] twoSignerCms;
    private static TrustAnchors anchors;

    @BeforeAll
    static void setUp() {
        java.security.Security.insertProviderAt(new org.rssys.gost.jca.RssysGostProvider(), 1);
        KeyPair badKeys = KeyGenerator.generateKeyPair(PARAMS);
        KeyPair goodKeys = KeyGenerator.generateKeyPair(PARAMS);
        badCert =
                CmsTestUtils.createSelfSignedCertWithDn(
                        badKeys.getPrivate(), badKeys.getPublic(), BAD_SIGNER_SERIAL, "Bad");
        goodCert =
                CmsTestUtils.createSelfSignedCertWithDn(
                        goodKeys.getPrivate(), goodKeys.getPublic(), GOOD_SIGNER_SERIAL, "Good");
        twoSignerCms =
                CmsSignedDataBuilder.create()
                        .data(DATA)
                        .addSigner(badKeys.getPrivate(), badCert)
                        .addSigner(goodKeys.getPrivate(), goodCert)
                        .build();
        anchors = TrustAnchors.ofCertificates(badCert, goodCert);
    }

    @Test
    @DisplayName("Подпись неверной длины: PkixException вместо IllegalArgumentException")
    void truncatedSignatureGivesPkixException() {
        byte[] cms =
                mutateBadSigner(
                        parts -> {
                            byte[] signature =
                                    DerCodec.parseOctetString(parts[SIGNER_INFO_SIGNATURE], 0);
                            parts[SIGNER_INFO_SIGNATURE] =
                                    DerCodec.encodeOctetString(
                                            Arrays.copyOf(signature, signature.length - 1));
                            return parts;
                        });

        PkixException e =
                assertThrows(
                        PkixException.class,
                        () -> verify(cms, SignerSelection.ALL),
                        "подпись неверной длины должна давать PkixException");
        assertEquals(
                PkixException.Reason.SIGNATURE_INVALID,
                e.reason(),
                "причина - недействительная подпись");
    }

    @Test
    @DisplayName("Дайджест другой длины, чем ключ: ALG_MISMATCH вместо IllegalArgumentException")
    void digestKeyMismatchGivesAlgMismatch() {
        byte[] cms =
                mutateBadSigner(
                        parts -> {
                            // SignerInfo заявляет Стрибог-512 при 256-битном ключе. messageDigest
                            // пересчитан, чтобы проверка дошла до сверки дайджеста с ключом.
                            parts[SIGNER_INFO_DIGEST_ALG] =
                                    DerCodec.encodeSequence(
                                            DerCodec.encodeOid(GostOids.DIGEST_512));
                            parts[SIGNER_INFO_SIGNED_ATTRS] =
                                    replaceMessageDigest(
                                            parts[SIGNER_INFO_SIGNED_ATTRS],
                                            GostSignatureHelper.digestByOid(
                                                    GostOids.DIGEST_512, DATA));
                            return parts;
                        });

        PkixException e =
                assertThrows(
                        PkixException.class,
                        () -> verify(cms, SignerSelection.ALL),
                        "несовпадение дайджеста с ключом должно давать PkixException");
        assertEquals(
                PkixException.Reason.ALG_MISMATCH,
                e.reason(),
                "причина - подмена алгоритма дайджеста");
    }

    @Test
    @DisplayName("ANY: битый подписант не мешает проверке валидного")
    void anyIgnoresMalformedSignerAndAcceptsValid() throws PkixException {
        byte[] cms =
                mutateBadSigner(
                        parts -> {
                            parts[SIGNER_INFO_SIGNATURE] =
                                    DerCodec.encodeOctetString(new byte[] {1, 2, 3});
                            return parts;
                        });

        VerifiedSignedData result = verify(cms, SignerSelection.ANY);

        assertArrayEquals(
                DATA, result.data(), "данные должны быть извлечены по валидному подписанту");
        assertEquals(
                GOOD_SIGNER_SERIAL,
                result.signerCertificate().getSerialNumberBigInt(),
                "принят должен быть именно валидный подписант");
    }

    @Test
    @DisplayName("ALL: битый подписант отклоняет весь SignedData")
    void allRejectsWhenAnySignerMalformed() {
        byte[] cms =
                mutateBadSigner(
                        parts -> {
                            parts[SIGNER_INFO_SIGNATURE] =
                                    DerCodec.encodeOctetString(new byte[] {1, 2, 3});
                            return parts;
                        });

        assertThrows(
                PkixException.class,
                () -> verify(cms, SignerSelection.ALL),
                "в режиме ALL один битый подписант отклоняет подпись");
    }

    private static VerifiedSignedData verify(byte[] cms, SignerSelection selection)
            throws PkixException {
        return CmsSignedDataVerifier.verify(
                cms, VerifyOptions.trusting(anchors, selection, Revocation.none()));
    }

    /** Применяет мутацию к SignerInfo первого подписанта и пересобирает SignedData. */
    private static byte[] mutateBadSigner(UnaryOperator<byte[][]> mutation) {
        try {
            byte[] signedData = CmsContentInfo.decode(twoSignerCms).content();
            byte[][] signedDataParts = DerCodec.parseSequenceContents(signedData, 0);
            int signerInfosIdx = signedDataParts.length - 1;
            byte[][] signerInfos = DerCodec.parseSetContents(signedDataParts[signerInfosIdx], 0);

            List<byte[]> rebuilt = new ArrayList<>();
            for (byte[] signerInfo : signerInfos) {
                byte[][] parts = DerCodec.parseSequenceContents(signerInfo, 0);
                BigInteger serial = CmsIssuerAndSerialNumber.decode(parts[1]).serial();
                rebuilt.add(
                        BAD_SIGNER_SERIAL.equals(serial)
                                ? DerCodec.encodeSequence(mutation.apply(parts))
                                : signerInfo);
            }
            signedDataParts[signerInfosIdx] = DerCodec.encodeSet(rebuilt.toArray(new byte[0][]));
            return DerCodec.encodeSequence(
                    DerCodec.encodeOid(GostOids.CMS_SIGNED_DATA),
                    DerCodec.encodeContextConstructed(0, DerCodec.encodeSequence(signedDataParts)));
        } catch (PkixException e) {
            throw new IllegalStateException("Test CMS could not be rebuilt", e);
        }
    }

    /** Подменяет значение messageDigest в signedAttrs [0], сохраняя остальные атрибуты. */
    private static byte[] replaceMessageDigest(byte[] signedAttrs, byte[] newDigest) {
        int[] len = DerCodec.decodeLength(signedAttrs, 1);
        byte[] content = Arrays.copyOfRange(signedAttrs, 1 + len[1], signedAttrs.length);
        List<byte[]> attributes = new ArrayList<>();
        int pos = 0;
        while (pos < content.length) {
            int[] attrLen = DerCodec.decodeLength(content, pos + 1);
            int total = 1 + attrLen[1] + attrLen[0];
            byte[] attribute = Arrays.copyOfRange(content, pos, pos + total);
            byte[][] attrParts = DerCodec.parseSequenceContents(attribute, 0);
            if (GostOids.ATTR_MESSAGE_DIGEST.equals(DerCodec.parseOid(attrParts[0], 0))) {
                attribute =
                        DerCodec.encodeSequence(
                                attrParts[0],
                                DerCodec.encodeSet(DerCodec.encodeOctetString(newDigest)));
            }
            attributes.add(attribute);
            pos += total;
        }
        return DerCodec.encodeContextConstructed(
                0, DerCodec.concat(attributes.toArray(new byte[0][])));
    }
}
