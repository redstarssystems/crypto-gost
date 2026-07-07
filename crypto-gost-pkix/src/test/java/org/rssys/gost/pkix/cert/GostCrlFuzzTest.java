package org.rssys.gost.pkix.cert;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import java.io.ByteArrayOutputStream;
import org.rssys.gost.api.Digest;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.api.Signature;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.util.DerCodec;

/**
 * Fuzz-тест для {@link GostCrl#GostCrl(byte[])} и IDP-парсинга через
 * {@link GostCrl#verify(PublicKeyParameters)}.
 *
 * <p>ПОЧЕМУ два метода: конструктор принимает недоверенные DER-байты напрямую
 * (fuzzConstructor). IDP- и FreshestCRL-парсинг живут в {@code parseCrlExtensions()} внутри
 * {@code verify()} — до них доходит только при валидной подписи.
 * fuzzIdp/fuzzFreshestCrl строят валидно-подписанный CRL с фаззенными байтами,
 * гарантируя достижение соответствующих методов парсинга.
 */
class GostCrlFuzzTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static final KeyPair KP = KeyGenerator.generateKeyPair(PARAMS);
    private static final byte[] ISSUER_DN;

    static {
        ISSUER_DN = GostDnParser.encodeDn("CN=Fuzz CA,O=FuzzOrg,C=RU");
    }

    @FuzzTest
    void fuzzConstructor(FuzzedDataProvider data) {
        byte[] der = data.consumeRemainingAsBytes();
        if (der.length == 0) return;
        try {
            new GostCrl(der);
        } catch (RuntimeException e) {
            rethrowIfBug(e);
        }
    }

    /**
     * Фаззит парсинг IssuingDistributionPoint (RFC 5280 §5.2.5).
     *
     * <p>Строит TBSCertList с фаззенными IDP-байтами, подписывает валидным ключом,
     * вызывает verify() — подпись гарантированно валидна, управление доходит до
     * {@code parseCrlExtensions()} → {@code parseIdpExtension()}.
     * PkixException (включая IDP_NOT_SUPPORTED при indirectCRL) — ожидаемый fail-closed.
     */
    @FuzzTest
    void fuzzIdp(FuzzedDataProvider data) {
        byte[] idpValue = data.consumeBytes(data.consumeInt(0, 8192));
        if (idpValue.length == 0) idpValue = new byte[] {0x30, 0x00};

        try {
            byte[] tbs = buildTbsWithFuzzedIdp(idpValue);
            int hlen = PARAMS.hlen;

            Digest.Algorithm hashAlg =
                    hlen == 32 ? Digest.Algorithm.STREEBOG_256 : Digest.Algorithm.STREEBOG_512;
            Digest digest = new Digest(hashAlg);
            digest.update(tbs, 0, tbs.length);
            byte[] hash = digest.digest();

            byte[] sig = Signature.signHash(hash, KP.getPrivate());
            byte[] sigAlg = GostSignatureHelper.buildAlgId(PARAMS);

            byte[] crlDer = DerCodec.encodeSequence(tbs, sigAlg, DerCodec.encodeBitString(sig));

            GostCrl crl =
                    new GostCrl(
                            crlDer,
                            GostCrl.DEFAULT_MAX_CRL_SIZE,
                            GostCrl.DEFAULT_MAX_REVOKED_ENTRIES);
            try {
                crl.verify(KP.getPublic());
            } catch (PkixException e) {
                // fail-closed: фаззенный IDP может быть битым → PkixException ок
            }
        } catch (RuntimeException e) {
            rethrowIfBug(e);
        }
    }

    /**
     * Фаззит парсинг FreshestCRL (RFC 5280 §5.2.6).
     *
     * <p>Строит TBSCertList с фаззенными FreshestCRL-байтами, подписывает валидным ключом,
     * вызывает verify() — подпись гарантированно валидна, управление доходит до
     * {@code parseCrlExtensions()} → {@code parseFreshestCrlExtension()}.
     * PkixException — ожидаемый fail-closed при битом DER.</p>
     */
    @FuzzTest
    void fuzzFreshestCrl(FuzzedDataProvider data) {
        byte[] freshestCrlValue = data.consumeBytes(data.consumeInt(0, 8192));
        if (freshestCrlValue.length == 0) freshestCrlValue = new byte[] {0x30, 0x00};

        try {
            byte[] tbs = buildTbsWithFuzzedFreshestCrl(freshestCrlValue);
            int hlen = PARAMS.hlen;

            Digest.Algorithm hashAlg =
                    hlen == 32 ? Digest.Algorithm.STREEBOG_256 : Digest.Algorithm.STREEBOG_512;
            Digest digest = new Digest(hashAlg);
            digest.update(tbs, 0, tbs.length);
            byte[] hash = digest.digest();

            byte[] sig = Signature.signHash(hash, KP.getPrivate());
            byte[] sigAlg = GostSignatureHelper.buildAlgId(PARAMS);

            byte[] crlDer = DerCodec.encodeSequence(tbs, sigAlg, DerCodec.encodeBitString(sig));

            GostCrl crl =
                    new GostCrl(
                            crlDer,
                            GostCrl.DEFAULT_MAX_CRL_SIZE,
                            GostCrl.DEFAULT_MAX_REVOKED_ENTRIES);
            try {
                crl.verify(KP.getPublic());
            } catch (PkixException e) {
                // fail-closed: фаззенный FreshestCRL может быть битым → PkixException ок
            }
        } catch (RuntimeException e) {
            rethrowIfBug(e);
        }
    }

    /**
     * Фаззит парсинг AuthorityKeyIdentifier (RFC 5280 §5.2.1).
     *
     * <p>Строит TBSCertList с фаззенными AKI-байтами, подписывает валидным ключом,
     * вызывает verify() — подпись гарантированно валидна, управление доходит до
     * {@code parseCrlExtensions()} → {@code parseAkiExtension()}.
     * PkixException — ожидаемый fail-closed при битом DER.</p>
     */
    @FuzzTest
    void fuzzAki(FuzzedDataProvider data) {
        byte[] akiValue = data.consumeBytes(data.consumeInt(0, 8192));
        if (akiValue.length == 0) akiValue = new byte[] {0x30, 0x00};

        try {
            byte[] tbs = buildTbsWithFuzzedAki(akiValue);
            int hlen = PARAMS.hlen;

            Digest.Algorithm hashAlg =
                    hlen == 32 ? Digest.Algorithm.STREEBOG_256 : Digest.Algorithm.STREEBOG_512;
            Digest digest = new Digest(hashAlg);
            digest.update(tbs, 0, tbs.length);
            byte[] hash = digest.digest();

            byte[] sig = Signature.signHash(hash, KP.getPrivate());
            byte[] sigAlg = GostSignatureHelper.buildAlgId(PARAMS);

            byte[] crlDer = DerCodec.encodeSequence(tbs, sigAlg, DerCodec.encodeBitString(sig));

            GostCrl crl =
                    new GostCrl(
                            crlDer,
                            GostCrl.DEFAULT_MAX_CRL_SIZE,
                            GostCrl.DEFAULT_MAX_REVOKED_ENTRIES);
            try {
                crl.verify(KP.getPublic());
            } catch (PkixException e) {
                // fail-closed: фаззенный AKI может быть битым → PkixException ок
            }
        } catch (RuntimeException e) {
            rethrowIfBug(e);
        }
    }

    /**
     * Строит TBSCertList DER с фаззенным IDP-расширением.
     * Структура: version [1], AlgorithmId, issuer, thisUpdate, nextUpdate,
     * crlExtensions [0] { IDP extension с фаззенными байтами }.
     */
    private byte[] buildTbsWithFuzzedIdp(byte[] idpValue) {
        try {
            ByteArrayOutputStream tbs = new ByteArrayOutputStream();

            // version INTEGER v2 (0x01)
            tbs.write(DerCodec.encodeTlv(0x02, new byte[] {0x01}));

            // signature AlgorithmIdentifier
            tbs.write(GostSignatureHelper.buildAlgId(PARAMS));

            // issuer Name
            tbs.write(ISSUER_DN);

            // thisUpdate
            tbs.write(DerCodec.encodeTime(GostSignatureHelper.nowGeneralizedTime()));

            // nextUpdate
            tbs.write(DerCodec.encodeTime("20990601120000Z"));

            // crlExtensions [0] EXPLICIT — содержит только IDP-расширение
            byte[] idpOid = DerCodec.encodeOid("2.5.29.28");
            byte[] idpExt = DerCodec.encodeSequence(idpOid, DerCodec.encodeTlv(0x04, idpValue));
            byte[] extSeq = DerCodec.encodeSequence(idpExt);
            tbs.write(DerCodec.encodeTlv(0xA0, extSeq));

            return DerCodec.encodeSequence(tbs.toByteArray());
        } catch (java.io.IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Строит TBSCertList DER с фаззенным FreshestCRL-расширением.
     * Структура идентична buildTbsWithFuzzedIdp, отличается OID (2.5.29.46).
     */
    private byte[] buildTbsWithFuzzedFreshestCrl(byte[] freshestCrlValue) {
        try {
            ByteArrayOutputStream tbs = new ByteArrayOutputStream();

            tbs.write(DerCodec.encodeTlv(0x02, new byte[] {0x01}));
            tbs.write(GostSignatureHelper.buildAlgId(PARAMS));
            tbs.write(ISSUER_DN);
            tbs.write(DerCodec.encodeTime(GostSignatureHelper.nowGeneralizedTime()));
            tbs.write(DerCodec.encodeTime("20990601120000Z"));

            byte[] freshestCrlOid = DerCodec.encodeOid("2.5.29.46");
            byte[] freshestExt =
                    DerCodec.encodeSequence(
                            freshestCrlOid, DerCodec.encodeTlv(0x04, freshestCrlValue));
            byte[] extSeq = DerCodec.encodeSequence(freshestExt);
            tbs.write(DerCodec.encodeTlv(0xA0, extSeq));

            return DerCodec.encodeSequence(tbs.toByteArray());
        } catch (java.io.IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Строит TBSCertList DER с фаззенным AKI-расширением.
     * Структура идентична buildTbsWithFuzzedIdp, отличается OID (2.5.29.35).
     */
    private byte[] buildTbsWithFuzzedAki(byte[] akiValue) {
        try {
            ByteArrayOutputStream tbs = new ByteArrayOutputStream();

            tbs.write(DerCodec.encodeTlv(0x02, new byte[] {0x01}));
            tbs.write(GostSignatureHelper.buildAlgId(PARAMS));
            tbs.write(ISSUER_DN);
            tbs.write(DerCodec.encodeTime(GostSignatureHelper.nowGeneralizedTime()));
            tbs.write(DerCodec.encodeTime("20990601120000Z"));

            byte[] akiOid = DerCodec.encodeOid("2.5.29.35");
            byte[] akiExt = DerCodec.encodeSequence(akiOid, DerCodec.encodeTlv(0x04, akiValue));
            byte[] extSeq = DerCodec.encodeSequence(akiExt);
            tbs.write(DerCodec.encodeTlv(0xA0, extSeq));

            return DerCodec.encodeSequence(tbs.toByteArray());
        } catch (java.io.IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static void rethrowIfBug(RuntimeException e) {
        if (e instanceof ArrayIndexOutOfBoundsException
                || e instanceof IndexOutOfBoundsException
                || e instanceof NegativeArraySizeException
                || e instanceof NullPointerException) {
            throw e;
        }
    }
}
