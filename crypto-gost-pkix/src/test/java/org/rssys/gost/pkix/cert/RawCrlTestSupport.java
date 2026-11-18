package org.rssys.gost.pkix.cert;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import org.rssys.gost.api.Signature;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.util.DerCodec;

/**
 * Сборка CRL из «сырых» DER-фрагментов для тестов строгого разбора.
 *
 * <p>{@link GostCrlBuilder} намеренно не умеет выпускать кривые структуры, а тестам нужны именно
 * они: неизвестные critical-расширения, повторы, хвосты, выход за границы. CRL подписывается
 * настоящим ключом, поэтому разбор доходит до проверяемых структур (подпись проверяется до
 * разбора).</p>
 */
public final class RawCrlTestSupport {

    public static final String OID_CRL_NUMBER = "2.5.29.20";
    public static final String OID_REASON_CODE = "2.5.29.21";
    public static final String OID_DELTA_CRL_INDICATOR = "2.5.29.27";
    public static final String OID_IDP = "2.5.29.28";
    public static final String OID_CERTIFICATE_ISSUER = "2.5.29.29";
    public static final String OID_AKI = "2.5.29.35";
    public static final String OID_FRESHEST_CRL = "2.5.29.46";
    public static final String OID_UNKNOWN = "1.2.3.4.5";

    private RawCrlTestSupport() {}

    /** Extension ::= SEQUENCE { extnID, critical (только если true), extnValue }. */
    public static byte[] extension(String oid, boolean critical, byte[] valueDer) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(DerCodec.encodeOid(oid));
        if (critical) {
            out.writeBytes(DerCodec.encodeBoolean(true));
        }
        out.writeBytes(DerCodec.encodeOctetString(valueDer));
        return DerCodec.encodeSequence(out.toByteArray());
    }

    /** SEQUENCE OF Extension. */
    public static byte[] extensionList(byte[]... extensions) {
        return DerCodec.encodeSequence(concat(extensions));
    }

    /** crlExtensions [0] EXPLICIT SEQUENCE OF Extension. */
    public static byte[] crlExtensions(byte[]... extensions) {
        return DerCodec.encodeTlv(0xA0, extensionList(extensions));
    }

    /** RevokedCertificate с серийным номером, датой и необязательным списком расширений. */
    public static byte[] revokedEntry(BigInteger serial, byte[] entryExtensionList) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(DerCodec.encodeInteger(serial));
        out.writeBytes(DerCodec.encodeTime("260601000000Z"));
        if (entryExtensionList != null) {
            out.writeBytes(entryExtensionList);
        }
        return DerCodec.encodeSequence(out.toByteArray());
    }

    /** SEQUENCE OF RevokedCertificate. */
    public static byte[] revokedList(byte[]... entries) {
        return DerCodec.encodeSequence(concat(entries));
    }

    public static byte[] reasonCodeValue(int code) {
        return DerCodec.encodeTlv(DerCodec.TAG_ENUMERATED, new byte[] {(byte) code});
    }

    public static byte[] integerValue(BigInteger value) {
        return DerCodec.encodeInteger(value);
    }

    /**
     * Подписанный CRL: версия, алгоритм, издатель, даты, затем {@code tbsTail} — произвольные
     * байты после nextUpdate (revokedCertificates и/или crlExtensions либо мусор).
     */
    public static byte[] crl(
            PrivateKeyParameters signKey, ECParameters params, byte[] issuerDn, byte[]... tbsTail) {
        ByteArrayOutputStream tbsOut = new ByteArrayOutputStream();
        tbsOut.writeBytes(DerCodec.encodeTlv(0x02, new byte[] {0x01}));
        tbsOut.writeBytes(GostSignatureHelper.buildAlgId(params));
        tbsOut.writeBytes(issuerDn);
        tbsOut.writeBytes(DerCodec.encodeTime(GostSignatureHelper.nowGeneralizedTime()));
        tbsOut.writeBytes(DerCodec.encodeTime("20990601120000Z"));
        for (byte[] part : tbsTail) {
            tbsOut.writeBytes(part);
        }
        return sign(signKey, params, DerCodec.encodeSequence(tbsOut.toByteArray()), new byte[0]);
    }

    /** Подписывает готовый TBS; {@code trailer} дописывается после CertificateList. */
    public static byte[] sign(
            PrivateKeyParameters signKey, ECParameters params, byte[] tbs, byte[] trailer) {
        byte[] hash = GostSignatureHelper.doHash(tbs, params.hlen);
        byte[] signature = Signature.signHash(hash, signKey);
        byte[] list =
                DerCodec.encodeSequence(
                        tbs,
                        GostSignatureHelper.buildAlgId(params),
                        DerCodec.encodeBitString(signature));
        if (trailer.length == 0) {
            return list;
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(list);
        out.writeBytes(trailer);
        return out.toByteArray();
    }

    public static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.writeBytes(part);
        }
        return out.toByteArray();
    }
}
