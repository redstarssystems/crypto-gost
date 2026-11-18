package org.rssys.gost.pkix.cms;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.List;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.util.DerCodec;

/** Общие приёмы тестов готовых векторов, созданных КриптоПро. */
final class CryptoproVectorSupport {

    private CryptoproVectorSupport() {}

    /** Читает ресурс вектора; {@code dir} вида {@code /cryptopro_xlong/}. */
    static byte[] resource(String dir, String name) throws IOException {
        try (InputStream in = CryptoproVectorSupport.class.getResourceAsStream(dir + name)) {
            if (in == null) {
                throw new IOException("нет ресурса " + dir + name);
            }
            return in.readAllBytes();
        }
    }

    /** Сырой атрибут certificate-values первого подписанта (без канонизации цепочки). */
    static List<GostCertificate> rawCertificateValues(byte[] cadesDer) throws Exception {
        SignedDataParts sd = SignedDataParts.parse(CmsContentInfo.decode(cadesDer).content());
        byte[][] signerInfos = DerCodec.parseSetContents(sd.signerInfosField(), 0);
        for (byte[] part : DerCodec.parseSequenceContents(signerInfos[0], 0)) {
            if (!DerCodec.isContextTag(part, 1)) {
                continue;
            }
            int[] lenInfo = DerCodec.decodeLength(part, 1);
            byte[] content = Arrays.copyOfRange(part, 1 + lenInfo[1], part.length);
            int pos = 0;
            while (pos < content.length) {
                int[] attrLen = DerCodec.decodeLength(content, pos + 1);
                int total = 1 + attrLen[1] + attrLen[0];
                CmsAttribute attr =
                        CmsAttribute.decode(Arrays.copyOfRange(content, pos, pos + total));
                if (GostOids.CERTIFICATE_VALUES.equals(attr.attrType())) {
                    return CAdESXLongData.decodeCertificateValues(attr.attrValues()[0]);
                }
                pos += total;
            }
        }
        throw new AssertionError("certificate-values не найден");
    }

    /** Смещение первого вхождения {@code needle} в {@code haystack} или -1. */
    static int indexOf(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= haystack.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }
}
