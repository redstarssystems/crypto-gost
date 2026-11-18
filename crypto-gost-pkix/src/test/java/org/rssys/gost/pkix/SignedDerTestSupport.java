package org.rssys.gost.pkix;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.rssys.gost.util.DerCodec;

/**
 * Сравнение подписанных DER-объектов с нормализацией значения подписи.
 *
 * <p>Подпись ГОСТ Р 34.10-2012 по умолчанию вероятностная: один и тот же TBS, подписанный дважды,
 * даёт разные байты подписи. Поэтому тесты вида «два пути сборки дают один объект» сравнивают всё,
 * что подписывается (TBS сертификата, CSR, CRL, подписанные атрибуты CMS, {@code tbsResponseData}
 * OCSP, алгоритмы, поле {@code certs}), побайтно, а байты самого значения подписи обнуляют. Так
 * расхождение двух путей сборки по-прежнему видно, а вероятностный нонс его не маскирует.
 *
 * <p>Значение подписи ищется структурно: это последний элемент {@code BIT STRING} или
 * {@code OCTET STRING} сразу после {@code AlgorithmIdentifier} с OID подписи ГОСТ. Байты открытого
 * ключа в {@code SubjectPublicKeyInfo} (там после идентификатора алгоритма тоже {@code BIT
 * STRING}) не обнуляются.
 */
public final class SignedDerTestSupport {

    private static final int TAG_BIT_STRING = 0x03;
    private static final int TAG_OCTET_STRING = 0x04;
    private static final int TAG_SEQUENCE = 0x30;
    private static final int CONSTRUCTED_BIT = 0x20;

    /** OID комбинированной подписи: после них стоит значение подписи (BIT или OCTET STRING). */
    private static final List<byte[]> SIGN_WITH_DIGEST_OIDS =
            List.of(
                    DerCodec.encodeOid(GostOids.SIGN_WITH_DIGEST_256),
                    DerCodec.encodeOid(GostOids.SIGN_WITH_DIGEST_512));

    /**
     * OID ключа: в CMS {@code SignerInfo} им может быть задан алгоритм подписи (значение подписи -
     * {@code OCTET STRING}); в {@code SubjectPublicKeyInfo} после него стоит {@code BIT STRING}
     * открытого ключа, который обнулять нельзя.
     */
    private static final List<byte[]> PUBLIC_KEY_OIDS =
            List.of(
                    DerCodec.encodeOid(GostOids.PUBLIC_KEY_256),
                    DerCodec.encodeOid(GostOids.PUBLIC_KEY_512));

    private SignedDerTestSupport() {}

    /**
     * Проверяет, что два DER-объекта совпадают побайтно везде, кроме значения подписи.
     *
     * @param message пояснение для сообщения об ошибке
     */
    public static void assertSameExceptSignature(String message, byte[] first, byte[] second) {
        assertArrayEquals(
                withZeroedSignatures(first),
                withZeroedSignatures(second),
                message + " (значения подписи при сравнении обнулены)");
    }

    /**
     * Копия DER с обнулёнными байтами значений подписи ГОСТ. Длины и все прочие байты сохраняются.
     *
     * @throws AssertionError если в объекте не найдено ни одной подписи: иначе сравнение стало бы
     *                        сравнением необработанных байт, и тест проходил бы тривиально
     */
    public static byte[] withZeroedSignatures(byte[] der) {
        byte[] copy = der.clone();
        int count = zeroSignatures(der, copy, 0, der.length);
        if (count == 0) {
            fail("в DER не найдено значения подписи ГОСТ: нормализация ничего не обнулила");
        }
        return copy;
    }

    private record Element(int tag, int contentStart, int contentEnd) {}

    private static int zeroSignatures(byte[] data, byte[] out, int start, int end) {
        List<Element> elements = new ArrayList<>();
        int position = start;
        while (position < end) {
            int tag = DerCodec.decodeTag(data, position);
            int[] length = DerCodec.decodeLength(data, position + 1);
            int contentStart = position + 1 + length[1];
            int contentEnd = contentStart + length[0];
            if (contentEnd > end) {
                throw new IllegalArgumentException("элемент выходит за границы родителя");
            }
            elements.add(new Element(tag, contentStart, contentEnd));
            position = contentEnd;
        }

        int count = 0;
        for (int i = 1; i < elements.size(); i++) {
            Element algorithm = elements.get(i - 1);
            Element value = elements.get(i);
            if (algorithm.tag() != TAG_SEQUENCE) {
                continue;
            }
            int oidKind = signatureOidKind(data, algorithm);
            boolean bitString = value.tag() == TAG_BIT_STRING;
            boolean octetString = value.tag() == TAG_OCTET_STRING;
            boolean signature =
                    (oidKind == 1 && (bitString || octetString)) || (oidKind == 2 && octetString);
            if (signature) {
                // В BIT STRING первый байт - число неиспользуемых бит, его оставляем
                int from = value.contentStart() + (bitString ? 1 : 0);
                Arrays.fill(out, from, value.contentEnd(), (byte) 0);
                count++;
            }
        }

        for (Element element : elements) {
            if ((element.tag() & CONSTRUCTED_BIT) != 0) {
                count += zeroSignatures(data, out, element.contentStart(), element.contentEnd());
            } else if (element.tag() == TAG_OCTET_STRING) {
                count += zeroInsideOctetString(data, out, element);
            }
        }
        return count;
    }

    /**
     * OCTET STRING может нести вложенный DER (BasicOCSPResponse внутри ResponseBytes). Заходим
     * внутрь, только если содержимое целиком является одной последовательностью.
     */
    private static int zeroInsideOctetString(byte[] data, byte[] out, Element octetString) {
        int start = octetString.contentStart();
        int end = octetString.contentEnd();
        if (end - start < 2 || (data[start] & 0xFF) != TAG_SEQUENCE) {
            return 0;
        }
        try {
            int[] length = DerCodec.decodeLength(data, start + 1);
            if (start + 1 + length[1] + length[0] != end) {
                return 0;
            }
            return zeroSignatures(data, out, start, end);
        } catch (IllegalArgumentException notNestedDer) {
            return 0;
        }
    }

    /** 1 - OID комбинированной подписи, 2 - OID ключа, 0 - прочее. */
    private static int signatureOidKind(byte[] data, Element algorithmSequence) {
        int start = algorithmSequence.contentStart();
        if (start >= algorithmSequence.contentEnd() || (data[start] & 0xFF) != 0x06) {
            return 0;
        }
        int[] length = DerCodec.decodeLength(data, start + 1);
        int end = start + 1 + length[1] + length[0];
        if (end > algorithmSequence.contentEnd()) {
            return 0;
        }
        byte[] oid = Arrays.copyOfRange(data, start, end);
        for (byte[] known : SIGN_WITH_DIGEST_OIDS) {
            if (Arrays.equals(oid, known)) {
                return 1;
            }
        }
        for (byte[] known : PUBLIC_KEY_OIDS) {
            if (Arrays.equals(oid, known)) {
                return 2;
            }
        }
        return 0;
    }
}
