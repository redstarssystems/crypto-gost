package org.rssys.gost.pkix.cert;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Набор доказательств отзыва для одного сертификата в CAdES-X Long.
 *
 * <p>В отличие от {@link CertRevocationData}, где выбирается одно
 * доказательство, здесь хранятся все CRL и OCSP-ответы, совпавшие с
 * C-ссылками. Проверяются все: любой видимый отзыв отклоняет подпись, а
 * хотя бы одно {@code good}-доказательство в окне делает проверку успешной.</p>
 *
 * @param crlDers          DER-кодированные CRL (не {@code null})
 * @param ocspResponseDers DER-кодированные OCSP-ответы (не {@code null})
 */
public record CertRevocationEvidence(List<byte[]> crlDers, List<byte[]> ocspResponseDers) {

    public CertRevocationEvidence {
        Objects.requireNonNull(crlDers, "crlDers must not be null");
        Objects.requireNonNull(ocspResponseDers, "ocspResponseDers must not be null");
        crlDers = copy(crlDers, "crlDers");
        ocspResponseDers = copy(ocspResponseDers, "ocspResponseDers");
    }

    private static List<byte[]> copy(List<byte[]> source, String name) {
        List<byte[]> result = new ArrayList<>(source.size());
        for (byte[] value : source) {
            if (value == null) {
                throw new IllegalArgumentException(name + " must not contain null");
            }
            result.add(value.clone());
        }
        return List.copyOf(result);
    }

    @Override
    public List<byte[]> crlDers() {
        return copy(crlDers, "crlDers");
    }

    @Override
    public List<byte[]> ocspResponseDers() {
        return copy(ocspResponseDers, "ocspResponseDers");
    }

    /** Возвращает {@code true}, если не передано ни одного доказательства. */
    public boolean isEmpty() {
        return crlDers.isEmpty() && ocspResponseDers.isEmpty();
    }
}
