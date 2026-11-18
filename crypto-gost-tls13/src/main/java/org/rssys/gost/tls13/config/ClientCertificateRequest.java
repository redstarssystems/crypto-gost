package org.rssys.gost.tls13.config;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Запрос сервера на клиентский сертификат: разобранный CertificateRequest (RFC 8446 §4.3.2).
 * <p>
 * Передаётся {@link ClientCertificateSelector}, чтобы тот выбрал сертификат, подходящий серверу.
 * Запись неизменяема: конструктор копирует списки и массивы, а аксессоры отдают копии, поэтому
 * селектор не может изменить то, что видит движок рукопожатия.
 *
 * @param caDns список DistinguishedName из certificate_authorities (RFC 8446 §4.2.4), может быть
 *              пустым; пустой список означает «CA не указаны», а не «подходящих нет»
 * @param oidFilters список OID-фильтров из oid_filters (RFC 8446 §4.2.5), может быть пустым
 * @param ocspRequested true - сервер запросил OCSP-staple клиентского сертификата (пустое
 *                      расширение status_request, RFC 8446 §4.4.2.1)
 * @param signatureSchemes схемы подписи из signature_algorithms в порядке сервера, включая
 *                      неизвестные нам коды (не пустой список): ключ листа должен подписывать
 *                      CertificateVerify одной из них (RFC 8446 §4.4.3)
 * @param certificateSignatureSchemes схемы подписи сертификатов цепочки: список из
 *                      signature_algorithms_cert, если сервер его прислал, иначе тот же список,
 *                      что и {@code signatureSchemes} (RFC 8446 §4.2.3)
 */
public record ClientCertificateRequest(
        List<byte[]> caDns,
        List<OIDFilter> oidFilters,
        boolean ocspRequested,
        int[] signatureSchemes,
        int[] certificateSignatureSchemes) {

    public ClientCertificateRequest {
        Objects.requireNonNull(caDns, "caDns must not be null");
        Objects.requireNonNull(oidFilters, "oidFilters must not be null");
        Objects.requireNonNull(signatureSchemes, "signatureSchemes must not be null");
        Objects.requireNonNull(
                certificateSignatureSchemes, "certificateSignatureSchemes must not be null");
        // Глубокое копирование: массивы внутри списка изменяемы, List.copyOf их не защищает
        List<byte[]> dnCopies = new ArrayList<>(caDns.size());
        for (byte[] dn : caDns) {
            dnCopies.add(dn.clone());
        }
        caDns = Collections.unmodifiableList(dnCopies);
        oidFilters = List.copyOf(oidFilters);
        signatureSchemes = signatureSchemes.clone();
        certificateSignatureSchemes = certificateSignatureSchemes.clone();
    }

    @Override
    public List<byte[]> caDns() {
        List<byte[]> copies = new ArrayList<>(caDns.size());
        for (byte[] dn : caDns) {
            copies.add(dn.clone());
        }
        return Collections.unmodifiableList(copies);
    }

    @Override
    public int[] signatureSchemes() {
        return signatureSchemes.clone();
    }

    @Override
    public int[] certificateSignatureSchemes() {
        return certificateSignatureSchemes.clone();
    }
}
