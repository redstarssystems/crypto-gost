package org.rssys.gost.tls13.config;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("ClientCertificateRequest: неизменяемость запроса сервера")
class ClientCertificateRequestTest {

    private static final int[] SCHEMES = {0x0709, 0x070A};

    @Test
    @DisplayName("Изменение исходных массивов и списков после создания запись не меняет")
    void sourceMutationDoesNotLeakIn() {
        byte[] dn = {1, 2, 3};
        List<byte[]> caDns = new ArrayList<>(List.of(dn));
        int[] schemes = SCHEMES.clone();
        int[] certSchemes = SCHEMES.clone();
        ClientCertificateRequest request =
                new ClientCertificateRequest(caDns, List.of(), false, schemes, certSchemes);

        dn[0] = 9;
        caDns.clear();
        schemes[0] = 0;
        certSchemes[0] = 0;

        assertArrayEquals(new byte[] {1, 2, 3}, request.caDns().get(0), "DN скопирован");
        assertEquals(1, request.caDns().size(), "список скопирован");
        assertArrayEquals(SCHEMES, request.signatureSchemes(), "схемы скопированы");
        assertArrayEquals(SCHEMES, request.certificateSignatureSchemes(), "схемы сертификатов");
    }

    @Test
    @DisplayName("Изменение возвращённых аксессорами значений запись не меняет")
    void accessorMutationDoesNotLeakOut() {
        ClientCertificateRequest request =
                new ClientCertificateRequest(
                        List.of(new byte[] {1, 2, 3}), List.of(), true, SCHEMES, SCHEMES);

        request.caDns().get(0)[0] = 9;
        request.signatureSchemes()[0] = 0;
        request.certificateSignatureSchemes()[0] = 0;

        assertArrayEquals(new byte[] {1, 2, 3}, request.caDns().get(0), "DN не изменился");
        assertArrayEquals(SCHEMES, request.signatureSchemes(), "схемы не изменились");
        assertArrayEquals(SCHEMES, request.certificateSignatureSchemes(), "схемы сертификатов");
    }

    @Test
    @DisplayName("Список DN неизменяем")
    void caDnsListIsUnmodifiable() {
        ClientCertificateRequest request =
                new ClientCertificateRequest(
                        List.of(new byte[] {1}), List.of(), false, SCHEMES, SCHEMES);
        assertThrows(UnsupportedOperationException.class, () -> request.caDns().clear());
        assertThrows(UnsupportedOperationException.class, () -> request.oidFilters().clear());
    }

    @Test
    @DisplayName(
            "OID-фильтр внутри запроса неизменяем: ни исходные, ни возвращённые массивы его не меняют")
    void oidFilterIsImmutable() {
        byte[] oid = {1, 2, 3};
        byte[] values = {4, 5};
        ClientCertificateRequest request =
                new ClientCertificateRequest(
                        List.of(), List.of(new OIDFilter(oid, values)), false, SCHEMES, SCHEMES);

        oid[0] = 9;
        values[0] = 9;
        request.oidFilters().get(0).extensionOid()[1] = 9;
        request.oidFilters().get(0).extensionValues()[1] = 9;

        assertArrayEquals(
                new byte[] {1, 2, 3},
                request.oidFilters().get(0).extensionOid(),
                "OID не изменился");
        assertArrayEquals(
                new byte[] {4, 5},
                request.oidFilters().get(0).extensionValues(),
                "значения не изменились");
    }

    @Test
    @DisplayName("null в любом компоненте даёт NullPointerException")
    void nullComponentsAreRejected() {
        assertThrows(
                NullPointerException.class,
                () -> new ClientCertificateRequest(null, List.of(), false, SCHEMES, SCHEMES));
        assertThrows(
                NullPointerException.class,
                () -> new ClientCertificateRequest(List.of(), null, false, SCHEMES, SCHEMES));
        assertThrows(
                NullPointerException.class,
                () -> new ClientCertificateRequest(List.of(), List.of(), false, null, SCHEMES));
        assertThrows(
                NullPointerException.class,
                () -> new ClientCertificateRequest(List.of(), List.of(), false, SCHEMES, null));
    }
}
