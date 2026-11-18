package org.rssys.gost.jsse.engine;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Хранение ответов OCSP в сессии: порядок, нулевая длина, изоляция копий. */
@DisplayName("GostSSLSession.getStatusResponses: порядок, нулевая длина, изоляция копий")
class GostSSLSessionStatusResponsesTest {

    private static GostSSLSession session() {
        return new GostSSLSession("TLS_TEST", "host", 0, null, null);
    }

    @Test
    @DisplayName("Новая сессия: пустой список")
    void emptyByDefault() {
        assertTrue(session().getStatusResponses().isEmpty());
    }

    @Test
    @DisplayName("[byte[0], staple]: порядок и нулевая длина сохраняются")
    void orderAndZeroLengthPreserved() {
        GostSSLSession s = session();
        byte[] staple = {0x30, 0x03, 0x0A, 0x01, 0x00};
        s.setStatusResponses(List.of(new byte[0], staple));

        List<byte[]> responses = s.getStatusResponses();
        assertEquals(2, responses.size());
        assertEquals(
                0, responses.get(0).length, "нулевая длина - «ответа нет» для первого сертификата");
        assertArrayEquals(staple, responses.get(1));
    }

    @Test
    @DisplayName("Изменение входных массивов и списка не влияет на сессию")
    void inputIsCopied() {
        GostSSLSession s = session();
        byte[] staple = {1, 2, 3};
        List<byte[]> input = new ArrayList<>(List.of(staple));
        s.setStatusResponses(input);

        staple[0] = 9;
        input.clear();

        assertArrayEquals(new byte[] {1, 2, 3}, s.getStatusResponses().get(0));
    }

    @Test
    @DisplayName("Изменение выданных массивов не влияет на сессию, список неизменяем")
    void outputIsCopiedAndUnmodifiable() {
        GostSSLSession s = session();
        s.setStatusResponses(List.of(new byte[] {1, 2, 3}));

        List<byte[]> out = s.getStatusResponses();
        out.get(0)[0] = 9;

        assertArrayEquals(new byte[] {1, 2, 3}, s.getStatusResponses().get(0));
        assertThrows(UnsupportedOperationException.class, () -> out.add(new byte[0]));
    }

    @Test
    @DisplayName("setOcspResponse (сервер): единственный ответ; null очищает")
    void serverSingletonConvenience() {
        GostSSLSession s = session();
        s.setOcspResponse(new byte[] {7});
        assertEquals(1, s.getStatusResponses().size());
        s.setOcspResponse(null);
        assertTrue(s.getStatusResponses().isEmpty());
    }
}
