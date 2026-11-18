package org.rssys.gost.jsse;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Проверка имён наборов шифров и протоколов, общая для движка и серверного сокета. */
@DisplayName("SslParameterNames: проверка имён наборов шифров и протоколов")
class SslParameterNamesTest {

    @Test
    @DisplayName("Поддерживаемые наборы принимаются и возвращаются копией")
    void supportedSuitesAreCopied() {
        String[] suites = GostJsseConstants.supportedCipherSuites();

        String[] checked = SslParameterNames.checkedCipherSuites(suites);

        assertArrayEquals(suites, checked, "состав сохраняется");
        assertNotSame(suites, checked, "возвращается копия: изменение исходного массива не влияет");
    }

    @Test
    @DisplayName("Пустой массив допустим: отказ наступит при рукопожатии, как в JDK")
    void emptyArraysAreAccepted() {
        assertEquals(0, SslParameterNames.checkedCipherSuites(new String[0]).length);
        assertEquals(0, SslParameterNames.checkedProtocols(new String[0]).length);
    }

    @Test
    @DisplayName("null и неизвестные имена отвергаются")
    void invalidNamesAreRejected() {
        assertThrows(
                IllegalArgumentException.class, () -> SslParameterNames.checkedCipherSuites(null));
        assertThrows(
                IllegalArgumentException.class,
                () -> SslParameterNames.checkedCipherSuites(new String[] {"TLS_NO_SUCH_SUITE"}));
        assertThrows(
                IllegalArgumentException.class, () -> SslParameterNames.checkedProtocols(null));
        assertThrows(
                IllegalArgumentException.class,
                () -> SslParameterNames.checkedProtocols(new String[] {"TLSv1.2"}));
    }

    @Test
    @DisplayName("Протокол TLSv1.3 принимается")
    void tlsThirteenIsAccepted() {
        assertArrayEquals(
                new String[] {GostJsseConstants.PROTOCOL_TLS_1_3},
                SslParameterNames.checkedProtocols(
                        new String[] {GostJsseConstants.PROTOCOL_TLS_1_3}));
    }
}
