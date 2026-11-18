package org.rssys.gost.pkix.util;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.net.SocketTimeoutException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("FetchFailure: причина по типу исключения, текст не читается")
class FetchFailureTest {

    @Test
    @DisplayName("Срок и таймаут сокета -> TIMEOUT, размер -> TOO_LARGE")
    void timeoutAndSize() {
        assertEquals(
                FetchFailure.TIMEOUT, FetchFailure.of(new DeadlineExceededException("deadline")));
        assertEquals(FetchFailure.TIMEOUT, FetchFailure.of(new SocketTimeoutException("read")));
        assertEquals(FetchFailure.TOO_LARGE, FetchFailure.of(new BodyTooLargeException(10, 11)));
    }

    @Test
    @DisplayName("Прочий IOException -> NETWORK, непроверяемое исключение -> INTERNAL")
    void networkAndInternal() {
        assertEquals(FetchFailure.NETWORK, FetchFailure.of(new IOException("http://u:p@h/")));
        assertEquals(FetchFailure.INTERNAL, FetchFailure.of(new IllegalStateException("сбой")));
    }
}
