package org.rssys.gost.pkix.internal.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.internal.net.FetchOutcome.Failure;
import org.rssys.gost.pkix.util.FetchFailure;
import org.rssys.gost.util.SafeText;

@DisplayName("FetchOutcome: успех с телом либо отказ с причиной")
class FetchOutcomeTest {

    @Test
    @DisplayName("Успех несёт тело и не несёт причины")
    void success() {
        FetchOutcome outcome = FetchOutcome.success(new byte[] {1});

        assertTrue(outcome.isSuccess());
        assertNull(outcome.failure());
        assertEquals(1, outcome.body().length);
    }

    @Test
    @DisplayName("Отказ не несёт тела; тело ошибки по умолчанию пустое")
    void failure() {
        FetchOutcome outcome =
                FetchOutcome.failure(Failure.NON_200, 503, URI.create("http://a.example/"), false);

        assertFalse(outcome.isSuccess());
        assertNull(outcome.body());
        assertEquals(503, outcome.status());
        assertEquals(0, outcome.errorBody().length);
    }

    @Test
    @DisplayName("Content-Type очищается от управляющих символов и усекается")
    void contentTypeIsSanitized() {
        FetchOutcome outcome =
                FetchOutcome.failure(
                        Failure.UNEXPECTED_CONTENT_TYPE,
                        200,
                        URI.create("http://a.example/"),
                        false,
                        "text/html\r\nX-Injected: 1" + "y".repeat(500),
                        null);

        assertTrue(outcome.contentType().startsWith("text/html??X-Injected: 1"));
        assertEquals(SafeText.MAX_HEADER_CHARS, outcome.contentType().length());
    }

    @Test
    @DisplayName("Исход обязан быть ровно одним из: тело, отказ, не изменилось")
    void exactlyOneState() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new FetchOutcome(null, null, false, null, 0, null, false, null, new byte[0]));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new FetchOutcome(
                                new byte[0],
                                Failure.NON_200,
                                false,
                                null,
                                0,
                                null,
                                false,
                                null,
                                new byte[0]));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new FetchOutcome(
                                new byte[0], null, true, null, 0, null, false, null, new byte[0]));
    }

    @Test
    @DisplayName("«Не изменилось»: не успех и не отказ, валидатора нет")
    void unchanged() {
        FetchOutcome outcome = FetchOutcome.unchanged();

        assertTrue(outcome.notModified());
        assertFalse(outcome.isSuccess(), "тела нет");
        assertNull(outcome.failure());
        assertNull(outcome.lastModified(), "дата из ответа 304 не читается");
    }

    @Test
    @DisplayName("Успех несёт допустимый Last-Modified и отбрасывает недопустимый")
    void successValidator() {
        assertEquals(
                "Sun, 08 Nov 2026 03:08:46 GMT",
                FetchOutcome.success(new byte[1], "Sun, 08 Nov 2026 03:08:46 GMT").lastModified());
        assertNull(FetchOutcome.success(new byte[1], "garbage").lastModified());
        assertNull(FetchOutcome.success(new byte[1]).lastModified());
    }

    @Test
    @DisplayName("Отказ без адреса не создаётся")
    void failureRequiresUri() {
        assertThrows(
                NullPointerException.class,
                () -> FetchOutcome.failure(Failure.NON_200, 500, null, false));
    }

    @Test
    @DisplayName(
            "Причина для журнала: каждая причина движка сводится к перечислению, у успеха её нет")
    void reasonMapsEveryFailure() {
        URI uri = URI.create("http://a.example/");
        java.util.Map<Failure, FetchFailure> expected =
                java.util.Map.of(
                        Failure.NON_200, FetchFailure.HTTP_STATUS,
                        Failure.DISALLOWED_SCHEME, FetchFailure.UNSUPPORTED_SCHEME,
                        Failure.BLOCKED_TARGET, FetchFailure.ADDRESS_BLOCKED,
                        Failure.DOWNGRADE, FetchFailure.REDIRECT_REJECTED,
                        Failure.MISSING_LOCATION, FetchFailure.REDIRECT_REJECTED,
                        Failure.BAD_LOCATION, FetchFailure.REDIRECT_REJECTED,
                        Failure.TOO_MANY_REDIRECTS, FetchFailure.REDIRECT_REJECTED,
                        Failure.UNEXPECTED_CONTENT_TYPE, FetchFailure.CONTENT_TYPE);

        for (Failure failure : Failure.values()) {
            assertEquals(
                    expected.get(failure),
                    FetchOutcome.failure(failure, 0, uri, false).reason(),
                    "причина для " + failure);
        }
        assertNull(FetchOutcome.success(new byte[] {1}).reason(), "у успеха причины нет");
        assertNull(FetchOutcome.unchanged().reason(), "у «не изменилось» причины нет");
    }
}
