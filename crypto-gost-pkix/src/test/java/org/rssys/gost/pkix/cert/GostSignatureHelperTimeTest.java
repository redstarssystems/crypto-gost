package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.*;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Модульные тесты форматтеров времени {@link GostSignatureHelper}.
 *
 * <p>Фиксируют эквивалентность вывода единого источника истины прежним приватным
 * форматтерам CAdES-C: паттерн {@code "yyMMddHHmmssX"} при нулевом смещении печатает
 * литерал {@code Z} — побайтово совпадает с {@code "yyMMddHHmmss'Z'"}. Тест защищает от
 * регрессии при будущем изменении паттерна в одном из мест.
 */
@DisplayName("GostSignatureHelper: форматтеры времени")
class GostSignatureHelperTimeTest {

    private static final DateTimeFormatter LITERAL_UTC =
            DateTimeFormatter.ofPattern("yyMMddHHmmss'Z'").withZone(ZoneOffset.UTC);
    private static final DateTimeFormatter LITERAL_GEN =
            DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'").withZone(ZoneOffset.UTC);

    @Test
    @DisplayName("formatUtcTime даёт литеральный Z и совпадает с эталоном")
    void formatUtcTimeMatchesLiteralPattern() {
        Instant instant = Instant.parse("2026-07-11T09:08:07Z");
        String actual = GostSignatureHelper.formatUtcTime(instant);
        assertEquals("260711090807Z", actual, "UTCTime должен быть YYMMDDHHMMSSZ");
        assertEquals(
                LITERAL_UTC.format(instant),
                actual,
                "formatUtcTime должен совпадать с прежним литеральным форматтером");
    }

    @Test
    @DisplayName("formatGeneralizedTime даёт полный год и совпадает с эталоном")
    void formatGeneralizedTimeMatchesLiteralPattern() {
        Instant instant = Instant.parse("2026-07-11T09:08:07Z");
        String actual = GostSignatureHelper.formatGeneralizedTime(instant);
        assertEquals("20260711090807Z", actual, "GeneralizedTime должен быть YYYYMMDDHHMMSSZ");
        assertEquals(
                LITERAL_GEN.format(instant),
                actual,
                "formatGeneralizedTime должен совпадать с прежним литеральным форматтером");
    }

    @Test
    @DisplayName("round-trip: formatUtcTime -> parseAsn1Time восстанавливает момент")
    void utcTimeRoundTrip() {
        Instant instant = Instant.parse("2001-02-03T04:05:06Z");
        String utc = GostSignatureHelper.formatUtcTime(instant);
        assertEquals(instant, GostSignatureHelper.parseAsn1Time(utc), "round-trip UTCTime");
    }
}
