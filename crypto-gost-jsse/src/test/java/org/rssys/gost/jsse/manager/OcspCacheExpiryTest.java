package org.rssys.gost.jsse.manager;

import static org.junit.jupiter.api.Assertions.*;

import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.pkix.cert.GostDnParser;
import org.rssys.gost.pkix.cert.GostOcspResponse;
import org.rssys.gost.pkix.cert.GostOcspResponseBuilder;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.pkix.cert.SingleOcspResponse;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.util.DerCodec;

/**
 * Срок записи OCSP-кэша не должен превышать окно, которое принимает {@code OcspVerifier}:
 * тот отвергает ответ сразу после {@code nextUpdate}, а без него - после
 * {@code thisUpdate + maxOcspAgeMs}.
 */
@DisplayName("GostX509TrustManager: срок жизни записи OCSP-кэша")
class OcspCacheExpiryTest {

    /** Тег certStatus good ([0] IMPLICIT NULL, RFC 6960 §4.2.1). */
    private static final int CERT_STATUS_GOOD_TAG = 0x80;

    private static final long NOW_MS = 1_800_000_000_000L;
    private static final long TTL_MS = Duration.ofHours(1).toMillis();
    private static final long MAX_AGE_MS = Duration.ofHours(6).toMillis();

    private static SingleOcspResponse single(Instant thisUpdate, Instant nextUpdate) {
        return new SingleOcspResponse(
                new byte[] {0x01}, CERT_STATUS_GOOD_TAG, thisUpdate, nextUpdate, null, null);
    }

    @Test
    @DisplayName("С nextUpdate: срок равен nextUpdate без допуска часов, если он раньше TTL")
    void expiryIsExactlyNextUpdate() {
        Instant now = Instant.ofEpochMilli(NOW_MS);
        Instant nextUpdate = now.plus(Duration.ofMinutes(10));

        long expiresAt =
                GostX509TrustManager.ocspCacheExpiry(
                        single(now.minus(Duration.ofHours(1)), nextUpdate),
                        NOW_MS,
                        TTL_MS,
                        MAX_AGE_MS,
                        null);

        assertEquals(
                nextUpdate.toEpochMilli(),
                expiresAt,
                "OcspVerifier отвергает ответ сразу после nextUpdate: допуск часов не добавляется");
    }

    @Test
    @DisplayName("С nextUpdate: срок ограничен TTL кэша")
    void expiryIsCappedByCacheTtl() {
        Instant now = Instant.ofEpochMilli(NOW_MS);

        long expiresAt =
                GostX509TrustManager.ocspCacheExpiry(
                        single(now, now.plus(Duration.ofDays(7))),
                        NOW_MS,
                        TTL_MS,
                        MAX_AGE_MS,
                        null);

        assertEquals(NOW_MS + TTL_MS, expiresAt, "далёкий nextUpdate не должен продлевать кэш");
    }

    @Test
    @DisplayName("Без nextUpdate: срок ограничен окном thisUpdate + maxOcspAgeMs")
    void withoutNextUpdateExpiryFollowsMaxAge() {
        Instant now = Instant.ofEpochMilli(NOW_MS);
        // Ответ выпущен 5 ч назад, окно 6 ч: остаётся час, TTL кэша тоже час - берём меньшее.
        Instant thisUpdate = now.minus(Duration.ofHours(5)).minus(Duration.ofMinutes(30));

        long expiresAt =
                GostX509TrustManager.ocspCacheExpiry(
                        single(thisUpdate, null), NOW_MS, TTL_MS, MAX_AGE_MS, null);

        assertEquals(
                thisUpdate.toEpochMilli() + MAX_AGE_MS,
                expiresAt,
                "без nextUpdate кэш не должен жить дольше окна свежести верификатора");
    }

    @Test
    @DisplayName("Уже просроченный ответ получает срок не позже now: не кэшируется")
    void alreadyExpiredResponseIsNotCacheable() {
        Instant now = Instant.ofEpochMilli(NOW_MS);

        long expiresAt =
                GostX509TrustManager.ocspCacheExpiry(
                        single(now.minus(Duration.ofDays(2)), now.minus(Duration.ofMinutes(1))),
                        NOW_MS,
                        TTL_MS,
                        MAX_AGE_MS,
                        null);

        assertTrue(expiresAt <= NOW_MS, "ответ после nextUpdate не должен кэшироваться");
    }

    @Test
    @DisplayName("Предел возраста: далёкий nextUpdate и старый thisUpdate - срок не дальше предела")
    void limitCapsExpiryWithFarNextUpdate() {
        Instant now = Instant.ofEpochMilli(NOW_MS);
        // Ответ выпущен 5 ч назад, предел 5 ч 30 мин: остаётся полчаса, это меньше TTL (час)
        Instant thisUpdate = now.minus(Duration.ofHours(5));
        Duration limit = Duration.ofHours(5).plus(Duration.ofMinutes(30));

        long expiresAt =
                GostX509TrustManager.ocspCacheExpiry(
                        single(thisUpdate, now.plus(Duration.ofDays(30))),
                        NOW_MS,
                        TTL_MS,
                        MAX_AGE_MS,
                        limit);

        assertEquals(
                thisUpdate.toEpochMilli() + limit.toMillis(),
                expiresAt,
                "кэш не должен держать ответ дольше окна, которое примет проверка");
    }

    @Test
    @DisplayName("Предел возраста: ответ уже старше предела - не кэшируется")
    void limitMakesTooOldResponseNotCacheable() {
        Instant now = Instant.ofEpochMilli(NOW_MS);

        long expiresAt =
                GostX509TrustManager.ocspCacheExpiry(
                        single(now.minus(Duration.ofHours(5)), now.plus(Duration.ofDays(30))),
                        NOW_MS,
                        TTL_MS,
                        MAX_AGE_MS,
                        Duration.ofHours(2));

        assertTrue(expiresAt <= NOW_MS, "ответ старше предела проверка отвергнет: не кэшировать");
    }

    @Test
    @DisplayName("Предел возраста: без nextUpdate действует меньшее из maxOcspAgeMs и предела")
    void limitWithoutNextUpdateTakesMinimum() {
        Instant now = Instant.ofEpochMilli(NOW_MS);
        Instant thisUpdate = now.minus(Duration.ofMinutes(10));
        Duration limit = Duration.ofMinutes(30);

        long expiresAt =
                GostX509TrustManager.ocspCacheExpiry(
                        single(thisUpdate, null), NOW_MS, TTL_MS, MAX_AGE_MS, limit);

        assertEquals(
                thisUpdate.toEpochMilli() + limit.toMillis(),
                expiresAt,
                "предел 30 мин строже maxOcspAgeMs (6 ч) и TTL (1 ч)");
    }

    @Test
    @DisplayName("Предел возраста больше остальных пределов ничего не меняет")
    void largeLimitDoesNotChangeExpiry() {
        Instant now = Instant.ofEpochMilli(NOW_MS);
        Instant nextUpdate = now.plus(Duration.ofMinutes(10));

        long expiresAt =
                GostX509TrustManager.ocspCacheExpiry(
                        single(now.minus(Duration.ofHours(1)), nextUpdate),
                        NOW_MS,
                        TTL_MS,
                        MAX_AGE_MS,
                        Duration.ofDays(365));

        assertEquals(nextUpdate.toEpochMilli(), expiresAt);
    }

    @Test
    @DisplayName("Очень большой предел: насыщение, без исключения")
    void hugeLimitSaturatesWithoutException() {
        Instant now = Instant.ofEpochMilli(NOW_MS);
        Instant nextUpdate = now.plus(Duration.ofMinutes(10));

        long expiresAt =
                assertDoesNotThrow(
                        () ->
                                GostX509TrustManager.ocspCacheExpiry(
                                        single(now, nextUpdate),
                                        NOW_MS,
                                        TTL_MS,
                                        MAX_AGE_MS,
                                        Duration.ofSeconds(Long.MAX_VALUE)),
                        "настройка не должна обрывать соединение переполнением");

        assertEquals(
                nextUpdate.toEpochMilli(), expiresAt, "огромный предел ничего не ограничивает");
    }

    @Test
    @DisplayName("SingleResponse выбирается по серийному номеру сертификата")
    void singleResponseIsMatchedBySerial() throws PkixException {
        KeyPair keys = KeyGenerator.generateKeyPair(ECParameters.tc26a256());
        byte[] ocspDer =
                GostOcspResponseBuilder.create(new byte[] {0x2A})
                        .issuerDn(GostDnParser.encodeDn("CN=Test CA"))
                        .sign(keys.getPrivate());

        assertNotNull(
                GostX509TrustManager.findSingleResponse(ocspDer, new byte[] {0x2A}),
                "ответ для своего серийного номера должен находиться");
        assertNull(
                GostX509TrustManager.findSingleResponse(ocspDer, new byte[] {0x2B}),
                "ответ на чужой серийный номер не должен использоваться для расчёта срока");
    }

    @Test
    @DisplayName("В ответе с несколькими SingleResponse выбирается запись нужного сертификата")
    void singleResponseIsFoundWhenNotFirst() throws PkixException {
        KeyPair keys = KeyGenerator.generateKeyPair(ECParameters.tc26a256());
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");
        byte[] otherSerial = new byte[] {0x11};
        byte[] targetSerial = new byte[] {0x22};
        byte[] otherDer =
                GostOcspResponseBuilder.create(otherSerial)
                        .issuerDn(issuerDn)
                        .nextUpdate(Instant.now().plus(Duration.ofDays(1)))
                        .sign(keys.getPrivate());
        byte[] targetDer =
                GostOcspResponseBuilder.create(targetSerial)
                        .issuerDn(issuerDn)
                        .nextUpdate(Instant.now().plus(Duration.ofMinutes(3)))
                        .sign(keys.getPrivate());

        // Целевая запись ставится второй: getNextUpdate() взял бы срок первой (чужой, сутки).
        byte[] combined = withSingleResponsesOf(targetDer, otherDer);

        GostOcspResponse parsed = new GostOcspResponse(combined);
        assertEquals(2, parsed.getResponses().size(), "в ответе должно быть две записи");
        assertEquals(
                parsed.getResponses().get(0).nextUpdate(),
                parsed.getNextUpdate(),
                "getNextUpdate() берёт первую запись - именно поэтому его нельзя использовать");

        SingleOcspResponse found = GostX509TrustManager.findSingleResponse(combined, targetSerial);
        assertNotNull(found, "запись целевого сертификата должна находиться, пусть и не первой");
        assertArrayEquals(targetSerial, found.certSerialNumber(), "серийный номер записи");
        assertTrue(
                found.nextUpdate().isBefore(parsed.getResponses().get(0).nextUpdate()),
                "срок берётся по записи целевого сертификата, а не первой");
    }

    /**
     * Собирает ответ, в котором SingleResponse из {@code extra} стоит перед записью {@code base}.
     * Подпись остаётся от {@code base} и после правки недействительна: разбор её не проверяет,
     * а тест касается только выбора записи.
     */
    private static byte[] withSingleResponsesOf(byte[] base, byte[] extra) {
        byte[][] response = DerCodec.parseSequenceContents(base, 0);
        int[] explicitLen = DerCodec.decodeLength(response[1], 1);
        byte[][] responseBytes = DerCodec.parseSequenceContents(response[1], 1 + explicitLen[1]);
        byte[][] basic =
                DerCodec.parseSequenceContents(DerCodec.parseOctetString(responseBytes[1], 0), 0);
        byte[][] tbs = DerCodec.parseSequenceContents(basic[0], 0);

        // tbsResponseData: responderID, producedAt, responses (version DEFAULT v1 опущена)
        byte[] extraSingle = firstSingleResponse(extra);
        byte[] baseSingle = DerCodec.parseSequenceContents(tbs[2], 0)[0];
        tbs[2] = DerCodec.encodeSequence(extraSingle, baseSingle);

        basic[0] = DerCodec.encodeSequence(tbs);
        responseBytes[1] = DerCodec.encodeOctetString(DerCodec.encodeSequence(basic));
        return DerCodec.encodeSequence(
                response[0],
                DerCodec.encodeContextConstructed(0, DerCodec.encodeSequence(responseBytes)));
    }

    private static byte[] firstSingleResponse(byte[] ocspDer) {
        byte[][] response = DerCodec.parseSequenceContents(ocspDer, 0);
        int[] explicitLen = DerCodec.decodeLength(response[1], 1);
        byte[][] responseBytes = DerCodec.parseSequenceContents(response[1], 1 + explicitLen[1]);
        byte[][] basic =
                DerCodec.parseSequenceContents(DerCodec.parseOctetString(responseBytes[1], 0), 0);
        byte[][] tbs = DerCodec.parseSequenceContents(basic[0], 0);
        return DerCodec.parseSequenceContents(tbs[2], 0)[0];
    }
}
