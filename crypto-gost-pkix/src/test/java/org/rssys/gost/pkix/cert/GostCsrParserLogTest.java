package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.Digest;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.signature.ECParameters;

/**
 * Журнал при провале proof-of-possession запроса на сертификат: в предупреждении нет DN
 * заявителя (в нём ФИО, СНИЛС, ИНН), вместо него отпечаток открытого ключа; усечённый DN пишется
 * на уровне DEBUG.
 */
@DisplayName("GostCsrParser: журнал при отказе проверки подписи запроса")
class GostCsrParserLogTest {

    private static final String LOGGER_NAME = "org.rssys.gost.pkix.cert.GostCsrParser";
    private static final String APPLICANT_NAME = "Иванов Иван Иванович";

    private static final class CollectingHandler extends Handler {
        final List<LogRecord> records = new ArrayList<>();

        @Override
        public void publish(LogRecord record) {
            records.add(record);
        }

        @Override
        public void flush() {}

        @Override
        public void close() {}
    }

    // Сильная ссылка: JUL хранит логгеры слабо, без неё обработчик мог бы пропасть вместе с ним
    private Logger logger;
    private CollectingHandler handler;
    private Level savedLevel;
    private boolean savedUseParentHandlers;

    @BeforeEach
    void attachHandler() {
        logger = Logger.getLogger(LOGGER_NAME);
        savedLevel = logger.getLevel();
        savedUseParentHandlers = logger.getUseParentHandlers();
        handler = new CollectingHandler();
        handler.setLevel(Level.ALL);
        logger.addHandler(handler);
        logger.setUseParentHandlers(false);
        logger.setLevel(Level.ALL);
    }

    @AfterEach
    void detachHandler() {
        logger.removeHandler(handler);
        logger.setLevel(savedLevel);
        logger.setUseParentHandlers(savedUseParentHandlers);
    }

    /** Запрос с испорченной подписью: последний байт DER это последний байт значения подписи. */
    private static GostCsrParser csrWithBrokenSignature() {
        KeyPair kp = KeyGenerator.generateKeyPair(ECParameters.tc26a256());
        byte[] csr =
                GostCsrBuilder.create("CN=" + APPLICANT_NAME + ",C=RU", kp.getPublic())
                        .sign(kp.getPrivate());
        csr[csr.length - 1] ^= 0x01;
        return GostCsrParser.fromDer(csr);
    }

    @Test
    @DisplayName("Отказ проверки: WARNING с отпечатком ключа и без DN, DN усечённым на DEBUG")
    void warningHasFingerprintAndNoSubject() {
        GostCsrParser parsed = csrWithBrokenSignature();

        assertFalse(parsed.verifySelf(), "запрос с испорченной подписью не должен проходить");

        List<LogRecord> warnings =
                handler.records.stream().filter(r -> r.getLevel().equals(Level.WARNING)).toList();
        assertEquals(1, warnings.size(), "ровно одно предупреждение об отказе проверки");
        LogRecord warning = warnings.get(0);
        String warningText = warning.getMessage() + " " + Arrays.toString(warning.getParameters());
        assertFalse(
                warningText.contains(APPLICANT_NAME) || warningText.contains("CN="),
                "в предупреждении не должно быть DN заявителя: " + warningText);
        String fingerprint = String.valueOf(warning.getParameters()[0]);
        assertTrue(
                fingerprint.matches("[0-9a-f]{16}"),
                "отпечаток ключа: 8 байт в шестнадцатеричной записи, получено " + fingerprint);

        assertTrue(
                handler.records.stream()
                        .anyMatch(
                                r ->
                                        r.getLevel().equals(Level.FINE)
                                                && String.valueOf(r.getParameters()[0])
                                                        .contains(APPLICANT_NAME)),
                "DN заявителя должен быть доступен на уровне DEBUG");
    }

    @Test
    @DisplayName("Отпечаток: первые 8 байт Стрибога-256 от DER SubjectPublicKeyInfo ключа запроса")
    void fingerprintMatchesIndependentlyComputedValue() {
        KeyPair kp = KeyGenerator.generateKeyPair(ECParameters.tc26a256());
        byte[] csr =
                GostCsrBuilder.create("CN=" + APPLICANT_NAME + ",C=RU", kp.getPublic())
                        .sign(kp.getPrivate());
        csr[csr.length - 1] ^= 0x01;

        assertFalse(GostCsrParser.fromDer(csr).verifySelf(), "подпись испорчена");

        // Значение считается независимо от парсера: из ключа, а не из байтов запроса
        byte[] spki = GostDerCodec.encodePublicKey(kp.getPublic());
        String expected = HexFormat.of().formatHex(Digest.digest256(spki), 0, 8);
        String actual =
                String.valueOf(
                        handler.records.stream()
                                .filter(r -> r.getLevel().equals(Level.WARNING))
                                .findFirst()
                                .orElseThrow()
                                .getParameters()[0]);
        assertEquals(expected, actual, "отпечаток должен совпасть с независимо посчитанным");
    }

    @Test
    @DisplayName("Разные ключи при одинаковом DN дают разные отпечатки: считается ключ, а не DN")
    void differentKeysSameSubjectGiveDifferentFingerprints() {
        for (int i = 0; i < 2; i++) {
            KeyPair kp = KeyGenerator.generateKeyPair(ECParameters.tc26a256());
            byte[] csr =
                    GostCsrBuilder.create("CN=" + APPLICANT_NAME + ",C=RU", kp.getPublic())
                            .sign(kp.getPrivate());
            csr[csr.length - 1] ^= 0x01;
            assertFalse(GostCsrParser.fromDer(csr).verifySelf(), "подпись испорчена");
        }
        List<String> fingerprints =
                handler.records.stream()
                        .filter(r -> r.getLevel().equals(Level.WARNING))
                        .map(r -> String.valueOf(r.getParameters()[0]))
                        .toList();
        assertEquals(2, fingerprints.size(), "два предупреждения на два запроса");
        assertFalse(
                fingerprints.get(0).equals(fingerprints.get(1)),
                "запросы с разными ключами и одинаковым DN должны различаться отпечатками");
    }

    @Test
    @DisplayName("Отпечаток ключа одинаков для одного запроса и не зависит от вызова")
    void fingerprintIsStable() {
        GostCsrParser parsed = csrWithBrokenSignature();
        assertFalse(parsed.verifySelf(), "первая проверка");
        assertFalse(parsed.verifySelf(), "вторая проверка");
        List<String> fingerprints =
                handler.records.stream()
                        .filter(r -> r.getLevel().equals(Level.WARNING))
                        .map(r -> String.valueOf(r.getParameters()[0]))
                        .toList();
        assertEquals(2, fingerprints.size(), "два предупреждения на две проверки");
        assertEquals(fingerprints.get(0), fingerprints.get(1), "отпечаток должен совпадать");
    }
}
