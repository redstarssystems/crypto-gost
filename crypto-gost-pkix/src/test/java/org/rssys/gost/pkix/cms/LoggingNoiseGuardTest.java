package org.rssys.gost.pkix.cms;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostPkcs12Loader;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;

/**
 * Страж шума в журнале: штатные операции (подпись, проверка, шифрование, расшифрование, загрузка
 * PFX) не пишут записей INFO и выше. Успех операции не событие; INFO на каждую подпись или
 * расшифрование попадал бы в консоль сервера и в logcat Android.
 */
@DisplayName("Журнал: штатные операции не пишут INFO и выше")
class LoggingNoiseGuardTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static final char[] RFC_PFX_PASSWORD = "Пароль для PFX".toCharArray();
    private static final byte[] DATA = "содержимое".getBytes(StandardCharsets.UTF_8);

    /** Родитель логгеров пакетов cms и cert: записи дочерних доходят до его обработчика. */
    private static final String PKIX_LOGGER = "org.rssys.gost.pkix";

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

    // Сильная ссылка: JUL хранит логгеры слабо, и без неё обработчик мог бы пропасть вместе с ним
    private Logger pkixLogger;
    private CollectingHandler handler;
    private Level savedLevel;
    private boolean savedUseParentHandlers;

    @BeforeEach
    void attachHandler() {
        pkixLogger = Logger.getLogger(PKIX_LOGGER);
        savedLevel = pkixLogger.getLevel();
        savedUseParentHandlers = pkixLogger.getUseParentHandlers();
        handler = new CollectingHandler();
        handler.setLevel(Level.ALL);
        pkixLogger.addHandler(handler);
        // Консоль не засоряем, если запись всё же появится
        pkixLogger.setUseParentHandlers(false);
        pkixLogger.setLevel(Level.ALL);
    }

    @AfterEach
    void detachHandler() {
        // Возвращаем всё как было, чтобы не влиять на соседние тесты
        pkixLogger.removeHandler(handler);
        pkixLogger.setLevel(savedLevel);
        pkixLogger.setUseParentHandlers(savedUseParentHandlers);
    }

    private List<LogRecord> recordsAtOrAbove(Level threshold) {
        return handler.records.stream()
                .filter(r -> r.getLevel().intValue() >= threshold.intValue())
                .toList();
    }

    @Test
    @DisplayName(
            "Подпись, проверка, шифрование (ktri и kari) и расшифрование: ни одной записи INFO")
    void cmsOperationsAreQuietAtInfo() throws Exception {
        KeyPair signerKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate signerCert =
                CmsTestUtils.createSelfSignedCert(signerKp.getPrivate(), signerKp.getPublic());
        KeyPair recipientKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate recipientCert =
                CmsTestUtils.createSelfSignedCert(
                        recipientKp.getPrivate(), recipientKp.getPublic());

        byte[] signed =
                CmsSignedDataBuilder.create()
                        .data(DATA)
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .build();
        CmsSignedDataVerifier.verify(
                signed,
                VerifyOptions.trusting(
                        TrustAnchors.ofCertificates(signerCert),
                        SignerSelection.ANY,
                        Revocation.none()));

        for (boolean kari : new boolean[] {false, true}) {
            CmsEnvelopedDataBuilder builder =
                    kari ? CmsEnvelopedDataBuilder.createKari() : CmsEnvelopedDataBuilder.create();
            byte[] enveloped = builder.data(DATA).addRecipient(recipientCert).build();
            assertArrayEquals(
                    DATA,
                    CmsEnvelopedDataDecryptor.decrypt(
                            enveloped, recipientKp.getPrivate(), recipientCert),
                    "расшифрованное содержимое должно совпасть с исходным");
        }

        assertTrue(
                recordsAtOrAbove(Level.INFO).isEmpty(),
                "штатные операции CMS не должны писать INFO и выше, записано: "
                        + recordsAtOrAbove(Level.INFO).stream()
                                .map(LogRecord::getMessage)
                                .toList());
        // Страж не должен быть пустышкой: подробности на уровне DEBUG (FINE) по-прежнему пишутся
        assertTrue(
                handler.records.stream().anyMatch(r -> r.getLevel().equals(Level.FINE)),
                "диагностика на уровне DEBUG должна сохраняться");
    }

    @Test
    @DisplayName("Загрузка PFX (RFC 9548 A.2): ни одной записи INFO")
    void pfxLoadIsQuietAtInfo() throws IOException {
        byte[] pfx;
        try (InputStream in = getClass().getResourceAsStream("/rfc9548/a2.pfx")) {
            assertNotNull(in, "не найден ресурс a2.pfx");
            pfx = in.readAllBytes();
        }
        GostPkcs12Loader.Result loaded =
                GostPkcs12Loader.load(pfx, RFC_PFX_PASSWORD.clone(), false, 1);
        if (loaded.getPrivateKey() != null) {
            loaded.getPrivateKey().destroy();
        }

        assertTrue(
                recordsAtOrAbove(Level.INFO).isEmpty(),
                "загрузка PFX не должна писать INFO и выше, записано: "
                        + recordsAtOrAbove(Level.INFO).stream()
                                .map(LogRecord::getMessage)
                                .toList());
        assertTrue(
                handler.records.stream().anyMatch(r -> r.getLevel().equals(Level.FINE)),
                "диагностика загрузки на уровне DEBUG должна сохраняться");
    }
}
