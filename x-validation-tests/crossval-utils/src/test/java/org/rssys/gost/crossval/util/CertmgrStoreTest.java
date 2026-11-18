package org.rssys.gost.crossval.util;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Разбор ответов {@code certmgr} без КриптоПро: вместо него запускается скрипт, чьё поведение
 * задаёт файл режима. Проверяется то, что поддельное хранилище не покрывает: код возврата и
 * {@code ErrorCode} вместе, число сертификатов по разделителям блоков, перевод ошибки без X.
 */
@DisplayName("CertmgrStore: разбор ответов certmgr")
class CertmgrStoreTest {

    private static final byte[] KEY_ID = {0x0a, 0x0b};

    private static Path modeFile;
    private static String previousBinary;

    @BeforeAll
    static void installFakeCertmgr(@TempDir Path dir) throws IOException {
        modeFile = dir.resolve("mode");
        Path script = dir.resolve("certmgr");
        // Режим читается из файла: success, success-two, empty, fail-code, no-x, ok-nonzero-exit.
        // При -export пишет файл, указанный после -dest
        Files.writeString(
                script,
                """
                #!/bin/bash
                mode=$(cat "%s")
                dest=""
                for ((i=1;i<=$#;i++)); do
                  if [ "${!i}" = "-dest" ]; then j=$((i+1)); dest="${!j}"; fi
                done
                [ -n "$dest" ] && printf 'DER-BYTES' > "$dest"
                case "$mode" in
                  success) printf '1-------\\nИздатель : X\\n\\n[ErrorCode: 0x00000000]\\n'; exit 0;;
                  success-two) printf '1-------\\nA\\n2-------\\nB\\n\\n[ErrorCode: 0x00000000]\\n'; exit 0;;
                  empty) printf 'Список сертификатов пуст\\n\\n[ErrorCode: 0x8010002c]\\n'; exit 44;;
                  fail-code) printf 'oops\\n[ErrorCode: 0x80090008]\\n'; exit 0;;
                  no-x) printf 'cannot\\n[ErrorCode: 0x80090020]\\n'; exit 32;;
                  ok-nonzero-exit) printf '[ErrorCode: 0x00000000]\\n'; exit 7;;
                esac
                """
                        .formatted(modeFile));
        Files.setPosixFilePermissions(script, PosixFilePermissions.fromString("rwxr-xr-x"));
        previousBinary = System.getProperty("certmgr.binary");
        System.setProperty("certmgr.binary", script.toString());
        CryptoProChecker.resetCachedBinaries();
    }

    @AfterAll
    static void restoreBinary() {
        // Тест не должен влиять на другие классы: возвращаем свойство и сбрасываем запомненный путь
        if (previousBinary == null) {
            System.clearProperty("certmgr.binary");
        } else {
            System.setProperty("certmgr.binary", previousBinary);
        }
        CryptoProChecker.resetCachedBinaries();
    }

    private static CertmgrStore store(String mode) throws IOException {
        Files.writeString(modeFile, mode);
        return new CertmgrStore();
    }

    @Test
    @DisplayName("Число сертификатов считается по разделителям блоков")
    void countsBlocksBySeparators() throws Exception {
        assertEquals(1, store("success").countByKeyId(KEY_ID));
        assertEquals(2, store("success-two").countByKeyId(KEY_ID));
    }

    @Test
    @DisplayName("Пустой список (ErrorCode 0x8010002c, exit 44) - ноль сертификатов, не ошибка")
    void emptyListIsZero() throws Exception {
        assertEquals(0, store("empty").countByKeyId(KEY_ID));
    }

    @Test
    @DisplayName("Ненулевой ErrorCode при нулевом exit-коде - ошибка")
    void errorCodeAloneIsAFailure() {
        IOException e =
                assertThrows(IOException.class, () -> store("fail-code").install(new byte[] {1}));

        assertTrue(e.getMessage().contains("0x80090008"), "код в сообщении: " + e.getMessage());
    }

    @Test
    @DisplayName("Ненулевой exit-код при нулевом ErrorCode - тоже ошибка")
    void exitCodeAloneIsAFailure() {
        assertThrows(IOException.class, () -> store("ok-nonzero-exit").deleteByKeyId(KEY_ID));
    }

    @Test
    @DisplayName("0x80090020 переводится в сообщение об отсутствии доступа к X-сессии")
    void noXCodeIsTranslated() {
        IOException e =
                assertThrows(IOException.class, () -> store("no-x").install(new byte[] {1}));

        assertTrue(e.getMessage().contains("X session"), "сообщение: " + e.getMessage());
    }

    @Test
    @DisplayName("Экспорт возвращает байты файла, указанного в -dest")
    void exportReturnsDestFileBytes() throws Exception {
        assertArrayEquals("DER-BYTES".getBytes(), store("success").exportByKeyId(KEY_ID));
    }
}
