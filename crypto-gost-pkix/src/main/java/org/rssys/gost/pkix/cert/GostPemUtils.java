package org.rssys.gost.pkix.cert;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import org.rssys.gost.util.DerCodec;

/**
 * Утилиты кодирования / декодирования PEM-формата для сертификатов и ключей.
 *
 * <p>PEM (Privacy-Enhanced Mail) — Base64-кодировка DER с заголовками
 * {@code -----BEGIN ...-----} / {@code -----END ...-----}. Используется
 * для передачи сертификатов между системами, хранения в файлах
 * (nginx, Apache, Java truststore) и отладки.</p>
 *
 * <p>Поддерживает автоопределение формата (DER/PEM/PFX) по первому байту.</p>
 *
 * <p>Вынесен из {@link GostCertificate} для разделения ответственности
 * и выделения общих PEM-утилит.</p>
 *
 * @see GostCertificate
 */
public final class GostPemUtils {

    private static final java.util.regex.Pattern PEM_HEADER =
            java.util.regex.Pattern.compile("-----[A-Z ]+-----");
    private static final java.util.regex.Pattern WHITESPACE =
            java.util.regex.Pattern.compile("\\s");

    private GostPemUtils() {}

    /**
     * Декодирует PEM-формат (Base64 между заголовками) в DER-байты.
     *
     * <p>Вырезает любые PEM-заголовки {@code -----BEGIN ...-----} / {@code -----END ...-----}
     * и пробельные символы, декодирует оставшийся Base64.</p>
     *
     * @param pem байты PEM-данных (сертификат, ключ или любой PEM-блок)
     * @return DER-байты
     */
    public static byte[] pemToDer(byte[] pem) {
        String text = new String(pem, StandardCharsets.US_ASCII);
        String b64 = WHITESPACE.matcher(PEM_HEADER.matcher(text).replaceAll("")).replaceAll("");
        return Base64.getDecoder().decode(b64);
    }

    /**
     * Проверяет, являются ли данные PEM-форматом.
     *
     * <p>Дискриминатор: первый байт 0x2D (ASCII '-') — начало PEM-заголовка.</p>
     *
     * @param data проверяемые байты
     * @return true если данные начинаются с PEM-заголовка
     */
    public static boolean isPem(byte[] data) {
        return data != null && data.length > 0 && (data[0] & 0xFF) == 0x2D;
    }

    /**
     * Проверяет, являются ли данные PFX-контейнером (PKCS12).
     *
     * <p>Дискриминатор: внешний SEQUENCE, первый вложенный элемент — INTEGER 3
     * (версия PFX). Это надёжнее полного разбора — без лишних аллокаций.</p>
     *
     * @param data проверяемые байты
     * @return true если данные имеют структуру PFX
     */
    public static boolean isPkcs12(byte[] data) {
        if (data == null || data.length < 10) return false;
        if ((data[0] & 0xFF) != 0x30) return false;
        try {
            byte[][] outer = DerCodec.parseSequenceContents(data, 0);
            if (outer.length < 2) return false;
            BigInteger version = DerCodec.parseInteger(outer[0], 0);
            if (!version.equals(BigInteger.valueOf(3))) return false;
            // AuthSafe должен быть SEQUENCE (ContentInfo)
            return outer[1] != null && outer[1].length > 0 && (outer[1][0] & 0xFF) == 0x30;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Кодирует DER-байты в PEM-формат (Base64 с заголовками CERTIFICATE).
     *
     * <p>Результат содержит ровно один блок {@code -----BEGIN CERTIFICATE-----}
     * с разбивкой Base64 по 64 символа на строку.</p>
     *
     * @param der DER-байты для кодирования
     * @return PEM-строка (включая заголовки и переводы строк)
     */
    public static String toPem(byte[] der) {
        return toPem(der, "CERTIFICATE");
    }

    /**
     * Кодирует DER-байты в PEM-формат с произвольным label.
     *
     * <p>Позволяет кодировать не только сертификаты, но и CSR
     * ({@code "CERTIFICATE REQUEST"}), ключи и другие PEM-типы.</p>
     *
     * @param der   DER-байты для кодирования
     * @param label тип блока (CERTIFICATE, CERTIFICATE REQUEST, ...)
     * @return PEM-строка (включая заголовки и переводы строк)
     */
    public static String toPem(byte[] der, String label) {
        String b64 = Base64.getEncoder().encodeToString(der);
        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN ").append(label).append("-----\n");
        for (int i = 0; i < b64.length(); i += 64) {
            sb.append(b64, i, Math.min(i + 64, b64.length())).append('\n');
        }
        sb.append("-----END ").append(label).append("-----\n");
        return sb.toString();
    }

    /**
     * Декодирует PEM-файл с несколькими сертификатными блоками в список DER-байтов.
     *
     * <p>Обрабатывает файлы с несколькими блоками {@code -----BEGIN CERTIFICATE-----},
     * включая цепочки из PEM-файлов УЦ Минцифры.</p>
     *
     * @param pem PEM-байты, содержащие один или несколько сертификатов
     * @return список DER-байтов (порядок из файла)
     * @throws IllegalArgumentException если ни один блок не распознан
     */
    public static List<byte[]> decodePemBlocks(byte[] pem) {
        String text = new String(pem, StandardCharsets.US_ASCII);
        String[] blocks = text.split("-----BEGIN CERTIFICATE-----");
        List<byte[]> result = new ArrayList<>();
        for (String block : blocks) {
            int end = block.indexOf("-----END CERTIFICATE-----");
            if (end < 0) {
                continue;
            }
            String b64 = WHITESPACE.matcher(block.substring(0, end)).replaceAll("");
            if (b64.isEmpty()) {
                continue;
            }
            byte[] der = Base64.getDecoder().decode(b64);
            result.add(der);
        }
        if (result.isEmpty()) {
            throw new IllegalArgumentException("No valid PEM certificates found");
        }
        return result;
    }

    /**
     * Конкатенирует PEM-блоки в одну строку.
     *
     * @param pemBlocks список PEM-строк
     * @return конкатенированная PEM-строка
     */
    public static String chainToPem(List<String> pemBlocks) {
        StringBuilder sb = new StringBuilder();
        for (String block : pemBlocks) {
            sb.append(block);
        }
        return sb.toString();
    }
}
