package org.rssys.gost.jca.spi;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import org.rssys.gost.api.MgmCipher;
import org.rssys.gost.cipher.Kuznyechik;
import org.rssys.gost.cipher.ParametersWithIV;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.cipher.mode.Mgm;
import org.rssys.gost.util.AuthenticationException;
import org.rssys.gost.util.CryptoRandom;

/**
 * Реализация {@link CipherSpi} для аутентифицированного шифрования
 * Кузнечик-MGM (Multilinear Galois Mode, RFC 9058).
 *
 * <p>Регистрируется в провайдере как {@code "Kuznyechik/MGM/NoPadding"}.
 *
 * <p>Пример использования:
 * <pre>{@code
 * Cipher cipher = Cipher.getInstance("Kuznyechik/MGM/NoPadding", provider);
 *
 * // Шифрование
 * cipher.init(Cipher.ENCRYPT_MODE, key);        // ICN генерируется автоматически
 * cipher.updateAAD(aad);
 * byte[] ciphertext = cipher.doFinal(plaintext); // без ICN — только C || T
 * byte[] icn = cipher.getIV();                  // ICN для передачи получателю
 *
 * // Расшифрование
 * cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(icn));
 * cipher.updateAAD(aad);
 * byte[] plaintext = cipher.doFinal(ciphertext); // бросает AEADBadTagException при ошибке
 * }</pre>
 *
 * <p><b>Состояние после {@code doFinal}.</b> В обе стороны (шифрование, расшифрование, в том числе
 * после ошибки тега) шифр требует нового {@code init}: любой следующий {@code update} или
 * {@code doFinal} бросает {@link IllegalStateException}. Так проще и строже, чем сброс по контракту
 * JCA: у каждого сообщения свой ICN, у {@code Mgm} нет {@code reset()}, и так же ведёт себя
 * gost-engine (признак IV сбрасывается после тега в обе стороны). Для шифрования это ещё и
 * защита от повтора ICN под тем же ключом (RFC 9058 §4.1, §6). Явный повтор тоже отвергается:
 * {@code init} на шифрование с теми же ключом и ICN, на которых уже выдан шифртекст, бросает
 * {@link InvalidAlgorithmParameterException} (сгенерированный ICN входит в пару, помнится только
 * последняя использованная пара и отпечаток ключа). Проверка действует в пределах одного
 * экземпляра {@code Cipher}; уникальность ICN между экземплярами обеспечивает вызывающий.
 * Расшифрование не проверяется.
 *
 * <p><b>Буферизация.</b> SPI накапливает весь вход до {@code doFinal}: при расшифровании тег идёт
 * в конце, поэтому отделить его от шифртекста раньше нельзя. {@code update} ничего не возвращает,
 * а объём накопленного ограничен только памятью.
 *
 * <p><b>Пустые данные.</b> Шифрование и расшифрование с пустым открытым текстом и пустыми
 * ассоциированными данными одновременно отвергаются (RFC 9058 §6: тег перестаёт зависеть от
 * ICN): шифрование бросает {@link IllegalArgumentException}, расшифрование —
 * {@link AEADBadTagException}. Поэтому {@code CipherOutputStream.close()} на потоке, в который
 * ничего не записано и не передано AAD, бросает {@link IllegalArgumentException}: проверяемые
 * исключения {@code close()} проглатывает молча, а это нет. Нижний поток {@code close()} в таком
 * случае не закрывает, его вызывающий закрывает сам (например, в {@code finally}).
 */
public final class GostMgmCipherSpi extends AbstractGostCipherSpi {

    /**
     * Длина ICN для Кузнечика-MGM: 16 байт (127-битное значение, MSB=0, RFC 9058 §3).
     */
    private static final int ICN_LEN = MgmCipher.ICN_LEN;

    /** Размер тега в байтах. */
    private static final int TAG_LEN = MgmCipher.TAG_LEN;

    private Mgm mgm;

    /**
     * Защита от повтора пары (ключ, ICN) при шифровании: повтор ICN под тем же ключом ломает и
     * конфиденциальность, и аутентичность (RFC 9058 §4.1, §6). Помнится отпечаток ключа и последняя
     * использованная пара; расшифрование не проверяется. Действует в пределах экземпляра.
     */
    private final EncryptionReuseGuard reuseGuard =
            new EncryptionReuseGuard("ICN", "MGM encryption");

    private boolean forEncryption;
    private byte[] icn;
    private boolean initialized;

    /** {@code doFinal} уже выполнялся (любой исход): до нового {@code init} шифр не работает. */
    private boolean completed;

    /**
     * Накопленный ввод: при расшифровании тег стоит в конце, а открытый текст нельзя выдавать до
     * его проверки, поэтому сообщение целиком остаётся в памяти до {@code doFinal}.
     */
    private final GrowableInputBuffer inputBuffer =
            new GrowableInputBuffer(GrowableInputBuffer.MAX_SIZE - TAG_LEN);

    /**
     * Режим задаётся только как часть трансформации «Kuznyechik/MGM/NoPadding».
     * Отдельной установки не требует; любое значение кроме «MGM» отклоняется.
     */
    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        if (!"MGM".equalsIgnoreCase(mode)) {
            throw new NoSuchAlgorithmException(
                    "Only MGM mode is supported by this SPI, got: " + mode);
        }
    }

    /** Единственный поддерживаемый padding — NoPadding (MGM — потоковый AEAD). */
    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        if (!"NoPadding".equalsIgnoreCase(padding)) {
            throw new NoSuchPaddingException(
                    "Only NoPadding is supported for MGM, got: " + padding);
        }
    }

    /** @return размер блока Кузнечика, 16 байт. */
    @Override
    protected int engineGetBlockSize() {
        return 16;
    }

    /**
     * Возвращает ICN, использованный при последней инициализации.
     *
     * @return копию ICN или {@code null} если не инициализирован
     */
    @Override
    protected byte[] engineGetIV() {
        return (icn != null) ? Arrays.copyOf(icn, icn.length) : null;
    }

    /**
     * Возвращает ожидаемый размер выходного буфера.
     * <p>
     * При шифровании:  входные данные + TAG_LEN (тег добавляется в {@code doFinal}).
     * При расшифровании: max(0, ввод - TAG_LEN).
     */
    @Override
    protected int engineGetOutputSize(int inputLen) {
        // long: сумма размера и длины ввода, а потом тега, не должна переполнить int
        long total = (long) inputBuffer.size() + inputLen;
        long needed = forEncryption ? total + TAG_LEN : Math.max(0, total - TAG_LEN);
        return (int) Math.min(needed, Integer.MAX_VALUE);
    }

    /** @return {@code null} — отдельные AlgorithmParameters не используются. */
    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    @Override
    protected void engineInit(
            int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        boolean encrypting = isEncrypting(opmode);
        SymmetricKey keyParam = SymmetricKeyExtractor.forCipher(key);
        byte[] token = null;
        boolean tokenHandedOver = false;
        try {
            byte[] newIcn;
            if (params instanceof IvParameterSpec ivSpec) {
                newIcn = validatedIcnCopy(ivSpec.getIV());
            } else if (params instanceof GCMParameterSpec gcmSpec) {
                // Длина тега в формате пакета не переносится и всегда равна 128 битам: вызывающий,
                // запросивший 96 бит, молча получил бы 128 и считал бы тег усечённым.
                if (gcmSpec.getTLen() != TAG_LEN * Byte.SIZE) {
                    throw new InvalidAlgorithmParameterException(
                            "MGM supports only a "
                                    + TAG_LEN * Byte.SIZE
                                    + "-bit tag, got GCMParameterSpec tLen="
                                    + gcmSpec.getTLen());
                }
                newIcn = validatedIcnCopy(gcmSpec.getIV());
            } else if (params == null) {
                if (encrypting) {
                    // Генерируем случайный ICN при шифровании; MSB должен быть 0 (RFC 9058 §3)
                    newIcn = new byte[ICN_LEN];
                    (random != null ? random : CryptoRandom.INSTANCE).nextBytes(newIcn);
                    newIcn[0] &= 0x7F; // обеспечиваем MSB=0
                } else {
                    throw new InvalidAlgorithmParameterException(
                            "MGM decryption requires an ICN (IvParameterSpec with 16 bytes, MSB=0)");
                }
            } else {
                throw new InvalidAlgorithmParameterException(
                        "Unsupported parameter type: "
                                + params.getClass().getName()
                                + ". Use IvParameterSpec(16 bytes, MSB=0) or GCMParameterSpec");
            }

            // Повтор пары (ключ, ICN) отвергаем до любых изменений состояния SPI (сам
            // javax.crypto.Cipher при любом отказе init остаётся неинициализированным).
            // Сгенерированный ICN входит в пару: иначе обход цепочкой
            // init(ENC, key) -> getIV() -> init(ENC, key, тот же ICN).
            if (encrypting) {
                token = reuseGuard.prepare(keyParam, newIcn);
            }

            // Новый Mgm собираем до замены состояния: при ошибке init прежнее состояние не тронуто.
            Mgm newMgm = new Mgm(new Kuznyechik());
            try {
                newMgm.init(encrypting, new ParametersWithIV(keyParam, newIcn));
            } catch (RuntimeException e) {
                newMgm.destroy();
                throw e;
            }
            if (mgm != null) mgm.destroy();
            mgm = newMgm;
            forEncryption = encrypting;
            icn = newIcn;

            // Затираем прежний буфер (мог содержать plaintext/ciphertext) перед сбросом.
            inputBuffer.clear();
            if (encrypting) {
                reuseGuard.setPending(token);
                tokenHandedOver = true;
            } else {
                // Расшифрование не проверяется; использованная пара шифрования сохраняется
                reuseGuard.discardPending();
            }
            completed = false;
            initialized = true;
        } finally {
            // Копия ключа нужна только на время init: Mgm забрал байты в своё расписание,
            // а копия иначе остаётся в куче до сборки мусора.
            keyParam.destroy();
            if (!tokenHandedOver) {
                EncryptionReuseGuard.wipe(token);
            }
        }
    }

    /**
     * Добавляет ассоциированные данные.
     * Должен вызываться до первого {@code update}/{@code doFinal}.
     */
    @Override
    protected void engineUpdateAAD(byte[] src, int offset, int len) {
        checkInitialized();
        mgm.updateAAD(src, offset, len);
    }

    /**
     * Накапливает входные данные.
     * <p>
     * MGM обрабатывает данные только в {@code doFinal}, чтобы при расшифровании
     * корректно отделить тег (последние TAG_LEN байт) от шифртекста.
     */
    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        checkInitialized();
        inputBuffer.append(input, inputOffset, inputLen);
        return new byte[0]; // накопление — вывод пуст до doFinal
    }

    @Override
    protected int engineUpdate(
            byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException {
        engineUpdate(input, inputOffset, inputLen);
        return 0;
    }

    /**
     * Финализирует шифрование или расшифрование.
     * <p>
     * При шифровании: обрабатывает все накопленные данные, добавляет тег.
     * Выход: {@code [шифртекст] [тег (16 байт)]}.
     * <p>
     * При расшифровании: отделяет тег (последние 16 байт буфера),
     * расшифровывает шифртекст, верифицирует тег.
     * Бросает {@link AEADBadTagException} при несовпадении — данные не возвращаются.
     */
    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {
        checkInitialized();
        try {
            if (input != null && inputLen > 0) {
                inputBuffer.append(input, inputOffset, inputLen);
            }
            if (forEncryption) {
                byte[] encrypted = doFinalEncrypt();
                // Тег выдаётся всегда, поэтому пара использована, как только шифрование удалось;
                // отказ раньше (пустые P и A) пару не расходует
                reuseGuard.commit();
                return encrypted;
            } else {
                return doFinalDecrypt();
            }
        } finally {
            // Любой исход завершает сообщение: затираем буфер и ключевое состояние MGM (расписание
            // ключа и производные таблицы), а флаг completed не даёт использовать шифр до нового
            // init.
            inputBuffer.clear();
            mgm.destroy();
            // Неиспользованная ожидающая пара не нужна: новый init заведёт её заново
            reuseGuard.discardPending();
            completed = true;
        }
    }

    @Override
    protected int engineDoFinal(
            byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        checkInitialized();
        // Размер проверяем до обработки: иначе doFinal уже завершил бы MGM (флаг finished) и
        // очистил
        // буфер, и повтор вызова с достаточным буфером упал бы с «Already finished» вместо
        // результата.
        // Оценка размера точна в обе стороны.
        int needed = engineGetOutputSize(Math.max(inputLen, 0));
        if (needed > output.length - outputOffset) {
            throw new ShortBufferException("Output buffer too small: need " + needed + " bytes");
        }
        byte[] result = engineDoFinal(input, inputOffset, inputLen);
        System.arraycopy(result, 0, output, outputOffset, result.length);
        Arrays.fill(result, (byte) 0);
        return result.length;
    }

    /** Шифрует все накопленные данные и добавляет тег. */
    private byte[] doFinalEncrypt() {
        int ptLen = inputBuffer.size();
        byte[] out = new byte[ptLen + TAG_LEN];

        mgm.processBytes(inputBuffer.array(), 0, ptLen, out, 0);
        mgm.finishEncryption(out, ptLen);

        return out;
    }

    /**
     * Расшифровывает накопленные данные и верифицирует тег.
     * Тег — последние TAG_LEN байт буфера.
     */
    private byte[] doFinalDecrypt() throws BadPaddingException {
        if (inputBuffer.size() < TAG_LEN) {
            throw new AEADBadTagException(
                    "Input too short to contain MGM tag: need at least "
                            + TAG_LEN
                            + " bytes, got "
                            + inputBuffer.size());
        }

        int ctLen = inputBuffer.size() - TAG_LEN;
        byte[] plaintext = new byte[ctLen];
        if (ctLen > 0) {
            mgm.processBytes(inputBuffer.array(), 0, ctLen, plaintext, 0);
        }

        try {
            // Тег — последние TAG_LEN байт
            mgm.finishDecryption(inputBuffer.array(), ctLen);
        } catch (AuthenticationException e) {
            // Обнуляем непроверенный открытый текст перед выбросом исключения. Ключевое состояние
            // Mgm (mulTab, счётчики, аккумулятор) затирает finally в engineDoFinal.
            Arrays.fill(plaintext, (byte) 0);
            throw new AEADBadTagException("MGM authentication tag mismatch");
        }

        return plaintext;
    }

    /** Проверяет ICN и возвращает его копию. */
    private static byte[] validatedIcnCopy(byte[] iv) throws InvalidAlgorithmParameterException {
        validateIcn(iv);
        return Arrays.copyOf(iv, iv.length);
    }

    /**
     * Проверяет ICN: 16 байт, старший бит = 0 (RFC 9058 §3).
     */
    private static void validateIcn(byte[] iv) throws InvalidAlgorithmParameterException {
        if (iv == null || iv.length != ICN_LEN) {
            throw new InvalidAlgorithmParameterException(
                    "MGM ICN (IV) must be exactly "
                            + ICN_LEN
                            + " bytes (MSB=0), got "
                            + (iv == null ? "null" : iv.length));
        }
        if ((iv[0] & 0x80) != 0) {
            throw new InvalidAlgorithmParameterException(
                    "MGM ICN MSB (bit 127) must be 0 per RFC 9058 §3");
        }
    }

    private void checkInitialized() {
        if (!initialized) {
            throw new IllegalStateException("Cipher not initialized — call init() first");
        }
        if (completed) {
            throw new IllegalStateException(
                    "MGM operation completed — call init() with a new ICN before reuse");
        }
    }
}
