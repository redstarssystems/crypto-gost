package org.rssys.gost.jca.spi;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import org.rssys.gost.cipher.BlockCipher;
import org.rssys.gost.cipher.Kuznyechik;
import org.rssys.gost.cipher.ParametersWithIV;
import org.rssys.gost.cipher.StreamCipher;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.cipher.mode.Cbc;
import org.rssys.gost.cipher.mode.Cfb;
import org.rssys.gost.cipher.mode.Ctr;
import org.rssys.gost.cipher.mode.Ofb;
import org.rssys.gost.util.CryptoRandom;
import org.rssys.gost.util.ISO7816d4Padding;
import org.rssys.gost.util.Pkcs7Padding;

/**
 * Реализация {@link CipherSpi} для алгоритма шифрования Кузнечик (ГОСТ Р 34.12-2015)
 * <b>Важно:</b> JCE управляет буферизацией. Для потоковых режимов (CTR/CFB/OFB)
 * {@code engineUpdate} возвращает байты по мере поступления. Для CBC — блоками.
 *
 * <p><b>Безопасность (режим CTR):</b> при инициализации без параметров nonce
 * генерируется случайно и составляет всего 64 бита (блок счётчика по
 * ГОСТ Р 34.13-2015 §4.4 = IV(8 байт) ‖ counter(8 байт), младшая половина —
 * счётчик, поэтому расширить nonce нельзя). Безопасный предел — не более
 * ~2^16 сообщений на одном ключе. При его превышении растёт вероятность
 * коллизии nonce по «парадоксу дней рождения» (≈50% к ~2^32 сообщений):
 * совпадение nonce даёт одинаковый keystream (счётчик у обоих стартует с 0),
 * и XOR двух шифртекстов раскрывает открытый текст — потеря
 * конфиденциальности. Для больших объёмов передавайте явный уникальный nonce
 * через {@link IvParameterSpec} (например, монотонный счётчик) либо
 * используйте {@code Kuznyechik/CTR-ACPKM} (детерминированный UKM + секционная
 * смена ключа). Подробности — ADR-06 (crypto-gost-core/doc/adr/adr-06.md).
 *
 * <p><b>Состояние после {@code doFinal}.</b> Расшифрование возвращается в состояние после
 * {@code init} (тот же ключ и IV, как требует контракт JCA): повторное расшифрование не создаёт
 * новой утечки: если отправитель использовал один IV для двух сообщений, связь между их открытыми
 * текстами раскрыта независимо от дешифратора. Шифрование сознательно отклоняется от контракта:
 * после успешного {@code doFinal} любой {@code update}/{@code doFinal} бросает
 * {@link IllegalStateException} до нового {@code init}, потому что сброс на тот же IV повторил
 * бы IV под тем же ключом (в CTR и OFB совпала бы гамма и раскрылся XOR открытых текстов, в CFB —
 * XOR первых блоков и далее до первого различия, в CBC — общий префикс из целых блоков).
 * Явный повтор тоже отвергается: {@code init} на шифрование с теми же ключом и IV, на которых уже
 * выдан шифртекст, бросает {@link InvalidAlgorithmParameterException} во всех режимах (CTR, CFB,
 * OFB, CBC). Защита общая с {@code Kuznyechik/CTR-ACPKM} и
 * {@code Kuznyechik/MGM} ({@code EncryptionReuseGuard}): пара считается использованной, когда
 * выдан непустой шифртекст, помнится только последняя использованная пара (после A, затем B пара A
 * снова принимается) и отпечаток ключа, а не ключ; сгенерированный IV входит в пару. Проверка
 * действует в пределах одного экземпляра {@code Cipher}; уникальность IV между экземплярами
 * обеспечивает вызывающий, осознанное детерминированное шифрование (фиксированный IV в CBC)
 * возможно через новый экземпляр. Блокировка шифрования после {@code doFinal}
 * и сброс расшифрования совпадают с {@code Kuznyechik/CTR-ACPKM}, а {@code Kuznyechik/MGM}
 * требует нового {@code init} в обе стороны (у каждого сообщения свой ICN, а {@code Mgm} не
 * имеет {@code reset()}).
 *
 * <p><b>Отказ шифрования до обработки.</b> Если {@code doFinal} отвергает шифрование из-за длины,
 * не кратной блоку (CBC/NoPadding), накопленный вход отбрасывается и не восстанавливается: повтор
 * должен передать сообщение целиком. Шифр при этом остаётся пригодным, пока {@code update} не
 * пропускал блоки через регистр цепочки; иначе он требует нового {@code init}.
 *
 * <p><b>Пустой вход.</b> {@code doFinal()} расшифрования CBC без единого байта шифртекста
 * возвращает пустой результат (как SunJCE): иначе чтение пустого потока через
 * {@code CipherInputStream} завершалось бы ошибкой.
 *
 * <p><b>Padding.</b> Дополнение применимо только в CBC; для CTR/CFB/OFB оно отвергается
 * (при {@code setPadding}, если режим уже выбран, и при {@code init}), чтобы не создавать у
 * вызывающего ложной уверенности, что данные дополнены. Расшифрование всегда требует IV:
 * случайный IV дал бы гарантированный мусор без ошибки.
 *
 * <p><b>Буфер вывода и повтор после {@code ShortBufferException}.</b> Размер буфера проверяется
 * до обработки, поэтому повтор с достаточным буфером даёт верный результат во всех режимах, кроме
 * одного случая: CBC-расшифрование с padding в {@code doFinal}. Там точный размер известен только
 * после снятия padding, и если буфер не меньше минимума, но короче открытого текста, отказ приходит
 * уже после расшифрования. Если {@code update} ещё не пропускал блоки через шифр (расшифрование
 * одним вызовом), состояние восстанавливается и повтор с достаточным буфером даёт верный результат.
 * Иначе (регистр CBC сдвинут) состояние потеряно, и шифр требует нового {@code init}: любой
 * следующий вызов бросает {@link IllegalStateException}. Надёжнее выделять буфер по
 * {@code getOutputSize()}.
 */
public final class GostCipherSpi extends AbstractGostCipherSpi {

    private static final int BLOCK_SIZE = Kuznyechik.BLOCK_SIZE;

    private static final String MODE_CTR = "CTR";
    private static final String MODE_CBC = "CBC";
    private static final String MODE_CFB = "CFB";
    private static final String MODE_OFB = "OFB";

    private static final String PAD_NONE = "NoPadding";
    private static final String PAD_PKCS5 = "PKCS5Padding";
    private static final String PAD_PKCS7 = "PKCS7Padding";
    private static final String PAD_ISO = "ISO7816-4";

    /** Текущий режим шифрования. По умолчанию CTR. */
    private String mode = MODE_CTR;

    /** Текущий padding. По умолчанию NoPadding. */
    private String padding = PAD_NONE;

    /** Активный блочный шифр с режимом (Ctr/Cbc/Cfb/Ofb). */
    private BlockCipher cipher;

    /**
     * Тот же объект, что {@link #cipher}, в потоковых режимах (CTR/CFB/OFB); {@code null} для CBC.
     * Потоковые режимы сами хранят неполный блок гаммы между вызовами, поэтому входные данные
     * им передаются как есть, без накопления и добивания до блока.
     */
    private StreamCipher streamCipher;

    /**
     * Защита от повтора пары (ключ, IV) при шифровании во всех режимах: повтор IV под тем же ключом
     * повторяет гамму (CTR, OFB), первые блоки (CFB) или делает предсказуемым первый блок (CBC).
     * Помнится отпечаток ключа и последняя использованная пара; расшифрование не проверяется.
     * Действует в пределах экземпляра {@code Cipher}.
     */
    private final EncryptionReuseGuard reuseGuard = new EncryptionReuseGuard("IV", "encryption");

    /** Признак шифрования (true) или расшифрования (false). */
    private boolean forEncryption;

    /** IV, использованный при инициализации (для engineGetIV). */
    private byte[] currentIv;

    /** Буфер накопленных входных данных. Используется только в CBC: потоковые режимы буфера не держат. */
    private byte[] inputBuffer = new byte[0];

    /** Признак того, что шифр инициализирован. */
    private boolean initialized = false;

    /**
     * Причина, по которой шифр требует нового {@code init} (завершённое шифрование или потеря
     * состояния после поздней ошибки); {@code null}, пока шифр не использовался или исправен.
     * Сбрасывается успешным {@code init}.
     */
    private String reinitReason;

    /**
     * Режим выбран явно через {@code engineSetMode} (а не взят по умолчанию). Флаг нужен для прямого
     * вызова SPI: у {@code Cipher} нет публичных {@code setMode}/{@code setPadding}, а
     * {@code getInstance} всегда вызывает {@code engineSetMode} раньше {@code engineSetPadding}, но
     * при прямом вызове padding может быть задан раньше режима, и легальная последовательность
     * {@code setPadding("PKCS7Padding")} -> {@code setMode("CBC")} не должна отвергаться из-за
     * режима по умолчанию (CTR). Не удалять как «лишний».
     */
    private boolean modeExplicit = false;

    /**
     * {@code true}, если с момента {@code init} через шифр CBC прошёл хотя бы один блок
     * ({@code update} сдвинул регистр цепочки). Пока {@code false}, регистр равен IV, и шифр можно
     * вернуть в исходное состояние через {@code reset()}. Булев признак, а не счётчик: счётчик
     * {@code int} после 2^32 блоков (64 ГиБ без {@code doFinal}) снова стал бы нулём.
     */
    private boolean cbcRegisterMoved = false;

    /**
     * Устанавливает режим шифрования.
     *
     * @param modeStr CTR, CBC, CFB, OFB
     * @throws NoSuchAlgorithmException если режим не поддерживается
     */
    @Override
    protected void engineSetMode(String modeStr) throws NoSuchAlgorithmException {
        if (modeStr == null) {
            throw new NoSuchAlgorithmException("Mode must not be null");
        }
        String upper = modeStr.toUpperCase();
        if (!upper.equals(MODE_CTR)
                && !upper.equals(MODE_CBC)
                && !upper.equals(MODE_CFB)
                && !upper.equals(MODE_OFB)) {
            throw new NoSuchAlgorithmException(
                    "Unsupported mode: " + modeStr + ". Supported: CTR, CBC, CFB, OFB");
        }
        this.mode = upper;
        this.modeExplicit = true;
    }

    /**
     * Устанавливает схему дополнения.
     * <p>
     * Проверка совместимости с режимом нужна для прямого вызова SPI; через {@code
     * Cipher.getInstance} режим уже задан, поэтому несовместимая пара (padding для CTR/CFB/OFB)
     * отвергается здесь же, ещё в {@code getInstance}.
     *
     * @param paddingStr NoPadding, PKCS5Padding, PKCS7Padding, ISO7816-4
     * @throws NoSuchPaddingException если padding не поддерживается или неприменим к выбранному режиму
     */
    @Override
    protected void engineSetPadding(String paddingStr) throws NoSuchPaddingException {
        if (paddingStr == null) {
            throw new NoSuchPaddingException("Padding must not be null");
        }
        String norm = paddingStr.trim();
        if (norm.equalsIgnoreCase(PAD_NONE)
                || norm.equalsIgnoreCase(PAD_PKCS5)
                || norm.equalsIgnoreCase(PAD_PKCS7)
                || norm.equalsIgnoreCase(PAD_ISO)) {
            // Режим выбран раньше padding (так всегда делает getInstance): несовместимое сочетание
            // отвергаем сразу. При прямом вызове SPI с padding раньше режима то же правило
            // проверяется в engineInit.
            if (modeExplicit && !MODE_CBC.equals(mode) && !norm.equalsIgnoreCase(PAD_NONE)) {
                throw new NoSuchPaddingException(
                        "Padding " + norm + " is not applicable to the " + mode + " mode");
            }
            this.padding = norm;
        } else {
            throw new NoSuchPaddingException(
                    "Unsupported padding: "
                            + paddingStr
                            + ". Supported: NoPadding, PKCS5Padding, PKCS7Padding, ISO7816-4");
        }
    }

    /** @return 16 Для потоковых режимов JCE ожидает 1 или BLOCK_SIZE. */
    @Override
    protected int engineGetBlockSize() {
        return BLOCK_SIZE;
    }

    /**
     * Возвращает IV.
     *
     * @return копию IV или {@code null} если шифр не инициализирован
     */
    @Override
    protected byte[] engineGetIV() {
        return (currentIv != null) ? Arrays.copyOf(currentIv, currentIv.length) : null;
    }

    /**
     * Возвращает ожидаемый размер выходного буфера для {@code inputLen} байт входа.
     * <p>
     * Для потоковых режимов (CTR/CFB/OFB) вывод = ввод.
     * Для CBC с padding — выровнен до кратного блоку.
     */
    @Override
    protected int engineGetOutputSize(int inputLen) {
        int buffered = inputBuffer.length;
        int total = buffered + inputLen;
        if (!mode.equals(MODE_CBC)) {
            // Потоковые режимы: вывод совпадает с вводом
            return total;
        }
        if (forEncryption) {
            // При шифровании с padding: до следующего полного блока
            if (!isPaddingNone()) {
                return ((total / BLOCK_SIZE) + 1) * BLOCK_SIZE;
            }
            return (total / BLOCK_SIZE) * BLOCK_SIZE;
        } else {
            // При расшифровании: не меньше total (padding будет снят в doFinal)
            return total;
        }
    }

    /** @return {@code null} — отдельные AlgorithmParameters не поддерживаются */
    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    /**
     * Инициализирует шифр с ключом и параметрами алгоритма.
     * <p>
     * Принимает {@link IvParameterSpec} для IV. Если параметры {@code null}, IV генерируется
     * случайным образом через {@code random} только при шифровании; при расшифровании
     * {@link IvParameterSpec} обязателен (случайный IV дал бы мусор без ошибки).
     * <p>
     * Здесь же выполняется окончательная проверка padding и режима: сюда попадает прямой вызов SPI
     * с padding, заданным раньше режима.
     * <p>
     * Для CTR авто-nonce ограничен 64 битами и безопасен лишь до ~2^16
     * сообщений на ключ (см. Javadoc класса / ADR-06); для контроля над
     * уникальностью передавайте {@link IvParameterSpec} с явным значением.
     */
    @Override
    protected void engineInit(
            int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        boolean encrypting = isEncrypting(opmode);
        SymmetricKey keyParam = SymmetricKeyExtractor.forCipher(key);
        byte[] token = null;
        boolean tokenHandedOver = false;
        try {
            // Padding существует только в CBC; в потоковых режимах он молча не применялся бы, и
            // вызывающий считал бы данные дополненными. Проверка здесь, а не только в
            // engineSetPadding: при прямом вызове SPI padding может быть задан раньше режима.
            if (!MODE_CBC.equals(mode) && !isPaddingNone()) {
                throw new InvalidAlgorithmParameterException(
                        "Padding " + padding + " is not applicable to the " + mode + " mode");
            }

            byte[] iv;
            if (params instanceof IvParameterSpec) {
                iv = ((IvParameterSpec) params).getIV();
                validateIv(iv);
            } else if (params == null) {
                if (!encrypting) {
                    // Случайный IV при расшифровании гарантированно даёт мусор на выходе без
                    // ошибки.
                    throw new InvalidAlgorithmParameterException(
                            "IV is required for decryption (IvParameterSpec)");
                }
                // Генерируем случайный IV
                iv = generateIv(random != null ? random : CryptoRandom.INSTANCE);
            } else {
                throw new InvalidAlgorithmParameterException(
                        "Unsupported parameter type: "
                                + params.getClass().getName()
                                + ". Expected IvParameterSpec");
            }

            // Повтор пары (ключ, IV) отвергаем до любых изменений состояния SPI (сам
            // javax.crypto.Cipher при любом отказе init остаётся неинициализированным).
            // Сгенерированный IV входит в пару: иначе обход цепочкой
            // init(ENC, key) -> getIV() -> init(ENC, key, тот же IV).
            if (encrypting) {
                token = reuseGuard.prepare(keyParam, iv);
            }
            initCipher(keyParam, iv, encrypting);
            if (encrypting) {
                reuseGuard.setPending(token);
                tokenHandedOver = true;
            } else {
                // Расшифрование не проверяется; использованная пара шифрования сохраняется
                reuseGuard.discardPending();
            }
        } finally {
            // Копия ключа нужна только на время init: шифр забрал байты в своё расписание,
            // а копия иначе остаётся в куче до сборки мусора.
            keyParam.destroy();
            if (!tokenHandedOver) {
                EncryptionReuseGuard.wipe(token);
            }
        }
    }

    /**
     * Обрабатывает часть входных данных.
     * <p>
     * Для потоковых режимов (CTR/CFB/OFB) данные шифруются немедленно.
     * Для CBC данные накапливаются и шифруются полными блоками; при расшифровании с padding
     * последний блок удерживается до {@code doFinal}.
     */
    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        checkInitialized();

        if (streamCipher != null) {
            byte[] streamResult = processStream(input, inputOffset, inputLen);
            commitIfCiphertextIssued(streamResult.length);
            return streamResult;
        }

        appendToBuffer(input, inputOffset, inputLen);

        // CBC: обрабатываем только блоки, готовые к выдаче, остаток оставляем в буфере
        int processLen = cbcUpdateOutputLength(inputBuffer.length);
        if (processLen == 0) {
            return new byte[0];
        }
        byte[] result = processCbcBlocks(inputBuffer, 0, processLen);
        cbcRegisterMoved = true;
        commitIfCiphertextIssued(result.length);
        // Оставляем хвост в буфере
        byte[] tail = Arrays.copyOfRange(inputBuffer, processLen, inputBuffer.length);
        Arrays.fill(inputBuffer, (byte) 0);
        inputBuffer = tail;
        return result;
    }

    @Override
    protected int engineUpdate(
            byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException {
        checkInitialized();
        if (inputLen <= 0) {
            return 0;
        }
        // Размер проверяем до обработки: шифр уже сдвинул бы гамму/регистр, и повтор вызова
        // с достаточным буфером дал бы другой результат (контракт JCA: при ShortBufferException
        // состояние не меняется). Для CBC берём точное число полных блоков, а не
        // engineGetOutputSize:
        // та даёт верхнюю оценку (на блок больше) и вызвала бы ложный отказ на достаточном буфере.
        int produced =
                (streamCipher != null)
                        ? inputLen
                        : cbcUpdateOutputLength(inputBuffer.length + inputLen);
        if (produced > output.length - outputOffset) {
            throw new ShortBufferException("Output buffer too small: need " + produced + " bytes");
        }
        if (streamCipher != null && input != output) {
            // Горячий путь: гамма пишется прямо в буфер вызывающего, без промежуточного массива.
            streamCipher.processBytes(input, inputOffset, inputLen, output, outputOffset);
            commitIfCiphertextIssued(inputLen);
            return inputLen;
        }
        // input == output: области могут пересекаться, поэтому через промежуточный массив.
        byte[] result = engineUpdate(input, inputOffset, inputLen);
        System.arraycopy(result, 0, output, outputOffset, result.length);
        Arrays.fill(result, (byte) 0);
        return result.length;
    }

    /**
     * Завершает шифрование/расшифрование.
     * <p>
     * При шифровании CBC добавляет padding (если не NoPadding). При расшифровании CBC снимает
     * padding. После успешного шифрования шифр блокируется до нового {@code init}, после
     * расшифрования (в том числе неудачного) возвращается в состояние после {@code init}.
     */
    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {
        checkInitialized();

        boolean processed = false;
        try {
            byte[] result;
            if (streamCipher != null) {
                // Потоковые режимы: накопленного буфера нет, оставшиеся байты шифруются сразу
                result = processStream(input, inputOffset, inputLen);
            } else {
                if (input != null && inputLen > 0) {
                    appendToBuffer(input, inputOffset, inputLen);
                }
                result = doFinalCbc();
            }
            processed = true;
            commitIfCiphertextIssued(result.length);
            return result;
        } finally {
            finishOperation(processed);
        }
    }

    @Override
    protected int engineDoFinal(
            byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        checkInitialized();
        int needed = engineGetOutputSize(Math.max(inputLen, 0));
        int available = output.length - outputOffset;
        // Размер проверяем до обработки: иначе шифр уже сдвинул бы гамму/регистр и очистил буфер,
        // а повтор вызова с достаточным буфером дал бы другой результат. Исключение —
        // CBC-расшифрование с padding: точный размер открытого текста известен только после снятия
        // padding (оценка needed — верхняя граница, настоящий размер на 1..16 байт меньше).
        // Отказывать по верхней границе нельзя: вызывающий, выделивший буфер ровно под известный
        // открытый текст, получил бы ложную ошибку (SunJCE и прежняя версия такой буфер принимают).
        // Поэтому заранее отвергается только заведомо малый буфер, а точная проверка идёт после
        // расшифрования.
        boolean exactSizeKnownOnlyAfterUnpadding =
                streamCipher == null && !forEncryption && !isPaddingNone();
        int minimumNeeded =
                exactSizeKnownOnlyAfterUnpadding ? Math.max(0, needed - BLOCK_SIZE) : needed;
        if (minimumNeeded > available) {
            throw new ShortBufferException("Output buffer too small: need " + needed + " bytes");
        }
        // Пока update не пропустил через шифр ни одного блока, регистр цепочки равен IV, и
        // состояние
        // до этого вызова восстановимо: снимок накопленного шифртекста + reset() после
        // расшифрования.
        byte[] bufferBeforeCall =
                (exactSizeKnownOnlyAfterUnpadding && !cbcRegisterMoved)
                        ? inputBuffer.clone()
                        : null;
        byte[] result = engineDoFinal(input, inputOffset, inputLen);
        if (result.length > available) {
            Arrays.fill(result, (byte) 0);
            String message = "Output buffer too small: need " + (result.length) + " bytes";
            if (bufferBeforeCall != null) {
                // finishOperation уже вернул шифр в состояние после init; возвращаем и накопленный
                // шифртекст, чтобы повтор того же вызова с достаточным буфером дал верный
                // результат.
                inputBuffer = bufferBeforeCall;
                throw new ShortBufferException(message);
            }
            // После update регистр CBC сдвинут, и повтор вернул бы без ошибки данные,
            // расшифрованные
            // «с середины» цепочки: шифр блокируется до нового init, ключевое расписание
            // затирается.
            invalidateUntilReinit(
                    "Cipher state lost after ShortBufferException — call init() first");
            throw new ShortBufferException(message + "; init() is required before reuse");
        }
        if (bufferBeforeCall != null) {
            Arrays.fill(bufferBeforeCall, (byte) 0);
        }
        System.arraycopy(result, 0, output, outputOffset, result.length);
        Arrays.fill(result, (byte) 0);
        return result.length;
    }

    /**
     * Создаёт и инициализирует блочный шифр с нужным режимом.
     */
    private void initCipher(SymmetricKey keyParam, byte[] iv, boolean encrypting) {
        ParametersWithIV params = new ParametersWithIV(keyParam, iv);

        // Сначала собираем и инициализируем новый шифр, и только потом заменяем состояние: если
        // init
        // бросит, прежние cipher/streamCipher/initialized остаются согласованными друг с другом.
        BlockCipher newCipher;
        switch (mode) {
            case MODE_CTR:
                newCipher = new Ctr(new Kuznyechik());
                break;
            case MODE_CBC:
                newCipher = new Cbc(new Kuznyechik());
                break;
            case MODE_CFB:
                newCipher = new Cfb(new Kuznyechik());
                break;
            case MODE_OFB:
                newCipher = new Ofb(new Kuznyechik());
                break;
            default:
                throw new IllegalStateException("Unknown mode: " + mode);
        }
        try {
            newCipher.init(encrypting, params);
        } catch (RuntimeException e) {
            newCipher.destroy();
            throw e;
        }

        if (cipher != null) {
            cipher.destroy();
        }
        // Затираем прежний буфер (мог содержать plaintext/ciphertext) перед сбросом.
        Arrays.fill(this.inputBuffer, (byte) 0);
        this.inputBuffer = new byte[0];

        this.currentIv = Arrays.copyOf(iv, iv.length);
        this.forEncryption = encrypting;
        this.reinitReason = null;
        this.cbcRegisterMoved = false;
        this.cipher = newCipher;
        this.streamCipher = (newCipher instanceof StreamCipher) ? (StreamCipher) newCipher : null;
        this.initialized = true;
    }

    /**
     * Шифрует/расшифровывает байты в потоковых режимах (CTR/CFB/OFB) за один вызов
     * {@link StreamCipher#processBytes}.
     * <p>
     * Режим сам хранит состояние между вызовами (счётчик, регистр обратной связи, остаток гаммы
     * неполного блока), поэтому нарезка входа на порции не влияет на результат: шифртекст всегда
     * совпадает с шифртекстом, полученным одним куском (ГОСТ Р 34.13-2015, CFB и OFB с s = n).
     * Нельзя прогонять неполный хвост как отдельный блок: регистр CFB получил бы «лишние» байты
     * гаммы, а OFB потерял бы остаток текущего блока гаммы.
     */
    private byte[] processStream(byte[] data, int offset, int len) {
        if (data == null || len <= 0) {
            return new byte[0];
        }
        byte[] out = new byte[len];
        streamCipher.processBytes(data, offset, len, out, 0);
        return out;
    }

    /**
     * Сколько байт CBC отдаёт из {@code update} при {@code totalBuffered} накопленных байтах.
     * <p>
     * При расшифровании с padding последний блок шифртекста нельзя выдавать до {@code doFinal}:
     * в нём может лежать дополнение, которое снимается только там. Поэтому всегда удерживается
     * от 1 до {@code BLOCK_SIZE} последних байт (включая полный последний блок). Иначе дополнение
     * попало бы в открытый текст, а {@code doFinal} получил бы пустой остаток. Во всех остальных
     * случаях выдаются все полные блоки.
     */
    private int cbcUpdateOutputLength(int totalBuffered) {
        if (totalBuffered == 0) {
            return 0;
        }
        boolean holdLastBlock = !forEncryption && !isPaddingNone();
        int blocks = (holdLastBlock ? totalBuffered - 1 : totalBuffered) / BLOCK_SIZE;
        return blocks * BLOCK_SIZE;
    }

    /**
     * Обрабатывает полные блоки CBC (только кратные BLOCK_SIZE).
     */
    private byte[] processCbcBlocks(byte[] data, int offset, int len) {
        byte[] out = new byte[len];
        for (int pos = 0; pos < len; pos += BLOCK_SIZE) {
            cipher.processBlock(data, offset + pos, out, pos);
        }
        return out;
    }

    /**
     * Завершает CBC с обработкой padding.
     */
    private byte[] doFinalCbc() throws IllegalBlockSizeException, BadPaddingException {
        if (forEncryption) {
            return doFinalCbcEncrypt();
        } else {
            return doFinalCbcDecrypt();
        }
    }

    private byte[] doFinalCbcEncrypt() throws IllegalBlockSizeException {
        byte[] paddedData;
        if (isPaddingNone()) {
            if (inputBuffer.length % BLOCK_SIZE != 0) {
                throw new IllegalBlockSizeException(
                        "CBC/NoPadding requires data length to be a multiple of "
                                + BLOCK_SIZE
                                + ", got "
                                + inputBuffer.length);
            }
            paddedData = inputBuffer;
        } else if (isPkcs5OrPkcs7()) {
            paddedData = Pkcs7Padding.pad(inputBuffer, BLOCK_SIZE);
        } else {
            // ISO7816-4
            paddedData = ISO7816d4Padding.pad(inputBuffer, BLOCK_SIZE);
        }
        try {
            return processCbcBlocks(paddedData, 0, paddedData.length);
        } finally {
            if (paddedData != inputBuffer) {
                Arrays.fill(paddedData, (byte) 0);
            }
        }
    }

    private byte[] doFinalCbcDecrypt() throws IllegalBlockSizeException, BadPaddingException {
        if (inputBuffer.length % BLOCK_SIZE != 0) {
            throw new IllegalBlockSizeException(
                    "CBC ciphertext length must be a multiple of "
                            + BLOCK_SIZE
                            + ", got "
                            + inputBuffer.length);
        }
        if (inputBuffer.length == 0) {
            return new byte[0];
        }
        byte[] decrypted = processCbcBlocks(inputBuffer, 0, inputBuffer.length);
        if (isPaddingNone()) {
            return decrypted;
        }
        try {
            if (isPkcs5OrPkcs7()) {
                return Pkcs7Padding.unpad(decrypted, BLOCK_SIZE);
            } else {
                // ISO7816-4
                return ISO7816d4Padding.unpad(decrypted, BLOCK_SIZE);
            }
        } catch (IllegalArgumentException e) {
            // Оба класса дополнения сообщают об испорченном дополнении IllegalArgumentException
            throw new BadPaddingException("Invalid padding");
        } finally {
            // Расшифрованный текст с padding — промежуточный; результат уже скопирован.
            Arrays.fill(decrypted, (byte) 0);
        }
    }

    /** Добавляет данные в конец внутреннего буфера. */
    private void appendToBuffer(byte[] input, int offset, int len) {
        if (len <= 0) return;
        byte[] newBuf = new byte[inputBuffer.length + len];
        System.arraycopy(inputBuffer, 0, newBuf, 0, inputBuffer.length);
        System.arraycopy(input, offset, newBuf, inputBuffer.length, len);
        Arrays.fill(inputBuffer, (byte) 0);
        inputBuffer = newBuf;
    }

    /** Генерирует случайный IV нужной длины для текущего режима.
     * <p>
     * Для CTR это 64-битный nonce (BLOCK_SIZE/2 = 8 байт): при > ~2^16
     * сообщений на одном ключе возникает birthday-риск коллизии nonce
     * (повтор keystream -> раскрытие plaintext); см. Javadoc класса и ADR-06. */
    private byte[] generateIv(SecureRandom random) {
        int ivLen = mode.equals(MODE_CTR) ? BLOCK_SIZE / 2 : BLOCK_SIZE;
        byte[] iv = new byte[ivLen];
        random.nextBytes(iv);
        return iv;
    }

    /**
     * Проверяет корректность IV для текущего режима: для CTR ровно {@code BLOCK_SIZE / 2} байт, для
     * CBC, CFB и OFB длина кратна блоку (m = n·z, ГОСТ Р 34.13-2015; контрольные примеры стандарта
     * используют z = 2).
     *
     * @throws InvalidAlgorithmParameterException если длина IV неверна
     */
    private void validateIv(byte[] iv) throws InvalidAlgorithmParameterException {
        if (iv == null) {
            throw new InvalidAlgorithmParameterException("IV must not be null");
        }
        boolean valid;
        String expected;
        if (mode.equals(MODE_CTR)) {
            valid = iv.length == BLOCK_SIZE / 2;
            expected = "exactly " + BLOCK_SIZE / 2;
        } else {
            valid = iv.length > 0 && iv.length % BLOCK_SIZE == 0;
            expected = "a positive multiple of " + BLOCK_SIZE;
        }
        if (!valid) {
            throw new InvalidAlgorithmParameterException(
                    "Invalid IV length for "
                            + mode
                            + ": expected "
                            + expected
                            + " bytes, got "
                            + iv.length);
        }
    }

    private void checkInitialized() {
        if (!initialized) {
            throw new IllegalStateException(
                    reinitReason != null
                            ? reinitReason
                            : "Cipher not initialized — call init() first");
        }
    }

    /**
     * Завершает операцию {@code doFinal}.
     * <p>
     * Расшифрование (успешное или нет) возвращается в состояние после {@code init}: тот же ключ и
     * IV, как требует контракт JCA; повторное расшифрование не создаёт новой утечки (если
     * отправитель использовал один IV для двух сообщений, связь между их открытыми текстами
     * раскрыта независимо от дешифратора). Шифрование после успешного завершения блокируется до
     * нового {@code init}: сброс на тот же IV повторил бы IV под тем же ключом (CTR, OFB — та же
     * гамма; CFB — совпадение первых блоков; CBC — общий префикс из целых блоков).
     * <p>
     * Если шифрование отвергнуто до обработки (CBC, длина не кратна блоку), гамма не выдавалась:
     * накопленный вход отбрасывается, и шифр остаётся пригодным, пока {@code update} не пропускал
     * блоки через регистр цепочки. Во всех остальных случаях сбоя (регистр уже сдвинут или
     * состояние потокового режима неизвестно) шифр блокируется до нового {@code init}.
     */
    private void finishOperation(boolean processed) {
        if (forEncryption) {
            if (processed) {
                invalidateUntilReinit(
                        "Encryption completed — call init() with a new IV before reuse");
            } else if (streamCipher == null && !cbcRegisterMoved) {
                Arrays.fill(inputBuffer, (byte) 0);
                inputBuffer = new byte[0];
            } else {
                invalidateUntilReinit("Cipher state lost after failed doFinal — call init() first");
            }
            return;
        }
        // Затираем накопленный шифртекст и возвращаем шифр в начальное состояние.
        Arrays.fill(inputBuffer, (byte) 0);
        inputBuffer = new byte[0];
        cbcRegisterMoved = false;
        cipher.reset();
    }

    /**
     * Переводит шифр в неинициализированное состояние с затиранием ключевого расписания и буфера.
     * Вызывается, когда продолжение невозможно (шифрование завершено) или дало бы молча неверный
     * результат (состояние потеряно). {@code currentIv} сохраняется: {@code getIV()} после
     * шифрования остаётся доступным.
     */
    private void invalidateUntilReinit(String reason) {
        if (cipher != null) {
            cipher.destroy();
        }
        // Ожидающая пара не нужна: новый init заведёт её заново; использованная сохраняется
        reuseGuard.discardPending();
        Arrays.fill(inputBuffer, (byte) 0);
        inputBuffer = new byte[0];
        // Ссылки на уничтоженные объекты обнуляются, чтобы инвариант «нет initialized -> нет шифра»
        // был виден в коде, а не только через checkInitialized().
        cipher = null;
        streamCipher = null;
        initialized = false;
        reinitReason = reason;
    }

    /**
     * Фиксирует пару (ключ, IV) как использованную, когда непустой шифртекст выдан вызывающему.
     * Пустой результат (например, CTR с пустым сообщением) гамму не расходует, пара остаётся
     * ожидающей.
     */
    private void commitIfCiphertextIssued(int issuedLength) {
        if (forEncryption && issuedLength > 0) {
            reuseGuard.commit();
        }
    }

    private boolean isPaddingNone() {
        return padding.equalsIgnoreCase(PAD_NONE);
    }

    private boolean isPkcs5OrPkcs7() {
        return padding.equalsIgnoreCase(PAD_PKCS5) || padding.equalsIgnoreCase(PAD_PKCS7);
    }
}
