package org.rssys.gost.cipher.mode;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import org.rssys.gost.cipher.CipherParameters;
import org.rssys.gost.cipher.Kuznyechik;
import org.rssys.gost.cipher.ParametersWithIV;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.kdf.KdfTreeGostR3411_2012_256;
import org.rssys.gost.mac.Cmac;
import org.rssys.gost.mac.Mac;
import org.rssys.gost.util.AuthenticationException;

/**
 * Режим шифрования для OID {@code id-gostr3412-2015-kuznyechik-ctracpkm}
 * (RFC 9337 §7.3, схема PBES2).
 * <p>
 * Два варианта:
 * <ul>
 *   <li><b>Без OMAC</b> ({@code id-gostr3412-2015-kuznyechik-ctracpkm}):
 *       ГОСТ Р 34.13-2015 CTR с S' = ukm[0..7]. Ключ = DK.</li>
 *   <li><b>С OMAC</b> ({@code id-gostr3412-2015-kuznyechik-ctracpkm-omac}):
 *       KDF_TREE(DK, "kdf tree", ukm[8..15]) -> K(1)||K(2). Схема RFC 9337 §5.1.1:
 *       CMAC с ключом K(2) считается по <b>открытому</b> тексту M, затем {@code M ‖ MAC}
 *       шифруется одним потоком CTR-ACPKM с ключом K(1). Тег шифруется продолжением
 *       того же потока (в том числе после смены ключа ACPKM) и в CMAC не попадает.</li>
 * </ul>
 * Симметричен: encrypt = decrypt для CTR-части.
 * <p>
 * Секционная смена ключа ACPKM выполняется каждые {@code sectionSize} байт
 * (Р 1323565.1.017-2018, RFC 8645 §6.2.2). Размер секции задаётся при
 * конструировании через константы {@link AcpkmSectionSize}.
 * {@code sectionSize} обязан быть кратен размеру блока (16 байт).
 */
public final class CtrAcpkmMode {

    private static final int BLOCK_SIZE = 16;
    private static final int UKM_LEN = 16;
    private static final int IV_LEN = 8;
    private static final int KEY_LEN = 32;

    /** Размер CMAC-тега для Кузнечика (128 бит). */
    private static final int MAC_TAG_LEN = 16;

    private static final byte[] KDF_TREE_LABEL = "kdf tree".getBytes(StandardCharsets.US_ASCII);

    /**
     * Константа ACPKM_D_2018 — первые 256 бит D (RFC 8645).
     * Используется для секционной смены ключа: K' = E_K(D[0..15]) || E_K(D[16..31]).
     */
    private static final byte[] ACPKM_D_2018 = {
        (byte) 0x80, (byte) 0x81, (byte) 0x82, (byte) 0x83,
        (byte) 0x84, (byte) 0x85, (byte) 0x86, (byte) 0x87,
        (byte) 0x88, (byte) 0x89, (byte) 0x8a, (byte) 0x8b,
        (byte) 0x8c, (byte) 0x8d, (byte) 0x8e, (byte) 0x8f,
        (byte) 0x90, (byte) 0x91, (byte) 0x92, (byte) 0x93,
        (byte) 0x94, (byte) 0x95, (byte) 0x96, (byte) 0x97,
        (byte) 0x98, (byte) 0x99, (byte) 0x9a, (byte) 0x9b,
        (byte) 0x9c, (byte) 0x9d, (byte) 0x9e, (byte) 0x9f
    };

    private final Kuznyechik cipher;
    private final boolean useOmac;
    private final int sectionSize;

    private byte[] ctr = new byte[BLOCK_SIZE];
    private byte[] gammaBuf = new byte[BLOCK_SIZE];
    private int byteCount;
    private int processedBytes;

    private Mac mac;

    /**
     * Ключ нулевой секции (DK или K(1)). Нужен {@link #reset()}: после ACPKM-смены ключа
     * в {@code cipher} лежит уже производный ключ, а возврат в начальное состояние
     * обязан вернуть именно исходный.
     */
    private byte[] initialKey;

    /** MAC финализирован: дальнейшая обработка данных сделала бы тег недостоверным. */
    private boolean finished;

    private boolean initialized;
    private boolean forEncryption;

    /**
     * Создаёт экземпляр с размером секции по умолчанию (4096 байт).
     *
     * @param cipher  экземпляр Кузнечика
     * @param useOmac {@code true} — OMAC-вариант
     */
    public CtrAcpkmMode(Kuznyechik cipher, boolean useOmac) {
        this(cipher, useOmac, AcpkmSectionSize.DEFAULT);
    }

    /**
     * Создаёт экземпляр с заданным размером секции ACPKM.
     *
     * @param cipher      экземпляр Кузнечика
     * @param useOmac     {@code true} — OMAC-вариант
     * @param sectionSize размер секции в байтах, обязателен кратен 16 (BLOCK_SIZE)
     * @throws IllegalArgumentException если {@code cipher == null}
     * @throws IllegalArgumentException если {@code sectionSize < 16} или не кратен 16
     */
    public CtrAcpkmMode(Kuznyechik cipher, boolean useOmac, int sectionSize) {
        if (cipher == null) throw new IllegalArgumentException("cipher must not be null");
        if (sectionSize < BLOCK_SIZE || sectionSize % BLOCK_SIZE != 0) {
            throw new IllegalArgumentException(
                    "sectionSize must be >= "
                            + BLOCK_SIZE
                            + " and a multiple of "
                            + BLOCK_SIZE
                            + ", got "
                            + sectionSize);
        }
        this.cipher = cipher;
        this.useOmac = useOmac;
        this.sectionSize = sectionSize;
    }

    /**
     * Инициализирует CTR-ACPKM. Повторный вызов полностью сбрасывает прежнее состояние
     * (гамма, счётчик, MAC, ключ нулевой секции).
     * <p>
     * UKM обязателен: режим без него детерминирован (одна и та же гамма на ключ).
     * Без OMAC UKM не короче 8 байт (используются первые 8 — IV счётчика);
     * с OMAC — ровно 16 байт (IV ‖ seed для KDF_TREE, RFC 9337 §5.1.1).
     *
     * @param forEncryption {@code true} — шифрование, {@code false} — расшифрование
     * @param dk            {@link ParametersWithIV}: {@link SymmetricKey} (DK) и UKM
     * @throws IllegalArgumentException если параметры некорректны или UKM отсутствует
     */
    public void init(boolean forEncryption, CipherParameters dk) {
        if (!(dk instanceof ParametersWithIV pv)
                || !(pv.getParameters() instanceof SymmetricKey sk)) {
            throw new IllegalArgumentException(
                    "CTR-ACPKM requires ParametersWithIV with SymmetricKey (UKM is mandatory)");
        }
        byte[] ukm = pv.getIV();
        if (useOmac) {
            if (ukm.length != UKM_LEN) {
                throw new IllegalArgumentException(
                        "CTR-ACPKM-OMAC requires 16-byte UKM, got " + ukm.length);
            }
        } else if (ukm.length < IV_LEN) {
            throw new IllegalArgumentException(
                    "UKM too short for CTR-ACPKM: need at least " + IV_LEN + " bytes");
        }

        byte[] dkBytes = sk.getKey();
        try {
            if (dkBytes.length != KEY_LEN) {
                throw new IllegalArgumentException("CTR-ACPKM key must be " + KEY_LEN + " bytes");
            }

            // Прежнее состояние (в т.ч. остаток гаммы и MAC) не должно просочиться в новый сеанс.
            initialized = false;
            wipeSessionState();
            this.forEncryption = forEncryption;

            if (useOmac) {
                // UKM[0..7] = S' (IV для CTR); UKM[8..15] = seed для KDF_TREE (RFC 9337 §5.1.1)
                byte[] seed = Arrays.copyOfRange(ukm, IV_LEN, UKM_LEN);
                // KDF_TREE разделяет DK на ключ шифрования K(1) и ключ MAC K(2).
                // count=2 безопасно при R=1: счётчик занимает 1 октет, i in {1,2} влезает.
                byte[] derived =
                        KdfTreeGostR3411_2012_256.generate(
                                dkBytes, KDF_TREE_LABEL, seed, 2, KEY_LEN);
                byte[] encKey = Arrays.copyOfRange(derived, 0, KEY_LEN);
                byte[] macKey = Arrays.copyOfRange(derived, KEY_LEN, KEY_LEN * 2);
                Arrays.fill(derived, (byte) 0);

                SymmetricKey encKeyObj = new SymmetricKey(encKey);
                SymmetricKey macKeyObj = new SymmetricKey(macKey);
                Arrays.fill(macKey, (byte) 0);
                try {
                    // Отдельный экземпляр Kuznyechik: иначе cipher.init(encKey) ниже перезатёр бы
                    // общее расписание раундовых ключей, и CMAC считался бы под ключом шифрования,
                    // а не под MAC-ключом K(2) — разделение ключей KDF_TREE было бы потеряно.
                    this.mac = new Cmac(new Kuznyechik());
                    this.mac.init(macKeyObj);
                    cipher.init(true, encKeyObj);
                } finally {
                    encKeyObj.destroy();
                    macKeyObj.destroy();
                }
                this.initialKey = encKey;
            } else {
                cipher.init(true, sk);
                this.initialKey = dkBytes.clone();
            }
            initCounter(Arrays.copyOf(ukm, IV_LEN));
            this.initialized = true;
        } finally {
            Arrays.fill(dkBytes, (byte) 0);
        }
    }

    /**
     * Обрабатывает данные (шифрование/расшифрование).
     * Для OMAC-варианта CMAC всегда считается по открытому тексту: при шифровании - по входу,
     * при расшифровании - по выходу (RFC 9337 §5.1.1, §5.1.2). Тег к потоку добавляют
     * {@link #finishEncryption()} и {@link #verifyEncryptedTag(byte[])}.
     * <p>
     * Вход и выход могут совпадать ({@code input == output}).
     *
     * @param input  входные данные
     * @param inOff  смещение во входном буфере
     * @param len    длина обрабатываемых данных
     * @param output выходной буфер
     * @param outOff смещение в выходном буфере
     * @return количество записанных байт
     * @throws IllegalStateException если режим не инициализирован или тег уже финализирован
     */
    public int processBytes(byte[] input, int inOff, int len, byte[] output, int outOff) {
        checkInitialized();
        if (finished) {
            throw new IllegalStateException(
                    "OMAC tag already finalized — call reset() or init() before processing more data");
        }
        return process(input, inOff, len, output, outOff, useOmac);
    }

    /**
     * Один общий цикл CTR-ACPKM для данных и для тега: проверка границы секции,
     * смена ключа, счётчик и остаток гаммы ведутся в одном месте. Отдельная обработка
     * тега напрямую через блочный шифр зашифровала бы его не тем ключом на границе секции.
     *
     * @param updateMac {@code true} - обновлять CMAC открытым текстом; {@code false} - только
     *                  поток CTR (так шифруется и расшифровывается сам тег)
     */
    private int process(
            byte[] input, int inOff, int len, byte[] output, int outOff, boolean updateMac) {
        if (len == 0) return 0;

        int remaining = len;
        int inPos = inOff;
        int outPos = outOff;

        while (remaining > 0) {
            if (processedBytes >= sectionSize) {
                acpkmNext();
                processedBytes &= (BLOCK_SIZE - 1);
            }

            int chunk = Math.min(remaining, sectionSize - processedBytes);
            // При шифровании открытый текст - это вход, и MAC обязан увидеть его до записи
            // выхода: при input == output цикл ниже перезапишет вход шифртекстом.
            if (updateMac && forEncryption) {
                mac.update(input, inPos, chunk);
            }
            for (int i = 0; i < chunk; i++) {
                output[outPos + i] = calculateByte(input[inPos + i]);
            }
            processedBytes += chunk;
            // При расшифровании открытый текст появляется только на выходе.
            if (updateMac && !forEncryption) {
                mac.update(output, outPos, chunk);
            }

            inPos += chunk;
            outPos += chunk;
            remaining -= chunk;
        }

        return len;
    }

    /**
     * Шифрование без OMAC (чистый CTR-ACPKM).
     * CTR симметричен — идентично {@link #decryptOnly}.
     * Размер секции ACPKM — по умолчанию (4096 байт).
     *
     * @param dk   ключ (SymmetricKey)
     * @param ukm  UKM (16 байт, первые 8 = S')
     * @param data открытые данные
     * @return зашифрованные данные
     */
    public static byte[] encryptOnly(CipherParameters dk, byte[] ukm, byte[] data) {
        return encryptOnly(dk, ukm, data, AcpkmSectionSize.DEFAULT);
    }

    /**
     * Шифрование без OMAC (чистый CTR-ACPKM) с заданным размером секции.
     * CTR симметричен — идентично {@link #decryptOnly(CipherParameters, byte[], byte[], int)}.
     *
     * @param dk          ключ (SymmetricKey)
     * @param ukm         UKM (16 байт, первые 8 = S')
     * @param data        открытые данные
     * @param sectionSize размер секции ACPKM в байтах
     * @return зашифрованные данные
     */
    public static byte[] encryptOnly(
            CipherParameters dk, byte[] ukm, byte[] data, int sectionSize) {
        return decryptOnly(dk, ukm, data, sectionSize);
    }

    /**
     * Однократное расшифрование данных (без OMAC — чистый CTR).
     * Размер секции ACPKM — по умолчанию (4096 байт).
     *
     * @param dk   ключ (SymmetricKey)
     * @param ukm  UKM (16 байт, первые 8 = S')
     * @param data зашифрованные данные
     * @return расшифрованные данные
     */
    public static byte[] decryptOnly(CipherParameters dk, byte[] ukm, byte[] data) {
        return decryptOnly(dk, ukm, data, AcpkmSectionSize.DEFAULT);
    }

    /**
     * Однократное расшифрование данных с заданным размером секции (без OMAC — чистый CTR).
     *
     * @param dk          ключ (SymmetricKey)
     * @param ukm         UKM (16 байт, первые 8 = S')
     * @param data        зашифрованные данные
     * @param sectionSize размер секции ACPKM в байтах
     * @return расшифрованные данные
     */
    public static byte[] decryptOnly(
            CipherParameters dk, byte[] ukm, byte[] data, int sectionSize) {
        CtrAcpkmMode mode = new CtrAcpkmMode(new Kuznyechik(), false, sectionSize);
        try {
            mode.init(false, new ParametersWithIV(dk, requireUkm(ukm)));
            byte[] result = new byte[data.length];
            mode.processBytes(data, 0, data.length, result, 0);
            return result;
        } finally {
            mode.destroy();
        }
    }

    /**
     * Секционная смена ключа ACPKM (Р 1323565.1.017-2018, RFC 8645).
     *
     * <p>Вычисляет новый ключ K' = E_K(D[0..15]) || E_K(D[16..31]),
     * затирает временный буфер и заменяет раундовые ключи Кузнечика.
     * Оба блока D шифруются на старом ключе; только после этого
     * {@code cipher.init()} заменяет расписание (старое зануляется внутри
     * {@code Kuznyechik.init()}).
     */
    private void acpkmNext() {
        byte[] newKey = new byte[KEY_LEN];
        cipher.processBlock(ACPKM_D_2018, 0, newKey, 0);
        cipher.processBlock(ACPKM_D_2018, BLOCK_SIZE, newKey, BLOCK_SIZE);
        SymmetricKey newSymKey = new SymmetricKey(newKey);
        Arrays.fill(newKey, (byte) 0);
        try {
            cipher.init(true, newSymKey);
        } finally {
            newSymKey.destroy();
        }
    }

    /**
     * Завершает шифрование OMAC-варианта: финализирует CMAC по всему открытому тексту
     * и возвращает тег, зашифрованный продолжением того же потока CTR-ACPKM
     * (RFC 9337 §5.1.1: шифруется {@code M ‖ MAC}). Тег в CMAC не попадает.
     * <p>
     * После вызова {@link #processBytes} запрещён до {@link #reset()} или {@link #init}.
     *
     * @return зашифрованный тег (16 байт), добавляется к шифртексту
     * @throws IllegalStateException если режим не OMAC, не инициализирован, настроен на
     *                               расшифрование или тег уже финализирован
     */
    public byte[] finishEncryption() {
        requireTagStage(true);
        byte[] tag = new byte[MAC_TAG_LEN];
        byte[] encryptedTag = new byte[MAC_TAG_LEN];
        try {
            mac.doFinal(tag, 0);
            process(tag, 0, MAC_TAG_LEN, encryptedTag, 0, false);
            finished = true;
            return encryptedTag;
        } finally {
            Arrays.fill(tag, (byte) 0);
        }
    }

    /**
     * Завершает расшифрование OMAC-варианта: расшифровывает тег продолжением потока,
     * финализирует CMAC по полученному открытому тексту и сравнивает за постоянное время.
     * <p>
     * После вызова {@link #processBytes} запрещён до {@link #reset()} или {@link #init}.
     *
     * @param encryptedTag зашифрованный тег (ровно 16 байт), следующий за шифртекстом
     * @throws AuthenticationException если тег неверной длины или не совпал
     * @throws IllegalStateException   если режим не OMAC, не инициализирован, настроен на
     *                                 шифрование или тег уже финализирован
     */
    public void verifyEncryptedTag(byte[] encryptedTag) throws AuthenticationException {
        requireTagStage(false);
        if (encryptedTag == null || encryptedTag.length != MAC_TAG_LEN) {
            throw new AuthenticationException("CTR-ACPKM-OMAC tag must be 16 bytes");
        }
        byte[] received = new byte[MAC_TAG_LEN];
        byte[] computed = new byte[MAC_TAG_LEN];
        try {
            process(encryptedTag, 0, MAC_TAG_LEN, received, 0, false);
            mac.doFinal(computed, 0);
            finished = true;
            if (!MessageDigest.isEqual(computed, received)) {
                throw new AuthenticationException("CTR-ACPKM-OMAC authentication tag mismatch");
            }
        } finally {
            Arrays.fill(received, (byte) 0);
            Arrays.fill(computed, (byte) 0);
        }
    }

    private void requireTagStage(boolean encryption) {
        if (!useOmac || mac == null) {
            throw new IllegalStateException("No OMAC tag available");
        }
        checkInitialized();
        if (forEncryption != encryption) {
            throw new IllegalStateException(
                    encryption
                            ? "finishEncryption() requires an encrypting mode"
                            : "verifyEncryptedTag() requires a decrypting mode");
        }
        if (finished) {
            throw new IllegalStateException("OMAC tag already finalized");
        }
    }

    /**
     * Шифрование OMAC-варианта по RFC 9337 §5.1.1: CMAC по открытому тексту,
     * шифруется {@code M ‖ MAC}. Размер секции ACPKM - по умолчанию (4096 байт).
     *
     * @param dk   ключ DK (SymmetricKey)
     * @param ukm  UKM (ровно 16 байт: IV ‖ seed KDF_TREE)
     * @param data открытые данные
     * @return шифртекст ‖ зашифрованный тег (16 байт), длина {@code data.length + 16}
     */
    public static byte[] encryptWithMac(CipherParameters dk, byte[] ukm, byte[] data) {
        return encryptWithMac(dk, ukm, data, AcpkmSectionSize.DEFAULT);
    }

    /**
     * Шифрование OMAC-варианта по RFC 9337 §5.1.1 с заданным размером секции.
     *
     * @param dk          ключ DK (SymmetricKey)
     * @param ukm         UKM (ровно 16 байт)
     * @param data        открытые данные
     * @param sectionSize размер секции ACPKM в байтах
     * @return шифртекст ‖ зашифрованный тег (16 байт), длина {@code data.length + 16}
     */
    public static byte[] encryptWithMac(
            CipherParameters dk, byte[] ukm, byte[] data, int sectionSize) {
        CtrAcpkmMode mode = new CtrAcpkmMode(new Kuznyechik(), true, sectionSize);
        try {
            mode.init(true, new ParametersWithIV(dk, requireUkm(ukm)));

            byte[] out = new byte[data.length + MAC_TAG_LEN];
            mode.processBytes(data, 0, data.length, out, 0);

            byte[] encryptedTag = mode.finishEncryption();
            System.arraycopy(encryptedTag, 0, out, data.length, MAC_TAG_LEN);
            return out;
        } finally {
            mode.destroy();
        }
    }

    /**
     * Расшифрование OMAC-варианта по RFC 9337 §5.1.2 с проверкой тега.
     * Размер секции ACPKM - по умолчанию (4096 байт).
     *
     * @param dk   ключ DK (SymmetricKey)
     * @param ukm  UKM (ровно 16 байт)
     * @param data шифртекст ‖ зашифрованный тег (последние 16 байт)
     * @return расшифрованные данные (без тега)
     * @throws AuthenticationException если вход короче тега или тег не совпал
     */
    public static byte[] decryptWithMac(CipherParameters dk, byte[] ukm, byte[] data)
            throws AuthenticationException {
        return decryptWithMac(dk, ukm, data, AcpkmSectionSize.DEFAULT);
    }

    /**
     * Расшифрование OMAC-варианта по RFC 9337 §5.1.2 с заданным размером секции.
     *
     * @param dk          ключ DK (SymmetricKey)
     * @param ukm         UKM (ровно 16 байт)
     * @param data        шифртекст ‖ зашифрованный тег (последние 16 байт)
     * @param sectionSize размер секции ACPKM в байтах
     * @return расшифрованные данные (без тега)
     * @throws AuthenticationException если вход короче тега или тег не совпал
     */
    public static byte[] decryptWithMac(
            CipherParameters dk, byte[] ukm, byte[] data, int sectionSize)
            throws AuthenticationException {
        if (data.length < MAC_TAG_LEN) {
            throw new AuthenticationException("Data too short for OMAC verification");
        }

        int textLen = data.length - MAC_TAG_LEN;
        byte[] encryptedTag = Arrays.copyOfRange(data, textLen, data.length);

        CtrAcpkmMode mode = new CtrAcpkmMode(new Kuznyechik(), true, sectionSize);
        byte[] plaintext = null;
        boolean authenticated = false;
        try {
            mode.init(false, new ParametersWithIV(dk, requireUkm(ukm)));

            plaintext = new byte[textLen];
            mode.processBytes(data, 0, textLen, plaintext, 0);
            mode.verifyEncryptedTag(encryptedTag);

            authenticated = true;
            return plaintext;
        } finally {
            // Непроверенный открытый текст не должен остаться в куче; на успешном пути
            // plaintext - возвращаемый результат, его затирать нельзя.
            if (!authenticated && plaintext != null) {
                Arrays.fill(plaintext, (byte) 0);
            }
            Arrays.fill(encryptedTag, (byte) 0);
            mode.destroy();
        }
    }

    /** @return имя алгоритма */
    public String getAlgorithmName() {
        return "Kuznyechik/CTR-ACPKM" + (useOmac ? "-OMAC" : "");
    }

    private static byte[] requireUkm(byte[] ukm) {
        if (ukm == null) {
            throw new IllegalArgumentException("UKM must not be null");
        }
        return ukm;
    }

    private void initCounter(byte[] iv) {
        Arrays.fill(ctr, (byte) 0);
        System.arraycopy(iv, 0, ctr, 0, Math.min(IV_LEN, iv.length));
    }

    private byte calculateByte(byte in) {
        if (byteCount == 0) {
            generateBuf();
        }
        byte rv = (byte) (gammaBuf[byteCount] ^ in);
        if (++byteCount == BLOCK_SIZE) {
            byteCount = 0;
            incrementCTR();
        }
        return rv;
    }

    private void generateBuf() {
        cipher.processBlock(ctr, 0, gammaBuf, 0);
    }

    private void incrementCTR() {
        for (int i = BLOCK_SIZE - 1; i >= IV_LEN; i--) {
            if (++ctr[i] != 0) break;
        }
    }

    private void checkInitialized() {
        if (!initialized) {
            throw new IllegalStateException("CTR-ACPKM not initialized — call init() first");
        }
    }

    /**
     * Возвращает режим в состояние сразу после {@link #init}: ключ нулевой секции, счётчик
     * из того же IV, пустая гамма, чистый MAC. Нужен повторному расшифрованию тем же
     * UKM; для шифрования повторное использование того же UKM недопустимо (повтор гаммы).
     *
     * @throws IllegalStateException если режим не инициализирован
     */
    public void reset() {
        checkInitialized();
        Arrays.fill(gammaBuf, (byte) 0);
        byteCount = 0;
        processedBytes = 0;
        finished = false;
        initCounter(Arrays.copyOf(ctr, IV_LEN));
        // После ACPKM-смены в шифре лежит производный ключ, поэтому восстанавливаем исходный.
        SymmetricKey restored = new SymmetricKey(initialKey);
        try {
            cipher.init(true, restored);
        } finally {
            restored.destroy();
        }
        if (mac != null) {
            mac.reset();
        }
    }

    /**
     * Затирает ключевой материал: буферы счётчика, гаммы, производные ключи.
     */
    public void destroy() {
        cipher.destroy();
        wipeSessionState();
        initialized = false;
    }

    /** Затирает всё, что относится к текущему сеансу, кроме самого шифра. */
    private void wipeSessionState() {
        Arrays.fill(ctr, (byte) 0);
        Arrays.fill(gammaBuf, (byte) 0);
        byteCount = 0;
        processedBytes = 0;
        finished = false;
        if (initialKey != null) {
            Arrays.fill(initialKey, (byte) 0);
            initialKey = null;
        }
        if (mac != null) {
            mac.destroy();
            mac = null;
        }
    }
}
