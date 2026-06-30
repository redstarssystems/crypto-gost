package org.rssys.gost.cipher.mode;

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
 * Режим CTR-ACPKM (RFC 8645, RFC 9337 §5) для Кузнечика.
 * <p>
 * Два варианта:
 * <ul>
 *   <li><b>Без OMAC</b> ({@code id-gostr3412-2015-kuznyechik-ctracpkm}):
 *       чистый CTR с S' = ukm[0..7]. Ключ = DK.</li>
 *   <li><b>С OMAC</b> ({@code id-gostr3412-2015-kuznyechik-ctracpkm-omac}):
 *       KDF_TREE(DK, "kdf tree", ukm[8..15]) -> K(1)||K(2).
 *       Encrypt-then-MAC: шифрование CTR с K(1), CMAC с K(2).</li>
 * </ul>
 * Симметричен: encrypt = decrypt для CTR-части.
 */
public final class CtrAcpkmMode {

    private static final int BLOCK_SIZE = 16;
    private static final int UKM_LEN = 16;
    private static final int IV_LEN = 8;
    private static final int KEY_LEN = 32;

    /** Размер CMAC-тега для Кузнечика (128 бит). */
    private static final int MAC_TAG_LEN = 16;

    private static final byte[] KDF_TREE_LABEL =
            "kdf tree".getBytes(java.nio.charset.StandardCharsets.US_ASCII);

    private final Kuznyechik cipher;
    private final boolean useOmac;

    private byte[] ctr = new byte[BLOCK_SIZE];
    private byte[] gammaBuf = new byte[BLOCK_SIZE];
    private int byteCount;

    private Mac mac;
    private byte[] computedTag;

    private boolean initialized;
    private boolean forEncryption;

    public CtrAcpkmMode(Kuznyechik cipher, boolean useOmac) {
        if (cipher == null) throw new IllegalArgumentException("cipher must not be null");
        this.cipher = cipher;
        this.useOmac = useOmac;
    }

    /**
     * Инициализирует CTR-ACPKM.
     *
     * @param forEncryption {@code true} — шифрование, {@code false} — расшифрование
     * @param dk            ключ (DK) из PBKDF2, {@link SymmetricKey} или {@link ParametersWithIV}
     * @throws IllegalArgumentException если параметры некорректны
     */
    public void init(boolean forEncryption, CipherParameters dk) {
        byte[] dkBytes;
        byte[] ukm;

        if (dk instanceof ParametersWithIV pv) {
            dkBytes = ((SymmetricKey) pv.getParameters()).getKey();
            ukm = pv.getIV();
        } else if (dk instanceof SymmetricKey sk) {
            dkBytes = sk.getKey();
            ukm = null;
        } else {
            throw new IllegalArgumentException(
                    "CTR-ACPKM requires SymmetricKey or ParametersWithIV");
        }

        if (dkBytes.length != KEY_LEN) {
            throw new IllegalArgumentException("CTR-ACPKM key must be " + KEY_LEN + " bytes");
        }

        this.forEncryption = forEncryption;
        this.computedTag = null;

        if (useOmac) {
            if (ukm == null || ukm.length != UKM_LEN) {
                throw new IllegalArgumentException(
                        "CTR-ACPKM-OMAC requires 16-byte UKM in ParametersWithIV");
            }
            // UKM[0..7] = S' (IV для CTR); UKM[8..15] = seed для KDF_TREE (RFC 9337 §5.1.1)
            byte[] seed = Arrays.copyOfRange(ukm, 8, 16);
            // KDF_TREE разделяет DK на ключ шифрования K(1) и ключ MAC K(2)
            byte[] derived =
                    KdfTreeGostR3411_2012_256.generate(dkBytes, KDF_TREE_LABEL, seed, 2, KEY_LEN);
            byte[] encKey = Arrays.copyOfRange(derived, 0, KEY_LEN);
            byte[] macKey = Arrays.copyOfRange(derived, KEY_LEN, KEY_LEN * 2);
            Arrays.fill(derived, (byte) 0);

            SymmetricKey encKeyObj = new SymmetricKey(encKey);
            SymmetricKey macKeyObj = new SymmetricKey(macKey);
            Arrays.fill(encKey, (byte) 0);
            Arrays.fill(macKey, (byte) 0);

            this.mac = new Cmac(cipher);
            this.mac.init(macKeyObj);

            cipher.init(true, encKeyObj);
            initCounter(Arrays.copyOf(ukm, 8));
        } else {
            byte[] iv;
            if (ukm != null) {
                if (ukm.length < IV_LEN) {
                    throw new IllegalArgumentException("UKM too short for CTR-ACPKM");
                }
                iv = Arrays.copyOf(ukm, IV_LEN);
            } else {
                iv = new byte[IV_LEN];
            }
            cipher.init(true, dk instanceof ParametersWithIV pv2 ? pv2.getParameters() : dk);
            initCounter(iv);
        }

        this.initialized = true;
    }

    /**
     * Обрабатывает данные (шифрование/расшифрование).
     * Для OMAC-варианта: при шифровании MAC считается по выходному шифртексту,
     * при расшифровании — по входному шифртексту (Encrypt-then-MAC).
     *
     * @param input  входные данные
     * @param inOff  смещение во входном буфере
     * @param len    длина обрабатываемых данных
     * @param output выходной буфер
     * @param outOff смещение в выходном буфере
     * @return количество записанных байт
     */
    public int processBytes(byte[] input, int inOff, int len, byte[] output, int outOff) {
        checkInitialized();

        if (len == 0) return 0;

        for (int i = 0; i < len; i++) {
            output[outOff + i] = calculateByte(input[inOff + i]);
        }

        if (useOmac) {
            // MAC считается по шифртексту, не по открытому тексту (EtM)
            if (forEncryption) {
                mac.update(output, outOff, len);
            } else {
                mac.update(input, inOff, len);
            }
        }

        return len;
    }

    /**
     * Шифрование без OMAC (чистый CTR-ACPKM).
     * CTR симметричен — идентично {@link #decryptOnly}.
     *
     * @param dk   ключ (SymmetricKey)
     * @param ukm  UKM (16 байт, первые 8 = S')
     * @param data открытые данные
     * @return зашифрованные данные
     */
    public static byte[] encryptOnly(CipherParameters dk, byte[] ukm, byte[] data) {
        return decryptOnly(dk, ukm, data);
    }

    /**
     * Однократное расшифрование данных (без OMAC — чистый CTR).
     *
     * @param dk   ключ (SymmetricKey)
     * @param ukm  UKM (16 байт, первые 8 = S')
     * @param data зашифрованные данные
     * @return расшифрованные данные
     */
    public static byte[] decryptOnly(CipherParameters dk, byte[] ukm, byte[] data) {
        CtrAcpkmMode mode = new CtrAcpkmMode(new Kuznyechik(), false);
        mode.init(false, ukm != null ? new ParametersWithIV(dk, ukm) : dk);
        byte[] result = new byte[data.length];
        mode.processBytes(data, 0, data.length, result, 0);
        return result;
    }

    /**
     * Возвращает CMAC-тег для OMAC-варианта.
     * Вызывается однократно после processBytes при шифровании.
     * Результат кешируется — повторный вызов возвращает тот же тег.
     *
     * @return CMAC-тег (16 байт)
     * @throws IllegalStateException если не используется OMAC или не было данных
     */
    public byte[] getMacTag() {
        if (!useOmac || mac == null) {
            throw new IllegalStateException("No OMAC tag available");
        }
        if (computedTag == null) {
            computedTag = new byte[MAC_TAG_LEN];
            mac.doFinal(computedTag, 0);
        }
        return computedTag;
    }

    /**
     * Шифрование с CMAC (OMAC-вариант).
     * Возвращает шифртекст || 16-байтовый MAC.
     *
     * @param dk   ключ (SymmetricKey)
     * @param ukm  UKM (16 байт)
     * @param data открытые данные
     * @return шифртекст + CMAC (последние 16 байт)
     */
    public static byte[] encryptWithMac(CipherParameters dk, byte[] ukm, byte[] data) {
        CtrAcpkmMode mode = new CtrAcpkmMode(new Kuznyechik(), true);
        mode.init(true, new ParametersWithIV(dk, ukm));

        byte[] ct = new byte[data.length + MAC_TAG_LEN];
        mode.processBytes(data, 0, data.length, ct, 0);

        byte[] tag = mode.getMacTag();
        System.arraycopy(tag, 0, ct, data.length, MAC_TAG_LEN);
        return ct;
    }

    /**
     * Расшифрование с проверкой CMAC (OMAC-вариант).
     * Ожидает на входе шифртекст || 16-байтовый MAC.
     *
     * @param dk   ключ (SymmetricKey)
     * @param ukm  UKM (16 байт)
     * @param data зашифрованные данные + MAC (последние 16 байт)
     * @return расшифрованные данные (без MAC)
     * @throws AuthenticationException если MAC не совпадает
     */
    public static byte[] decryptWithMac(CipherParameters dk, byte[] ukm, byte[] data)
            throws AuthenticationException {
        if (data.length < MAC_TAG_LEN) {
            throw new AuthenticationException("Data too short for OMAC verification");
        }

        byte[] ct = Arrays.copyOf(data, data.length - MAC_TAG_LEN);
        byte[] expectedTag = Arrays.copyOfRange(data, data.length - MAC_TAG_LEN, data.length);

        CtrAcpkmMode mode = new CtrAcpkmMode(new Kuznyechik(), true);
        mode.init(false, new ParametersWithIV(dk, ukm));

        byte[] plaintext = new byte[ct.length];
        mode.processBytes(ct, 0, ct.length, plaintext, 0);

        // CMAC считается по принятому шифртексту (EtM)
        byte[] computedTag = mode.getMacTag();

        if (!MessageDigest.isEqual(computedTag, expectedTag)) {
            throw new AuthenticationException("CTR-ACPKM-OMAC authentication tag mismatch");
        }

        return plaintext;
    }

    /** @return имя алгоритма */
    public String getAlgorithmName() {
        return "Kuznyechik/CTR-ACPKM" + (useOmac ? "-OMAC" : "");
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

    public void reset() {
        Arrays.fill(gammaBuf, (byte) 0);
        byteCount = 0;
        computedTag = null;
        initCounter(Arrays.copyOf(ctr, IV_LEN));
        cipher.reset();
        if (mac != null) {
            mac.reset();
        }
    }

    /**
     * Затирает ключевой материал: буферы счётчика, гаммы, производные ключи.
     */
    public void destroy() {
        cipher.destroy();
        Arrays.fill(ctr, (byte) 0);
        Arrays.fill(gammaBuf, (byte) 0);
        if (mac != null) {
            mac.reset();
        }
        computedTag = null;
        initialized = false;
    }
}
