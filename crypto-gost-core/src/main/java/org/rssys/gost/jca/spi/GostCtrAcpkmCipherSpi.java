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
import javax.crypto.spec.IvParameterSpec;
import org.rssys.gost.cipher.Kuznyechik;
import org.rssys.gost.cipher.ParametersWithIV;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.cipher.mode.CtrAcpkmMode;
import org.rssys.gost.util.AuthenticationException;
import org.rssys.gost.util.CryptoRandom;

/**
 * JCA SPI для OID {@code id-gostr3412-2015-kuznyechik-ctracpkm}
 * (RFC 9337 §7.3, схема PBES2). Реализует ГОСТ Р 34.13-2015 CTR
 * с секционной сменой ключа ACPKM (RFC 8645 §6.2.2) каждые 4096 байт.
 * <p>
 * Два варианта — два внутренних подкласса, регистрируются как отдельные
 * {@code Cipher.*} в {@link org.rssys.gost.jca.RssysGostProvider}:
 * <ul>
 *   <li>{@link WithoutOmac} — {@code "Kuznyechik/CTR-ACPKM/NoPadding"}</li>
 *   <li>{@link WithOmac} — {@code "Kuznyechik/CTR-ACPKM-OMAC/NoPadding"}</li>
 * </ul>
 * <p>
 * Внутреннее использование в {@code GostPbes2} предпочтительнее через прямой
 * вызов {@link CtrAcpkmMode}, не через JCA — обходятся накладные расходы
 * JCA на маршаллинг ключей и параметров.
 * <p>
 * Секционная смена ключа ACPKM выполняется каждые 4096 байт
 * (RFC 8645 §6.2.2). Для PBES2-сценария данные всегда
 * умещаются в одну секцию.
 * <p>
 * <b>Состояние после {@code doFinal}.</b> Расшифрование возвращается в состояние после
 * {@code init} (тот же ключ и UKM), как требует контракт JCA. Шифрование сознательно
 * отклоняется от него: повторный {@code update}/{@code doFinal} без {@code init} бросает
 * {@link IllegalStateException}, потому что сброс на тот же UKM повторил бы гамму.
 * Повторный {@code init} на шифрование с тем же ключом и тем же UKM, на которых уже выдан
 * шифртекст, отвергается ({@link InvalidAlgorithmParameterException}); новый UKM или ключ
 * допустимы. Помнится только последняя использованная пара: после A, затем B пара A снова
 * принимается. Хранится отпечаток ключа, а не ключ (общая защита {@code EncryptionReuseGuard}).
 * Без OMAC гамма зависит только от первых 8 байт UKM, поэтому сравниваются они, а не весь UKM:
 * UKM {@code X} и {@code X ‖ Y} дают одну гамму и считаются одной парой. Уникальность UKM по всем
 * сообщениям обеспечивает вызывающий.
 */
public class GostCtrAcpkmCipherSpi extends AbstractGostCipherSpi {

    /** Без OMAC — чистый CTR (ГОСТ Р 34.13-2015). */
    public static final class WithoutOmac extends GostCtrAcpkmCipherSpi {
        public WithoutOmac() {
            super(false);
        }
    }

    /** С OMAC - CMAC по открытому тексту, шифруется M || MAC (RFC 9337 §5.1.1). */
    public static final class WithOmac extends GostCtrAcpkmCipherSpi {
        public WithOmac() {
            super(true);
        }
    }

    private static final int UKM_LEN = 16;
    private static final int TAG_LEN = Kuznyechik.BLOCK_SIZE;

    /** Минимальная длина UKM без OMAC: 8 байт IV счётчика (RFC 8645 §6.2.2, n/2 бит). */
    private static final int MIN_UKM_LEN = 8;

    private final boolean useOmac;
    private boolean forEncryption;
    private CtrAcpkmMode mode;
    private byte[] ukm;
    private boolean initialized;

    /** Шифрование завершено: повторное использование того же UKM дало бы повтор гаммы. */
    private boolean encryptionCompleted;

    /**
     * Защита от повтора пары «ключ + эффективный nonce» при шифровании (аналог защиты SunJCE GCM):
     * повтор дал бы ту же гамму. Помнится отпечаток ключа, а не ключ; действует в пределах одного
     * экземпляра {@code Cipher}, помнит последнюю использованную пару. Использованная пара
     * переживает {@code init} на расшифрование, иначе защита обходится цепочкой
     * encrypt -> init(DECRYPT) -> init(ENCRYPT).
     */
    private final EncryptionReuseGuard reuseGuard =
            new EncryptionReuseGuard("UKM", "CTR-ACPKM encryption");

    /**
     * Накопленный ввод режима с OMAC (без OMAC шифр потоковый и не буферизует): тег проверяется в
     * {@code doFinal}, поэтому сообщение целиком остаётся в памяти до него.
     */
    private final GrowableInputBuffer inputBuffer =
            new GrowableInputBuffer(GrowableInputBuffer.MAX_SIZE - TAG_LEN);

    GostCtrAcpkmCipherSpi(boolean useOmac) {
        this.useOmac = useOmac;
    }

    /**
     * Абстрактный метод CipherSpi. Не вызывается JCA при регистрации полной
     * трансформации (Cipher.alg/mode/padding), но обязан быть реализован.
     */
    @Override
    protected void engineSetMode(String modeStr) throws NoSuchAlgorithmException {
        if (!"CTR-ACPKM".equalsIgnoreCase(modeStr) && !"CTR-ACPKM-OMAC".equalsIgnoreCase(modeStr)) {
            throw new NoSuchAlgorithmException(
                    "Only CTR-ACPKM/CTR-ACPKM-OMAC supported, got: " + modeStr);
        }
    }

    /**
     * Абстрактный метод CipherSpi. Не вызывается JCA при регистрации полной
     * трансформации, но обязан быть реализован.
     */
    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        if (!"NoPadding".equalsIgnoreCase(padding)) {
            throw new NoSuchPaddingException("Only NoPadding supported for CTR-ACPKM");
        }
    }

    @Override
    protected int engineGetBlockSize() {
        return 16;
    }

    @Override
    protected byte[] engineGetIV() {
        return (ukm != null) ? Arrays.copyOf(ukm, ukm.length) : null;
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        // long: сумма размера и длины ввода, а потом тега, не должна переполнить int
        long total = (long) inputBuffer.size() + inputLen;
        long needed = total;
        if (useOmac) {
            needed = forEncryption ? total + TAG_LEN : Math.max(0, total - TAG_LEN);
        }
        return (int) Math.min(needed, Integer.MAX_VALUE);
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    @Override
    protected void engineInit(
            int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        boolean encrypt = isEncrypting(opmode);
        SymmetricKey keyParam = SymmetricKeyExtractor.forCipher(key);
        try {
            byte[] newUkm = resolveUkm(params, encrypt, random);
            // Эффективный nonce: гамма зависит только от первых 8 байт UKM без OMAC (счётчик
            // строится из них), а с OMAC - от всех 16 (последние 8 - seed KDF_TREE). Сравнивать
            // полный UKM без OMAC нельзя: X и X ‖ Y дали бы одну гамму как разные пары.
            byte[] token = encrypt ? reuseGuard.prepare(keyParam, effectiveNonce(newUkm)) : null;
            boolean tokenHandedOver = false;
            try {
                // Новый экземпляр режима создаём до замены состояния: при ошибке
                // инициализации прежнее состояние Cipher остаётся нетронутым.
                CtrAcpkmMode newMode = new CtrAcpkmMode(new Kuznyechik(), useOmac);
                newMode.init(encrypt, new ParametersWithIV(keyParam, newUkm));
                releaseState();
                this.mode = newMode;
                this.forEncryption = encrypt;
                this.ukm = newUkm;
                if (encrypt) {
                    reuseGuard.setPending(token);
                    tokenHandedOver = true;
                }
                this.encryptionCompleted = false;
                this.initialized = true;
            } finally {
                if (!tokenHandedOver) {
                    EncryptionReuseGuard.wipe(token);
                }
            }
        } finally {
            keyParam.destroy();
        }
    }

    /** Проверяет и возвращает UKM: заданный вызывающим либо сгенерированный при шифровании. */
    private byte[] resolveUkm(AlgorithmParameterSpec params, boolean encrypt, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        if (params instanceof IvParameterSpec ivp) {
            byte[] iv = ivp.getIV();
            if (useOmac && iv.length != UKM_LEN) {
                throw new InvalidAlgorithmParameterException(
                        "CTR-ACPKM-OMAC requires 16-byte UKM, got " + iv.length);
            }
            if (!useOmac && iv.length < MIN_UKM_LEN) {
                throw new InvalidAlgorithmParameterException(
                        "CTR-ACPKM requires UKM of at least "
                                + MIN_UKM_LEN
                                + " bytes, got "
                                + iv.length);
            }
            return iv;
        }
        if (params == null) {
            if (!encrypt) {
                throw new InvalidAlgorithmParameterException(
                        "CTR-ACPKM decryption requires UKM (IvParameterSpec)");
            }
            byte[] generated = new byte[useOmac ? UKM_LEN : MIN_UKM_LEN];
            (random != null ? random : CryptoRandom.INSTANCE).nextBytes(generated);
            return generated;
        }
        throw new InvalidAlgorithmParameterException("Use IvParameterSpec for CTR-ACPKM");
    }

    /**
     * Часть UKM, от которой зависит гамма: без OMAC - первые 8 байт (IV счётчика), с OMAC - весь
     * UKM строгой длины 16 байт.
     */
    private byte[] effectiveNonce(byte[] ukmValue) {
        return useOmac ? ukmValue : Arrays.copyOf(ukmValue, MIN_UKM_LEN);
    }

    /**
     * Затирает режим, буфер и ожидающую пару. Использованная пара сохраняется: она нужна
     * защите от повтора UKM и после {@code init} на расшифрование. Пара переводится в
     * использованную только когда шифртекст выдан (см. {@code commitIfCiphertextProduced}):
     * до этого гамма наружу не попадала, и повторный {@code init} с той же парой безопасен.
     */
    private void releaseState() {
        if (mode != null) {
            mode.destroy();
            mode = null;
        }
        inputBuffer.clear();
        reuseGuard.discardPending();
        initialized = false;
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        byte[] result = updateWithoutCommit(input, inputOffset, inputLen);
        commitIfCiphertextProduced(result.length);
        return result;
    }

    /** Обрабатывает порцию, не фиксируя использование пары: фиксирует вызывающий после выдачи. */
    private byte[] updateWithoutCommit(byte[] input, int inputOffset, int inputLen) {
        checkInitialized();
        if (useOmac) {
            inputBuffer.append(input, inputOffset, inputLen);
            return new byte[0];
        }
        byte[] result = new byte[inputLen];
        mode.processBytes(input, inputOffset, inputLen, result, 0);
        return result;
    }

    /** Пара считается использованной, когда непустой шифртекст успешно сформирован. */
    private void commitIfCiphertextProduced(int producedLength) {
        if (forEncryption && producedLength > 0) {
            reuseGuard.commit();
        }
    }

    @Override
    protected int engineUpdate(
            byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException {
        checkInitialized();
        // Размер проверяем до обработки: иначе гамма уже продвинулась бы, и повтор
        // вызова с достаточным буфером дал бы испорченные данные.
        if (!useOmac && inputLen > output.length - outputOffset) {
            throw new ShortBufferException("Output buffer too short");
        }
        byte[] result = updateWithoutCommit(input, inputOffset, inputLen);
        System.arraycopy(result, 0, output, outputOffset, result.length);
        // Фиксируем после успешной выдачи в буфер вызывающего, не раньше.
        commitIfCiphertextProduced(result.length);
        return result.length;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {
        checkInitialized();

        byte[] plaintext = null;
        boolean success = false;
        try {
            // Внутри try: отказ по размеру тоже завершает операцию, буфер с данными затирается
            if (input != null && inputLen > 0) {
                inputBuffer.append(input, inputOffset, inputLen);
            }
            if (!useOmac) {
                byte[] result = new byte[inputBuffer.size()];
                mode.processBytes(inputBuffer.array(), 0, inputBuffer.size(), result, 0);
                success = true;
                commitIfCiphertextProduced(result.length);
                return result;
            }
            if (forEncryption) {
                // RFC 9337 §5.1.1: CMAC по открытому тексту, шифруется M || MAC одним потоком.
                byte[] out = new byte[inputBuffer.size() + TAG_LEN];
                mode.processBytes(inputBuffer.array(), 0, inputBuffer.size(), out, 0);
                byte[] encryptedTag = mode.finishEncryption();
                System.arraycopy(encryptedTag, 0, out, inputBuffer.size(), TAG_LEN);
                success = true;
                // OMAC всегда выдаёт хотя бы тег, поэтому пара использована.
                commitIfCiphertextProduced(out.length);
                return out;
            }
            int ctLen = inputBuffer.size() - TAG_LEN;
            if (ctLen < 0) {
                throw new AEADBadTagException("CTR-ACPKM-OMAC data too short for tag");
            }
            plaintext = new byte[ctLen];
            mode.processBytes(inputBuffer.array(), 0, ctLen, plaintext, 0);
            try {
                mode.verifyEncryptedTag(
                        Arrays.copyOfRange(inputBuffer.array(), ctLen, inputBuffer.size()));
            } catch (AuthenticationException e) {
                throw new AEADBadTagException("CTR-ACPKM-OMAC tag mismatch");
            }
            success = true;
            return plaintext;
        } finally {
            if (!success && plaintext != null) {
                // Непроверенный открытый текст не должен остаться в куче.
                Arrays.fill(plaintext, (byte) 0);
            }
            inputBuffer.clear();
            finishOperation();
        }
    }

    /**
     * Завершает операцию: расшифрование возвращается в состояние после {@code init}
     * (в том числе после ошибки тега — без кешированного тега и продвинутой гаммы),
     * шифрование блокируется до нового {@code init}.
     */
    private void finishOperation() {
        if (forEncryption) {
            mode.destroy();
            initialized = false;
            encryptionCompleted = true;
        } else {
            mode.reset();
        }
    }

    @Override
    protected int engineDoFinal(
            byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        checkInitialized();
        // Размер проверяем до обработки: при ShortBufferException состояние не меняется,
        // и вызов можно повторить с достаточным буфером.
        int needed = engineGetOutputSize(Math.max(inputLen, 0));
        if (needed > output.length - outputOffset) {
            throw new ShortBufferException("Output buffer too small: need " + needed + " bytes");
        }
        byte[] result = engineDoFinal(input, inputOffset, inputLen);
        try {
            System.arraycopy(result, 0, output, outputOffset, result.length);
            return result.length;
        } finally {
            if (!forEncryption) {
                Arrays.fill(result, (byte) 0);
            }
        }
    }

    private void checkInitialized() {
        if (!initialized) {
            throw new IllegalStateException(
                    encryptionCompleted
                            ? "CTR-ACPKM encryption completed: re-init with a new UKM is required"
                            : "Cipher not initialized");
        }
    }
}
