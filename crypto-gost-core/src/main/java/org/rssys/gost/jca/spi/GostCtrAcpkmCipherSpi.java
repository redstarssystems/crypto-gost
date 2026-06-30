package org.rssys.gost.jca.spi;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import org.rssys.gost.cipher.Kuznyechik;
import org.rssys.gost.cipher.ParametersWithIV;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.cipher.mode.CtrAcpkmMode;
import org.rssys.gost.jca.key.GostSecretKey;
import org.rssys.gost.util.CryptoRandom;

/**
 * JCA SPI для Кузнечик-CTR-ACPKM (RFC 9337 §5).
 * <p>
 * Два варианта — два внутренних подкласса, регистрируются как отдельные
 * {@code Cipher.*} в {@link org.rssys.gost.jca.RssysGostProvider}:
 * <ul>
 *   <li>{@link WithoutOmac} — {@code "Kuznyechik/CTR-ACPKM/NoPadding"}</li>
 *   <li>{@link WithOmac} — {@code "Kuznyechik/CTR-ACPKM-OMAC/NoPadding"}</li>
 * </ul>
 * <p>
 * Внутреннее использование в {@code GostPbes2} предпочтительнее через прямой
 * вызов {@link CtrAcpkmMode}, не через JCA — так обходятся накладные расходы
 * JCA на маршаллинг ключей и параметров.
 */
public class GostCtrAcpkmCipherSpi extends CipherSpi {

    /** Без OMAC — чистый CTR-ACPKM. */
    public static final class WithoutOmac extends GostCtrAcpkmCipherSpi {
        public WithoutOmac() {
            super(false);
        }
    }

    /** С OMAC — CTR-ACPKM с CMAC (Encrypt-then-MAC). */
    public static final class WithOmac extends GostCtrAcpkmCipherSpi {
        public WithOmac() {
            super(true);
        }
    }

    private static final int UKM_LEN = 16;
    private static final int TAG_LEN = 16;

    private final boolean useOmac;
    private boolean forEncryption;
    private SymmetricKey keyParam;
    private CtrAcpkmMode mode;
    private byte[] ukm;
    private boolean initialized;

    private byte[] inputBuffer = new byte[0];

    GostCtrAcpkmCipherSpi(boolean useOmac) {
        this.useOmac = useOmac;
    }

    /**
     * Абстрактный метод CipherSpi. Не вызывается JCA при регистрации полной
     * трансформации (Cipher.alg/mode/padding), но обязан быть реализован.
     */
    @Override
    protected void engineSetMode(String modeStr) throws java.security.NoSuchAlgorithmException {
        if (!"CTR-ACPKM".equalsIgnoreCase(modeStr) && !"CTR-ACPKM-OMAC".equalsIgnoreCase(modeStr)) {
            throw new java.security.NoSuchAlgorithmException(
                    "Only CTR-ACPKM/CTR-ACPKM-OMAC supported, got: " + modeStr);
        }
    }

    /**
     * Абстрактный метод CipherSpi. Не вызывается JCA при регистрации полной
     * трансформации, но обязан быть реализован.
     */
    @Override
    protected void engineSetPadding(String padding) throws javax.crypto.NoSuchPaddingException {
        if (!"NoPadding".equalsIgnoreCase(padding)) {
            throw new javax.crypto.NoSuchPaddingException("Only NoPadding supported for CTR-ACPKM");
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
        int total = inputBuffer.length + inputLen;
        if (useOmac && forEncryption) return total + TAG_LEN;
        if (useOmac && !forEncryption) return Math.max(0, total - TAG_LEN);
        return total;
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    @Override
    protected void engineInit(
            int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        this.keyParam = extractSymmetricKey(key);
        forEncryption =
                (opmode == javax.crypto.Cipher.ENCRYPT_MODE
                        || opmode == javax.crypto.Cipher.WRAP_MODE);

        if (params instanceof IvParameterSpec ivp) {
            byte[] iv = ivp.getIV();
            if (useOmac && iv.length != UKM_LEN) {
                throw new InvalidAlgorithmParameterException(
                        "CTR-ACPKM-OMAC requires 16-byte UKM, got " + iv.length);
            }
            if (!useOmac && iv.length < 8) {
                throw new InvalidAlgorithmParameterException(
                        "CTR-ACPKM requires UKM of at least 8 bytes, got " + iv.length);
            }
            this.ukm = Arrays.copyOf(iv, iv.length);
        } else if (params == null) {
            if (forEncryption) {
                this.ukm = new byte[useOmac ? UKM_LEN : 8];
                (random != null ? random : CryptoRandom.INSTANCE).nextBytes(ukm);
            } else {
                throw new InvalidAlgorithmParameterException(
                        "CTR-ACPKM decryption requires UKM (IvParameterSpec)");
            }
        } else {
            throw new InvalidAlgorithmParameterException("Use IvParameterSpec for CTR-ACPKM");
        }

        this.mode = new CtrAcpkmMode(new Kuznyechik(), useOmac);
        this.mode.init(forEncryption, new ParametersWithIV(keyParam, ukm));
        this.inputBuffer = new byte[0];
        this.initialized = true;
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        AlgorithmParameterSpec spec = null;
        if (params != null) {
            try {
                spec = params.getParameterSpec(IvParameterSpec.class);
            } catch (Exception e) {
                throw new InvalidAlgorithmParameterException("Cannot extract IvParameterSpec", e);
            }
        }
        engineInit(opmode, key, spec, random);
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        try {
            engineInit(opmode, key, (AlgorithmParameterSpec) null, random);
        } catch (InvalidAlgorithmParameterException e) {
            throw new InvalidKeyException("Init failed: " + e.getMessage(), e);
        }
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        checkInitialized();
        if (useOmac) {
            appendToBuffer(input, inputOffset, inputLen);
            return new byte[0];
        }
        byte[] result = new byte[inputLen];
        mode.processBytes(input, inputOffset, inputLen, result, 0);
        return result;
    }

    @Override
    protected int engineUpdate(
            byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException {
        byte[] result = engineUpdate(input, inputOffset, inputLen);
        if (result.length > output.length - outputOffset) {
            throw new ShortBufferException("Output buffer too short");
        }
        System.arraycopy(result, 0, output, outputOffset, result.length);
        return result.length;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {
        checkInitialized();
        if (input != null && inputLen > 0) {
            appendToBuffer(input, inputOffset, inputLen);
        }

        try {
            if (!useOmac) {
                byte[] result = new byte[inputBuffer.length];
                mode.processBytes(inputBuffer, 0, inputBuffer.length, result, 0);
                return result;
            }
            if (forEncryption) {
                byte[] ct = new byte[inputBuffer.length];
                mode.processBytes(inputBuffer, 0, inputBuffer.length, ct, 0);
                byte[] tag = mode.getMacTag();
                byte[] out = new byte[ct.length + TAG_LEN];
                System.arraycopy(ct, 0, out, 0, ct.length);
                System.arraycopy(tag, 0, out, ct.length, TAG_LEN);
                return out;
            }
            int ctLen = inputBuffer.length - TAG_LEN;
            if (ctLen < 0) {
                throw new AEADBadTagException("CTR-ACPKM-OMAC data too short for tag");
            }
            byte[] ct = Arrays.copyOf(inputBuffer, ctLen);
            byte[] expectedTag = Arrays.copyOfRange(inputBuffer, ctLen, inputBuffer.length);

            byte[] plaintext = new byte[ctLen];
            mode.processBytes(ct, 0, ctLen, plaintext, 0);
            byte[] computedTag = mode.getMacTag();

            if (!MessageDigest.isEqual(computedTag, expectedTag)) {
                throw new AEADBadTagException("CTR-ACPKM-OMAC tag mismatch");
            }
            return plaintext;
        } catch (AEADBadTagException e) {
            throw e;
        } finally {
            inputBuffer = new byte[0];
            keyParam = null;
        }
    }

    @Override
    protected int engineDoFinal(
            byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        byte[] result = engineDoFinal(input, inputOffset, inputLen);
        if (result.length > output.length - outputOffset) {
            throw new ShortBufferException(
                    "Output buffer too small: need " + result.length + " bytes");
        }
        System.arraycopy(result, 0, output, outputOffset, result.length);
        return result.length;
    }

    private static SymmetricKey extractSymmetricKey(Key key) throws InvalidKeyException {
        if (key == null) throw new InvalidKeyException("Key must not be null");
        if (key instanceof GostSecretKey gsk) return gsk.toSymmetricKey();
        if (key instanceof SecretKey && "RAW".equals(key.getFormat())) {
            byte[] encoded = key.getEncoded();
            if (encoded == null || encoded.length != Kuznyechik.KEY_SIZE) {
                throw new InvalidKeyException(
                        "Kuznyechik requires 32-byte key, got "
                                + (encoded == null ? "null" : encoded.length));
            }
            return new SymmetricKey(encoded);
        }
        throw new InvalidKeyException("Unsupported key type: " + key.getClass().getName());
    }

    private void appendToBuffer(byte[] input, int offset, int len) {
        if (len <= 0) return;
        byte[] newBuf = new byte[inputBuffer.length + len];
        System.arraycopy(inputBuffer, 0, newBuf, 0, inputBuffer.length);
        System.arraycopy(input, offset, newBuf, inputBuffer.length, len);
        inputBuffer = newBuf;
    }

    private void checkInitialized() {
        if (!initialized) {
            throw new IllegalStateException("Cipher not initialized");
        }
    }
}
