package org.rssys.gost.crossval.kuznyechik;

import org.bouncycastle.crypto.engines.GOST3412_2015Engine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.modes.OFBBlockCipher;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.util.Arrays;

/**
 * Stateless обёртка над BouncyCastle для ГОСТ Р 34.12-2015 (Кузнечик).
 *
 * Каждый метод создаёт свежий экземпляр шифра — накопление состояния
 * между вызовами исключено, что гарантирует изоляцию тестов.
 *
 * BouncyCastle использует свою терминологию режимов:
 * SICBlockCipher = CTR, все остальные — прямое отображение.
 */
public final class BcHelper {

    private BcHelper() {}

    /**
     * BC SICBlockCipher (CTR) с ГОСТ Р 34.13-2015 совместимостью.
     *
     * ГОСТ Р 34.13-2015 §4.4: CTR-IV = 8 байт, счётчик = IV || 0x00..00 (8 нулей).
     * SICBlockCipher принимает 16-байтный IV, поэтому расширяем iv8 нулями.
     */
    public static byte[] bcCtr(byte[] data, byte[] key, byte[] iv8) {
        if (data.length == 0) return new byte[0];
        byte[] counterBlock = new byte[16];
        System.arraycopy(iv8, 0, counterBlock, 0, Math.min(iv8.length, 8));
        SICBlockCipher blockCipher = new SICBlockCipher(new GOST3412_2015Engine());
        blockCipher.init(true, new ParametersWithIV(new KeyParameter(key), counterBlock));
        byte[] output = new byte[data.length];
        blockCipher.processBytes(data, 0, data.length, output, 0);
        return output;
    }

    /**
     * BC CBC с PKCS7 паддингом.
     */
    public static byte[] bcCbcPad(byte[] data, byte[] key, byte[] iv, boolean encrypt) {
        if (data.length == 0 && !encrypt) {
            CBCBlockCipher blockCipher = new CBCBlockCipher(new GOST3412_2015Engine());
            blockCipher.init(false, new ParametersWithIV(new KeyParameter(key), iv));
            return new byte[0];
        }
        PaddedBufferedBlockCipher blockCipher = new PaddedBufferedBlockCipher(
                new CBCBlockCipher(new GOST3412_2015Engine()), new PKCS7Padding());
        blockCipher.init(encrypt, new ParametersWithIV(new KeyParameter(key), iv));
        byte[] outputBuffer = new byte[blockCipher.getOutputSize(data.length)];
        int processLen = blockCipher.processBytes(data, 0, data.length, outputBuffer, 0);
        try {
            int totalLen = blockCipher.doFinal(outputBuffer, processLen);
            return Arrays.copyOf(outputBuffer, processLen + totalLen);
        } catch (Exception e) {
            throw new RuntimeException("bcCbcPad завершился ошибкой", e);
        }
    }

    /**
     * BC CBC без паддинга (кратно 16 байтам).
     */
    public static byte[] bcCbc(byte[] data, byte[] key, byte[] iv, boolean encrypt) {
        if (data.length == 0) return new byte[0];
        CBCBlockCipher blockCipher = new CBCBlockCipher(new GOST3412_2015Engine());
        blockCipher.init(encrypt, new ParametersWithIV(new KeyParameter(key), iv));
        byte[] output = new byte[data.length];
        for (int offset = 0; offset < data.length; offset += 16) {
            blockCipher.processBlock(data, offset, output, offset);
        }
        return output;
    }

    /**
     * BC CFB с полным блоком (128 бит).
     */
    public static byte[] bcCfb(byte[] data, byte[] key, byte[] iv, boolean encrypt) {
        if (data.length == 0) return new byte[0];
        CFBBlockCipher blockCipher = new CFBBlockCipher(new GOST3412_2015Engine(), 128);
        blockCipher.init(encrypt, new ParametersWithIV(new KeyParameter(key), iv));
        byte[] output = new byte[data.length];
        blockCipher.processBytes(data, 0, data.length, output, 0);
        return output;
    }

    /**
     * BC OFB с полным блоком (128 бит).
     */
    public static byte[] bcOfb(byte[] data, byte[] key, byte[] iv, boolean encrypt) {
        if (data.length == 0) return new byte[0];
        OFBBlockCipher blockCipher = new OFBBlockCipher(new GOST3412_2015Engine(), 128);
        blockCipher.init(encrypt, new ParametersWithIV(new KeyParameter(key), iv));
        byte[] output = new byte[data.length];
        blockCipher.processBytes(data, 0, data.length, output, 0);
        return output;
    }
}
