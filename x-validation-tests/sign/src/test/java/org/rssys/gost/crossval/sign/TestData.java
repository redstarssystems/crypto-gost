package org.rssys.gost.crossval.sign;

import org.rssys.gost.signature.ECParameters;

import org.rssys.gost.util.CryptoRandom;
import java.util.function.Supplier;

/**
 * Описания кривых и данные для кросс-валидации подписи ГОСТ Р 34.10-2012.
 *
 * OpenSSL поддерживает CryptoPro-A/B/C (gost2012_256, paramset A/B/C)
 * и TC26-A/B/C-512 (gost2012_512, paramset A/B/C).
 * Для каждой кривой указана разрядность подписи (rolen = 32 для 256 бит,
 * 64 для 512 бит) и флаг совместимости с OpenSSL.
 */
public final class TestData {

    public record CurveSpec(String name, String bits,
                            Supplier<ECParameters> paramsFn,
                            int rolen,
                            boolean opensslSupported,
                            String opensslAlgo,
                            String opensslParamset) {}

    public static final CurveSpec[] CURVES = {
        new CurveSpec("TC26-A-256",  "256", ECParameters::tc26a256,   32, false, null, null),
        new CurveSpec("CryptoPro-A", "256", ECParameters::cryptoProA, 32, true,
                "gost2012_256", "A"),
        new CurveSpec("CryptoPro-B", "256", ECParameters::cryptoProB, 32, true,
                "gost2012_256", "B"),
        new CurveSpec("CryptoPro-C", "256", ECParameters::cryptoProC, 32, true,
                "gost2012_256", "C"),
        new CurveSpec("TC26-A-512",  "512", ECParameters::tc26a512,   64, true,
                "gost2012_512", "A"),
        new CurveSpec("TC26-B-512",  "512", ECParameters::tc26b512,   64, true,
                "gost2012_512", "B"),
        new CurveSpec("TC26-C-512",  "512", ECParameters::tc26c512,   64, true,
                "gost2012_512", "C"),
    };

    public static final int NUM_MESSAGES = 100;
    public static final int MSG_SIZE = 1024;
    public static final int OPENSSL_NUM_MESSAGES = 10;

    private TestData() {}

    public static byte[] randomMessage(int size) {
        byte[] data = new byte[size];
        CryptoRandom.INSTANCE.nextBytes(data);
        return data;
    }

    public static byte[][] randomMessages(int count, int size) {
        byte[][] msgs = new byte[count][size];
        for (int i = 0; i < count; i++) msgs[i] = randomMessage(size);
        return msgs;
    }
}
