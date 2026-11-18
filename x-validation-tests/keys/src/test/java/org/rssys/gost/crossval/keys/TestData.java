package org.rssys.gost.crossval.keys;

import org.rssys.gost.signature.ECParameters;

import java.util.function.Supplier;

/**
 * Описания кривых ГОСТ Р 34.10-2012 для кросс-валидации ключей.
 *
 * Каждая кривая описывается именем, разрядностью, фабрикой параметров
 * и флагами совместимости с OpenSSL.
 * TC26-A-256 в engine gost называется paramset TCA (имя D не существует); ECDH на ней
 * с OpenSSL здесь не проверяется: кофактор 4 покрыт в кросс-валидации TLS.
 */
public final class TestData {

    public record CurveSpec(String name, String bits,
                            Supplier<ECParameters> paramsFn,
                            boolean opensslGenSupported,
                            boolean opensslReadSupported,
                            boolean ecdhSupported,
                            String opensslAlgo,
                            String opensslParamset) {
        @Override
        public String toString() { return name; }
    }

    public static final CurveSpec[] CURVES = {
        new CurveSpec("TC26-A-256",  "256", ECParameters::tc26a256,   true,  true,  false,
                "gost2012_256", "TCA"),
        new CurveSpec("CryptoPro-A", "256", ECParameters::cryptoProA, true,  true,  true,
                "gost2012_256", "A"),
        new CurveSpec("CryptoPro-B", "256", ECParameters::cryptoProB, true,  true,  true,
                "gost2012_256", "B"),
        new CurveSpec("CryptoPro-C", "256", ECParameters::cryptoProC, true,  true,  true,
                "gost2012_256", "C"),
        new CurveSpec("TC26-A-512",  "512", ECParameters::tc26a512,   true,  true,  true,
                "gost2012_512", "A"),
        new CurveSpec("TC26-B-512",  "512", ECParameters::tc26b512,   true,  true,  true,
                "gost2012_512", "B"),
        new CurveSpec("TC26-C-512",  "512", ECParameters::tc26c512,   true,  true,  true,
                "gost2012_512", "C"),
    };

    private TestData() {}
}
