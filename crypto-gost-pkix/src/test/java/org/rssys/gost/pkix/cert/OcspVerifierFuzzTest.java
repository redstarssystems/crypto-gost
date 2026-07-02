package org.rssys.gost.pkix.cert;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PublicKeyParameters;

/**
 * Fuzz-тесты для {@link OcspVerifier} — низкоуровневый API (package-private).
 */
class OcspVerifierFuzzTest {

    private static PublicKeyParameters caKey;

    static {
        caKey = KeyGenerator.generateKeyPair(ECParameters.tc26a256()).getPublic();
    }

    @FuzzTest
    void fuzzVerifyWithCertId(FuzzedDataProvider data) {
        byte[] ocspResponse = data.consumeBytes(data.consumeInt(0, 65536));
        byte[] serialNumber = data.consumeBytes(data.consumeInt(0, 32));
        byte[] issuerDn = data.consumeBytes(data.consumeInt(0, 256));
        byte[] issuerCert = data.consumeBytes(data.consumeInt(0, 4096));
        if (ocspResponse.length == 0) return;
        try {
            OcspVerifier.verify(ocspResponse, serialNumber, caKey, issuerDn, issuerCert);
        } catch (PkixException e) {
            // Ожидаемо
        } catch (RuntimeException e) {
            rethrowIfBug(e);
        }
    }

    @FuzzTest
    void fuzzVerify(FuzzedDataProvider data) {
        byte[] ocspResponse = data.consumeBytes(data.consumeInt(0, 65536));
        byte[] serialNumber = data.consumeBytes(data.consumeInt(0, 32));
        if (ocspResponse.length == 0) return;
        try {
            OcspVerifier.verify(ocspResponse, serialNumber, caKey);
        } catch (PkixException e) {
            // Ожидаемо
        } catch (RuntimeException e) {
            rethrowIfBug(e);
        }
    }

    private static void rethrowIfBug(RuntimeException e) {
        if (e instanceof ArrayIndexOutOfBoundsException
                || e instanceof IndexOutOfBoundsException
                || e instanceof NegativeArraySizeException
                || e instanceof NullPointerException
                || e instanceof ClassCastException
                || e instanceof ArithmeticException
                || e instanceof java.nio.BufferOverflowException) {
            throw e;
        }
    }
}
