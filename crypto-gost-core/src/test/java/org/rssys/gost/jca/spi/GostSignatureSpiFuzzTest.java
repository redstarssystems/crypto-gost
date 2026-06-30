package org.rssys.gost.jca.spi;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.ECGenParameterSpec;
import org.rssys.gost.jca.RssysGostProvider;

/**
 * Fuzz-тесты для {@link GostSignatureSpi#engineVerify}.
 * <p>
 * Проверяет JCA entry point верификации подписи: Signature.getInstance("ECGOST3410-2012-256")
 * с произвольными байтами подписи. Путь: engineVerify -> Signature.verify ->
 * SignatureCodec.decode -> ECDSASigner.verifySignature.
 * <p>
 * ПОЧЕМУ ловим только SignatureException: engineVerify использует
 * {@code catch (Exception e)} и заворачивает всё в SignatureException.
 * Если NPE/AIOOBE не будут перехвачены — Jazzer увидит их как баг.
 */
class GostSignatureSpiFuzzTest {

    private static final String PROVIDER = RssysGostProvider.PROVIDER_NAME;
    private static final byte[] MSG =
            "fuzz test message".getBytes(java.nio.charset.StandardCharsets.UTF_8);

    private static final KeyPair KEY_PAIR;
    private static final java.security.PublicKey PUBLIC_KEY;

    static {
        if (Security.getProvider(RssysGostProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new RssysGostProvider());
        }
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECGOST3410-2012", PROVIDER);
            kpg.initialize(new ECGenParameterSpec("cryptopro-A"));
            KEY_PAIR = kpg.generateKeyPair();
            PUBLIC_KEY = KEY_PAIR.getPublic();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate key pair", e);
        }
    }

    /**
     * Подаёт произвольные байты подписи в engineVerify с фиксированным
     * открытым ключом и фиксированным сообщением.
     * <p>
     * SignatureCodec.decode вызывается внутри engineVerify и получает
     * произвольные байты — проверка длины (64 байта) отсекает большинство
     * вариантов, но те, что проходят, попадают в ECDSASigner.verifySignature.
     */
    @FuzzTest
    void fuzzEngineVerify(FuzzedDataProvider data) {
        byte[] sigBytes = data.consumeRemainingAsBytes();
        if (sigBytes.length == 0) return;
        try {
            Signature verifier = Signature.getInstance("ECGOST3410-2012-256", PROVIDER);
            verifier.initVerify(PUBLIC_KEY);
            verifier.update(MSG);
            verifier.verify(sigBytes);
        } catch (SignatureException e) {
            // Ожидаемо: неверная длина подписи, неверный r/s, неверная подпись
        } catch (IllegalStateException e) {
            // Ожидаемо: engine не инициализирован
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException e) {
            // Ожидаемо: JCA-initialisation ошибки
        }
    }

    /**
     * Подаёт произвольные байты как данные + произвольную подпись.
     * Покрывает path: engineUpdate -> engineVerify с битыми данными и подписью.
     */
    @FuzzTest
    void fuzzEngineUpdateAndVerify(FuzzedDataProvider data) {
        byte[] msgBytes = data.consumeBytes(Math.min(data.remainingBytes(), 256));
        byte[] sigBytes = data.consumeRemainingAsBytes();
        if (msgBytes.length == 0 || sigBytes.length == 0) return;
        try {
            Signature verifier = Signature.getInstance("ECGOST3410-2012-256", PROVIDER);
            verifier.initVerify(PUBLIC_KEY);
            verifier.update(msgBytes);
            verifier.verify(sigBytes);
        } catch (SignatureException e) {
            // Ожидаемо
        } catch (IllegalStateException e) {
            // Ожидаемо
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException e) {
            // Ожидаемо: JCA-initialisation ошибки
        }
    }
}
