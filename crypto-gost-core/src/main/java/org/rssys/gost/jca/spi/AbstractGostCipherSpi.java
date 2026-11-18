package org.rssys.gost.jca.spi;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.spec.IvParameterSpec;

/**
 * Общая часть шифр-SPI провайдера: перегрузки {@code engineInit}, которые сводятся к одной точке
 * входа с {@link AlgorithmParameterSpec}, и разбор режима операции.
 *
 * <p>Режимы {@code WRAP_MODE} и {@code UNWRAP_MODE} не поддерживаются: {@code engineWrap} и
 * {@code engineUnwrap} не реализованы, а молчаливая трактовка WRAP как шифрования, а UNWRAP как
 * расшифрования обернулась бы в {@link UnsupportedOperationException} без текста уже при
 * {@code wrap()}; здесь тот же отказ выдаётся сразу при {@code init} и с понятным текстом.
 */
abstract class AbstractGostCipherSpi extends CipherSpi {

    /**
     * Определяет направление операции и отвергает режимы, которых SPI не поддерживает. Вызывается
     * первой в {@code engineInit}: до извлечения ключа и до любых изменений состояния.
     *
     * @param opmode режим {@link Cipher}
     * @return {@code true} для шифрования, {@code false} для расшифрования
     * @throws UnsupportedOperationException если режим не {@code ENCRYPT_MODE} и не
     *                                       {@code DECRYPT_MODE}
     */
    static boolean isEncrypting(int opmode) {
        return switch (opmode) {
            case Cipher.ENCRYPT_MODE -> true;
            case Cipher.DECRYPT_MODE -> false;
            default ->
                    throw new UnsupportedOperationException(
                            "Only ENCRYPT_MODE and DECRYPT_MODE are supported (key wrapping is not"
                                    + " supported), got opmode "
                                    + opmode);
        };
    }

    @Override
    protected final void engineInit(
            int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        AlgorithmParameterSpec spec = null;
        if (params != null) {
            try {
                spec = params.getParameterSpec(IvParameterSpec.class);
            } catch (InvalidParameterSpecException e) {
                throw new InvalidAlgorithmParameterException(
                        "Cannot extract IvParameterSpec from AlgorithmParameters", e);
            }
        }
        engineInit(opmode, key, spec, random);
    }

    /**
     * Инициализация без параметров допустима для шифрования со случайным IV. Сюда же приходит
     * расшифрование без IV и несовместимые параметры: сигнатура JCA не оставляет для них другого
     * исключения, кроме {@link InvalidKeyException}.
     */
    @Override
    protected final void engineInit(int opmode, Key key, SecureRandom random)
            throws InvalidKeyException {
        try {
            engineInit(opmode, key, (AlgorithmParameterSpec) null, random);
        } catch (InvalidAlgorithmParameterException e) {
            throw new InvalidKeyException(e.getMessage(), e);
        }
    }
}
