package org.rssys.gost.jca.key;

import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.signature.PrivateKeyParameters;

import javax.security.auth.Destroyable;
import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;

/**
 * Закрытый ключ ГОСТ Р 34.10-2012, реализующий {@link PrivateKey}.
 * <p>
 * Хранит {@link PrivateKeyParameters} и предоставляет совместимый с JCA интерфейс.
 * DER-кодирование в формате PKCS#8 PrivateKeyInfo выполняется через
 * {@link GostDerCodec#encodePrivateKey(PrivateKeyParameters)}.
 * <p>
 * Реализует {@link Destroyable}: вызов {@link #destroy()} делегирует
 * {@link PrivateKeyParameters#destroy()}, обнуляя ключевой материал d.
 * После уничтожения {@link #getEncoded()} возвращает {@code null}.
 * <p>
 * <b>Безопасность:</b> сериализация объекта запрещена — {@link #writeObject} и
 * {@link #readObject} бросают {@link NotSerializableException}.
 * Ключевой материал не должен попадать в поток сериализации.
 */
public final class GostECPrivateKey implements PrivateKey, Destroyable {

    private static final long serialVersionUID = 1L;

    /** Имя алгоритма, регистрируемое в JCA. */
    public static final String ALGORITHM = "ECGOST3410-2012";

    /** Низкоуровневые параметры закрытого ключа. */
    private final PrivateKeyParameters params;

    /**
     * @param params параметры закрытого ключа
     * @throws IllegalArgumentException если {@code params} равен {@code null}
     */
    public GostECPrivateKey(PrivateKeyParameters params) {
        if (params == null) {
            throw new IllegalArgumentException("PrivateKeyParameters must not be null");
        }
        this.params = params;
    }

    @Override
    public String getAlgorithm() {
        return ALGORITHM;
    }

    /** @return {@code "PKCS#8"} — стандартный формат для закрытых ключей */
    @Override
    public String getFormat() {
        return "PKCS#8";
    }

    /**
     * Возвращает DER-кодирование ключа в формате PKCS#8 PrivateKeyInfo.
     * <p>
     * Структура:
     * <pre>
     * PrivateKeyInfo ::= SEQUENCE {
     *   version    INTEGER (0),
     *   AlgorithmIdentifier,
     *   OCTET STRING { OCTET STRING d }
     * }
     * </pre>
     *
     * @return DER-байты, или {@code null} если ключ уничтожен или произошла ошибка
     */
    @Override
    public byte[] getEncoded() {
        if (params.isDestroyed()) {
            return null;
        }
        try {
            return GostDerCodec.encodePrivateKey(params);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Обнуляет закрытый ключ d в памяти.
     * Делегирует {@link PrivateKeyParameters#destroy()}.
     */
    @Override
    public void destroy() {
        params.destroy();
    }

    @Override
    public boolean isDestroyed() {
        return params.isDestroyed();
    }

    /**
     * Возвращает низкоуровневые параметры закрытого ключа.
     *
     * @return {@link PrivateKeyParameters}
     * @throws IllegalStateException если ключ уничтожен
     */
    public PrivateKeyParameters toPrivateKeyParameters() {
        if (params.isDestroyed()) {
            throw new IllegalStateException("GostECPrivateKey has been destroyed");
        }
        return params;
    }

    /**
     * Запрещает сериализацию — закрытый ключ не должен попадать в поток.
     *
     * @throws NotSerializableException всегда
     */
    private void writeObject(ObjectOutputStream out) throws IOException {
        throw new NotSerializableException("GostECPrivateKey must not be serialized");
    }

    /**
     * Запрещает десериализацию — закрытый ключ не должен восстанавливаться из потока.
     *
     * @throws NotSerializableException всегда
     */
    private void readObject(ObjectInputStream in) throws IOException {
        throw new NotSerializableException("GostECPrivateKey must not be deserialized");
    }
}
