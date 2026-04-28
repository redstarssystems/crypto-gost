package org.rssys.gost.jca.key;

import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.signature.PublicKeyParameters;

import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PublicKey;

/**
 * Открытый ключ ГОСТ Р 34.10-2012, реализующий {@link PublicKey}.
 * <p>
 * Хранит {@link PublicKeyParameters} и предоставляет совместимый с JCA интерфейс.
 * DER-кодирование в формате X.509 SubjectPublicKeyInfo выполняется
 * через {@link GostDerCodec#encodePublicKey(PublicKeyParameters)}.
 * <p>
 * Координаты точки Q кодируются в порядке little-endian (x_LE || y_LE),
 * согласно RFC 4491 §2.3.2.
 * <p>
 * <b>Безопасность:</b> сериализация объекта запрещена — {@link #writeObject} и
 * {@link #readObject} бросают {@link NotSerializableException}.
 */
public final class GostECPublicKey implements PublicKey {

    private static final long serialVersionUID = 1L;

    /** Имя алгоритма, регистрируемое в JCA. */
    public static final String ALGORITHM = "ECGOST3410-2012";

    /** Низкоуровневые параметры открытого ключа. */
    private final PublicKeyParameters params;

    /**
     * @param params параметры открытого ключа
     * @throws IllegalArgumentException если {@code params} равен {@code null}
     */
    public GostECPublicKey(PublicKeyParameters params) {
        if (params == null) {
            throw new IllegalArgumentException("PublicKeyParameters must not be null");
        }
        this.params = params;
    }

    /** @return {@code "ECGOST3410-2012"} */
    @Override
    public String getAlgorithm() {
        return ALGORITHM;
    }

    /** @return {@code "X.509"} — стандартный формат для открытых ключей */
    @Override
    public String getFormat() {
        return "X.509";
    }

    /**
     * Возвращает DER-кодирование ключа в формате X.509 SubjectPublicKeyInfo.
     * <p>
     * Структура:
     * <pre>
     * SubjectPublicKeyInfo ::= SEQUENCE {
     *   AlgorithmIdentifier,
     *   BIT STRING { OCTET STRING x_LE || y_LE }
     * }
     * </pre>
     *
     * @return DER-байты, или {@code null} если кодирование недоступно
     */
    @Override
    public byte[] getEncoded() {
        try {
            return GostDerCodec.encodePublicKey(params);
        } catch (Exception e) {
            // Стандарт Key.getEncoded() разрешает вернуть null при ошибке
            return null;
        }
    }

    /**
     * Возвращает низкоуровневые параметры открытого ключа.
     *
     * @return {@link PublicKeyParameters}
     */
    public PublicKeyParameters toPublicKeyParameters() {
        return params;
    }

    /**
     * Запрещает сериализацию — открытый ключ не должен попадать в поток.
     * Для передачи используйте {@link #getEncoded()} (DER X.509).
     *
     * @throws NotSerializableException всегда
     */
    private void writeObject(ObjectOutputStream out) throws IOException {
        throw new NotSerializableException("GostECPublicKey must not be serialized");
    }

    /**
     * Запрещает десериализацию — используйте {@link java.security.KeyFactory} с
     * {@link java.security.spec.X509EncodedKeySpec} для восстановления ключа из DER.
     *
     * @throws NotSerializableException всегда
     */
    private void readObject(ObjectInputStream in) throws IOException {
        throw new NotSerializableException("GostECPublicKey must not be deserialized");
    }
}
