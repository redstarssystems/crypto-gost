package org.rssys.gost.jca.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.Objects;
import org.rssys.gost.signature.NonceMode;

/**
 * JCA {@link AlgorithmParameterSpec} для выбора режима нонса подписи ГОСТ Р 34.10-2012.
 *
 * <p>Передаётся через {@code Signature.setParameter(spec)}. Режим сохраняется между вызовами
 * {@code initSign}: это параметр подписи, а не свойство ключа, и он меняется только новым
 * {@code setParameter}. Пока параметр не задан, действует {@link NonceMode#DEFAULT}. Режим
 * влияет только на подпись; на проверку подписи он не влияет.
 *
 * <pre>{@code
 * Signature sig = Signature.getInstance("ECGOST3410-2012-256", provider);
 * sig.setParameter(new GostSignatureParameterSpec(NonceMode.DETERMINISTIC));
 * sig.initSign(privateKey);
 * }</pre>
 *
 * <p>Источник случайности для гибридного режима задаётся стандартно, вторым аргументом
 * {@code initSign(key, random)}; без него используется {@code CryptoRandom.INSTANCE}.
 */
public final class GostSignatureParameterSpec implements AlgorithmParameterSpec {

    private final NonceMode nonceMode;

    /**
     * @param nonceMode режим нонса (не {@code null})
     * @throws IllegalArgumentException если режим равен {@code null}
     */
    public GostSignatureParameterSpec(NonceMode nonceMode) {
        if (nonceMode == null) {
            throw new IllegalArgumentException("nonceMode must not be null");
        }
        this.nonceMode = nonceMode;
    }

    /**
     * @return режим нонса
     */
    public NonceMode getNonceMode() {
        return nonceMode;
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof GostSignatureParameterSpec that && nonceMode == that.nonceMode;
    }

    @Override
    public int hashCode() {
        return Objects.hash(nonceMode);
    }

    @Override
    public String toString() {
        return "GostSignatureParameterSpec[nonceMode=" + nonceMode + "]";
    }
}
