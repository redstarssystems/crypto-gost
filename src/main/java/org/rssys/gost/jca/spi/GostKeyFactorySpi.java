package org.rssys.gost.jca.spi;

import org.rssys.gost.jca.key.GostECPrivateKey;
import org.rssys.gost.jca.key.GostECPrivateKeySpec;
import org.rssys.gost.jca.key.GostECPublicKey;
import org.rssys.gost.jca.key.GostECPublicKeySpec;
import org.rssys.gost.jca.spec.GostCurves;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.ECPoint;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Реализация {@link KeyFactorySpi} для ключей ГОСТ Р 34.10-2012.
 * <p>
 * Поддерживаемые преобразования:
 * <ul>
 *   <li>{@link X509EncodedKeySpec} → {@link GostECPublicKey} (DER SubjectPublicKeyInfo)</li>
 *   <li>{@link GostECPublicKeySpec} → {@link GostECPublicKey} (сырые координаты)</li>
 *   <li>{@link PKCS8EncodedKeySpec} → {@link GostECPrivateKey} (DER PrivateKeyInfo)</li>
 *   <li>{@link GostECPrivateKeySpec} → {@link GostECPrivateKey} (сырой скаляр d)</li>
 * </ul>
 * <p>
 * Регистрируется в провайдере как {@code "ECGOST3410-2012"}.
 */
public final class GostKeyFactorySpi extends KeyFactorySpi {

    /**
     * Генерирует открытый ключ по спецификации.
     *
     * @param keySpec {@link X509EncodedKeySpec} или {@link GostECPublicKeySpec}
     * @throws InvalidKeySpecException если тип спецификации не поддерживается
     *         или данные некорректны
     */
    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof X509EncodedKeySpec) {
            byte[] encoded = ((X509EncodedKeySpec) keySpec).getEncoded();
            try {
                PublicKeyParameters params = GostDerCodec.decodePublicKey(encoded);
                return new GostECPublicKey(params);
            } catch (Exception e) {
                throw new InvalidKeySpecException(
                    "Cannot decode X.509 SubjectPublicKeyInfo: " + e.getMessage(), e);
            }
        }
        if (keySpec instanceof GostECPublicKeySpec) {
            GostECPublicKeySpec spec = (GostECPublicKeySpec) keySpec;
            try {
                ECParameters curve = GostCurves.byName(spec.getCurveName());
                ECPoint q = ECPoint.affine(spec.getX(), spec.getY(), curve);
                return new GostECPublicKey(new PublicKeyParameters(q, curve));
            } catch (IllegalArgumentException e) {
                throw new InvalidKeySpecException(
                    "Invalid GostECPublicKeySpec: " + e.getMessage(), e);
            }
        }
        throw new InvalidKeySpecException(
            "Unsupported KeySpec type: " + keySpec.getClass().getName()
            + ". Supported: X509EncodedKeySpec, GostECPublicKeySpec");
    }

    /**
     * Генерирует закрытый ключ по спецификации.
     *
     * @param keySpec {@link PKCS8EncodedKeySpec} или {@link GostECPrivateKeySpec}
     * @throws InvalidKeySpecException если тип спецификации не поддерживается
     *         или данные некорректны
     */
    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof PKCS8EncodedKeySpec) {
            byte[] encoded = ((PKCS8EncodedKeySpec) keySpec).getEncoded();
            try {
                PrivateKeyParameters params = GostDerCodec.decodePrivateKey(encoded);
                return new GostECPrivateKey(params);
            } catch (Exception e) {
                throw new InvalidKeySpecException(
                    "Cannot decode PKCS#8 PrivateKeyInfo: " + e.getMessage(), e);
            }
        }
        if (keySpec instanceof GostECPrivateKeySpec) {
            GostECPrivateKeySpec spec = (GostECPrivateKeySpec) keySpec;
            try {
                ECParameters curve = GostCurves.byName(spec.getCurveName());
                PrivateKeyParameters params = new PrivateKeyParameters(spec.getD(), curve);
                return new GostECPrivateKey(params);
            } catch (IllegalArgumentException e) {
                throw new InvalidKeySpecException(
                    "Invalid GostECPrivateKeySpec: " + e.getMessage(), e);
            }
        }
        throw new InvalidKeySpecException(
            "Unsupported KeySpec type: " + keySpec.getClass().getName()
            + ". Supported: PKCS8EncodedKeySpec, GostECPrivateKeySpec");
    }

    /**
     * Возвращает спецификацию ключа в запрошенном формате.
     *
     * @param key      ключ ({@link GostECPublicKey} или {@link GostECPrivateKey})
     * @param keyClass запрошенный класс спецификации
     * @throws InvalidKeySpecException если ключ или класс спецификации не поддерживается
     */
    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keyClass)
            throws InvalidKeySpecException {
        if (key instanceof GostECPublicKey) {
            return getPublicKeySpec((GostECPublicKey) key, keyClass);
        }
        if (key instanceof GostECPrivateKey) {
            return getPrivateKeySpec((GostECPrivateKey) key, keyClass);
        }
        throw new InvalidKeySpecException(
            "Unsupported key type: " + key.getClass().getName()
            + ". Expected GostECPublicKey or GostECPrivateKey");
    }

    @SuppressWarnings("unchecked")
    private <T extends KeySpec> T getPublicKeySpec(GostECPublicKey key, Class<T> keyClass)
            throws InvalidKeySpecException {
        if (X509EncodedKeySpec.class.isAssignableFrom(keyClass)) {
            byte[] encoded = key.getEncoded();
            if (encoded == null) {
                throw new InvalidKeySpecException("Cannot encode public key");
            }
            return (T) new X509EncodedKeySpec(encoded);
        }
        if (GostECPublicKeySpec.class.isAssignableFrom(keyClass)) {
            PublicKeyParameters params = key.toPublicKeyParameters();
            ECPoint q = params.getQ().normalize();
            String oid = GostCurves.oidOf(params.getParams());
            return (T) new GostECPublicKeySpec(q.getX(), q.getY(), oid);
        }
        throw new InvalidKeySpecException(
            "Unsupported KeySpec class for public key: " + keyClass.getName()
            + ". Supported: X509EncodedKeySpec, GostECPublicKeySpec");
    }

    @SuppressWarnings("unchecked")
    private <T extends KeySpec> T getPrivateKeySpec(GostECPrivateKey key, Class<T> keyClass)
            throws InvalidKeySpecException {
        if (PKCS8EncodedKeySpec.class.isAssignableFrom(keyClass)) {
            byte[] encoded = key.getEncoded();
            if (encoded == null) {
                throw new InvalidKeySpecException("Cannot encode private key (possibly destroyed)");
            }
            return (T) new PKCS8EncodedKeySpec(encoded);
        }
        if (GostECPrivateKeySpec.class.isAssignableFrom(keyClass)) {
            PrivateKeyParameters params = key.toPrivateKeyParameters();
            String oid = GostCurves.oidOf(params.getParams());
            return (T) new GostECPrivateKeySpec(params.getD(), oid);
        }
        throw new InvalidKeySpecException(
            "Unsupported KeySpec class for private key: " + keyClass.getName()
            + ". Supported: PKCS8EncodedKeySpec, GostECPrivateKeySpec");
    }

    /**
     * Транслирует ключ в ключ провайдера.
     * <p>
     * Если ключ уже является {@link GostECPublicKey} или {@link GostECPrivateKey} —
     * возвращается как есть. Иначе — попытка декодирования через DER-представление.
     *
     * @throws InvalidKeyException если ключ не может быть транслирован
     */
    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {
        if (key instanceof GostECPublicKey || key instanceof GostECPrivateKey) {
            return key;
        }
        // Пробуем через DER-кодирование
        if (key instanceof PublicKey) {
            byte[] encoded = key.getEncoded();
            if (encoded != null && "X.509".equals(key.getFormat())) {
                try {
                    return engineGeneratePublic(new X509EncodedKeySpec(encoded));
                } catch (InvalidKeySpecException e) {
                    throw new InvalidKeyException("Cannot translate public key", e);
                }
            }
        }
        if (key instanceof PrivateKey) {
            byte[] encoded = key.getEncoded();
            if (encoded != null && "PKCS#8".equals(key.getFormat())) {
                try {
                    return engineGeneratePrivate(new PKCS8EncodedKeySpec(encoded));
                } catch (InvalidKeySpecException e) {
                    throw new InvalidKeyException("Cannot translate private key", e);
                }
            }
        }
        throw new InvalidKeyException(
            "Cannot translate key of type: " + key.getClass().getName());
    }
}
