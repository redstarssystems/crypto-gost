package org.rssys.gost.tls13.cert;

import org.rssys.gost.jca.RssysGostProvider;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.jca.key.GostECPrivateKey;
import org.rssys.gost.signature.PrivateKeyParameters;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Загрузчик PKCS12 (PFX) для GOST TLS 1.3 (RFC 7292).
 * <p>
 * Основан на встроенном JDK KeyStore (PKCS12).
 * Для работы с GOST-ключами требуется провайдер {@link RssysGostProvider}.
 * Провайдер регистрируется автоматически при первой загрузке класса.
 * <p>
 * PKCS12 от КриптоПро использует нестандартное GOST PBE
 * и в данной версии не поддерживается.
 * <p>
 * Конвертация КриптоПро → standard:
 * openssl pkcs12 -in cryptopro.p12 -out standard.p12
 *   -nodes -password pass:old -new-password pass:new
 *   (требует gost-engine для OpenSSL)
 */
public final class Pkcs12Loader {

    static {
        if (Security.getProvider("RssysGostProvider") == null) {
            Security.addProvider(new RssysGostProvider());
        }
    }

    private Pkcs12Loader() {
    }

    /**
     * Результат загрузки PKCS12: закрытый ключ + цепочка сертификатов.
     *
     * <p>Цепочка упорядочена leaf-first per RFC 8446 §4.4.2:
     * {@code chain[0]} — сертификат субъекта (leaf),
     * {@code chain[1..n-1]} — промежуточные CA,
     * {@code chain[n-1]} — корневой CA (если присутствует в контейнере).
     */
    public static final class Result {
        private final PrivateKeyParameters privateKey;
        private final List<TlsCertificate> certificateChain;

        Result(PrivateKeyParameters privateKey, List<TlsCertificate> certificateChain) {
            this.privateKey = privateKey;
            this.certificateChain = certificateChain;
        }

        /** @return закрытый ключ */
        public PrivateKeyParameters getPrivateKey() {
            return privateKey;
        }

        /**
         * @return цепочка сертификатов (leaf first per RFC 8446 §4.4.2)
         */
        public List<TlsCertificate> getCertificateChain() {
            return certificateChain;
        }
    }

    /**
     * Загружает PKCS12-файл и извлекает закрытый ключ + цепочку сертификатов.
     *
     * @param pfxData  DER-байты PFX-контейнера
     * @param password пароль для расшифровки
     * @return Result с ключом и цепочкой сертификатов
     * @throws IllegalArgumentException при неверном пароле, повреждённых данных
     *                                   или неподдерживаемом формате
     */
    public static Result load(byte[] pfxData, char[] password) {
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(new ByteArrayInputStream(pfxData), password);

            // Берём первый key entry
            String alias = null;
            java.util.Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
                String a = aliases.nextElement();
                if (ks.isKeyEntry(a)) {
                    alias = a;
                    break;
                }
            }
            if (alias == null) {
                throw new IllegalArgumentException("PKCS12: no private key found");
            }

            PrivateKey jdkKey = (PrivateKey) ks.getKey(alias, password);
            PrivateKeyParameters ourKey = adaptPrivateKey(jdkKey);

            Certificate[] jdkChain = ks.getCertificateChain(alias);
            List<TlsCertificate> ourChain = new ArrayList<>();
            for (Certificate cert : jdkChain) {
                ourChain.add(new TlsCertificate(cert.getEncoded()));
            }

            return new Result(ourKey, ourChain);

        } catch (IOException e) {
            String msg = e.getMessage();
            if (msg != null && msg.contains("wrong password")) {
                throw new IllegalArgumentException("PKCS12: wrong password", e);
            }
            throw new IllegalArgumentException("PKCS12: " + e.getMessage(), e);
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalArgumentException("PKCS12: " + e.getMessage(), e);
        }
    }

    /**
     * Адаптирует JDK PrivateKey в наш PrivateKeyParameters.
     *
     * @param jdkKey JDK-ключ из KeyStore
     * @return адаптированный ключ
     */
    public static PrivateKeyParameters adaptPrivateKey(PrivateKey jdkKey) {
        if (jdkKey instanceof GostECPrivateKey) {
            return ((GostECPrivateKey) jdkKey).toPrivateKeyParameters();
        }
        return GostDerCodec.decodePrivateKey(jdkKey.getEncoded());
    }
}
