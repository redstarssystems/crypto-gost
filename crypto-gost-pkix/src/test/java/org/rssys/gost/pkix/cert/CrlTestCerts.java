package org.rssys.gost.pkix.cert;

import java.math.BigInteger;
import org.rssys.gost.api.GostSigner;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PublicKeyParameters;

/**
 * Проверяемые сертификаты для тестов CRL.
 *
 * <p>{@link CrlVerifier} принимает {@link GostCertificate}, а не пару «серийный номер + issuer
 * DN»: область CRL зависит от признака CA и от CDP. Тестам, у которых есть только номер и DN,
 * нужен настоящий сертификат с этими полями; ключ у всех общий и одноразовый.</p>
 */
final class CrlTestCerts {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static final KeyPair KEY = KeyGenerator.generateKeyPair(PARAMS);

    private CrlTestCerts() {}

    /**
     * Сертификат издателя CRL с заданным ключом и без KeyUsage: такой издатель вправе подписывать
     * CRL (RFC 5280 §4.2.1.3). Нужен тестам, у которых есть только пара ключей CA.
     */
    static GostCertificate issuerOf(PublicKeyParameters issuerKey) {
        return issuerOf(issuerKey, new GostCertificateBuilder.KeyUsage[0]);
    }

    /**
     * Сертификат издателя CRL с заданным ключом и набором KeyUsage; пустой набор - расширения нет.
     */
    static GostCertificate issuerOf(
            PublicKeyParameters issuerKey, GostCertificateBuilder.KeyUsage... usages) {
        GostCertificateBuilder builder =
                GostCertificateBuilder.create(PARAMS, "CN=CRL Test Issuer,O=Test,C=RU")
                        .publicKey(issuerKey)
                        .notBefore("250101000000Z")
                        .notAfter("350101000000Z")
                        .serial(BigInteger.ONE)
                        .basicConstraints(true, null);
        if (usages.length > 0) {
            builder.keyUsage(usages);
        }
        return GostCertificateBuilder.sign(builder.buildTbs(), GostSigner.of(KEY.getPrivate()));
    }

    /**
     * Конечный сертификат с заданными серийным номером и issuer DN (DER).
     * <p>
     * Серийный номер по RFC 5280 §4.1.2.2 положителен, а байты приходят в том числе от фаззера
     * (пустой или нулевой массив): нулевое значение заменяется единицей, иначе билдер законно
     * отверг бы вход и фаззинг-тест падал бы на помощнике, а не на проверяемом коде.
     */
    static GostCertificate certFor(byte[] serial, byte[] issuerDn) {
        BigInteger serialNumber = new BigInteger(1, serial);
        if (serialNumber.signum() == 0) {
            serialNumber = BigInteger.ONE;
        }
        return GostCertificateBuilder.sign(
                GostCertificateBuilder.create(PARAMS, "CN=CRL Test Subject,O=Test,C=RU")
                        .publicKey(KEY.getPublic())
                        .issuerDn(issuerDn)
                        .notBefore("250101000000Z")
                        .notAfter("350101000000Z")
                        .serial(serialNumber)
                        .buildTbs(),
                GostSigner.of(KEY.getPrivate()));
    }
}
