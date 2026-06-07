package org.rssys.gost.jca;

import org.rssys.gost.jca.spi.GostCipherSpi;
import org.rssys.gost.jca.spi.GostKeyFactorySpi;
import org.rssys.gost.jca.spi.GostKeyGeneratorSpi;
import org.rssys.gost.jca.spi.GostKeyPairGeneratorSpi;
import org.rssys.gost.jca.spi.GostMacSpi;
import org.rssys.gost.jca.spi.GostMessageDigestSpi;
import org.rssys.gost.jca.spi.GostMgmCipherSpi;
import org.rssys.gost.jca.spi.GostPbkdf2SecretKeyFactorySpi;
import org.rssys.gost.jca.spi.GostSecretKeyFactorySpi;
import org.rssys.gost.jca.spi.GostSignatureSpi;
import org.rssys.gost.jca.spi.GostCtrAcpkmCipherSpi;
import org.rssys.gost.jca.spi.GostKeyAgreementSpi;
import org.rssys.gost.jca.spi.GostVkoKeyAgreementSpi;

import java.security.Provider;

/**
 * JCA/JCE провайдер.
 *
 * <p>Имя провайдера: {@code "RssysGostProvider"}.
 *
 * <h3>Регистрируемые алгоритмы:</h3>
 *
 * <b>MessageDigest — хэш-функции Стрибог (ГОСТ Р 34.11-2012 / RFC 6986):</b>
 * <ul>
 *   <li>{@code GOST3411-2012-256} / {@code Streebog-256}, OID {@code 1.2.643.7.1.1.2.2}</li>
 *   <li>{@code GOST3411-2012-512} / {@code Streebog-512}, OID {@code 1.2.643.7.1.1.2.3}</li>
 * </ul>
 *
 * <b>Mac — коды аутентификации сообщений:</b>
 * <ul>
 *   <li>{@code HmacGOST3411-2012-256}, OID {@code 1.2.643.7.1.1.4.1} (RFC 7836 §4.1.1)</li>
 *   <li>{@code HmacGOST3411-2012-512}, OID {@code 1.2.643.7.1.1.4.2} (RFC 7836 §4.1.2)</li>
 *   <li>{@code CMAC-Kuznyechik} (ГОСТ Р 34.13-2015 §4.6)</li>
 * </ul>
 *
 * <b>Cipher — блочный шифр Кузнечик (ГОСТ Р 34.12-2015 / ГОСТ Р 34.13-2015):</b>
 * <ul>
 *   <li>{@code Kuznyechik/CTR/NoPadding}    — режим гаммирования, IV = 8 байт</li>
 *   <li>{@code Kuznyechik/CFB/NoPadding}    — режим ОС по шифртексту, IV = 16 байт</li>
 *   <li>{@code Kuznyechik/OFB/NoPadding}    — режим ОС по выходу, IV = 16 байт</li>
 *   <li>{@code Kuznyechik/CBC/PKCS5Padding}  — режим CBC с PKCS#7, IV = 16 байт</li>
 *   <li>{@code Kuznyechik/CBC/NoPadding}    — режим CBC без padding, IV = 16 байт</li>
  *   <li>{@code Kuznyechik/MGM/NoPadding}    — AEAD-режим MGM (RFC 9058), ICN = 16 байт,
 *       совместим с OpenSSL {@code kuznyechik-mgm}</li>
 * </ul>
 *
 * <b>KeyGenerator — генерация симметричных ключей:</b>
 * <ul>
 *   <li>{@code Kuznyechik} — 256-битный ключ</li>
 * </ul>
 *
 * <b>KeyPairGenerator / KeyFactory — ключи ЭП (ГОСТ Р 34.10-2012):</b>
 * <ul>
 *   <li>{@code ECGOST3410-2012}, OID {@code 1.2.643.7.1.1.1.1} (256-бит),
 *       OID {@code 1.2.643.7.1.1.1.2} (512-бит)</li>
 * </ul>
 *
 * <b>SecretKeyFactory — конвертация симметричных ключей:</b>
 * <ul>
 *   <li>{@code Kuznyechik}</li>
 * </ul>
 *
 * <b>Signature — электронная подпись (ГОСТ Р 34.10-2012 / RFC 7091):</b>
 * <ul>
 *   <li>{@code ECGOST3410-2012-256} — 256-битные кривые, OID {@code 1.2.643.7.1.1.3.2}</li>
 *   <li>{@code ECGOST3410-2012-512} — 512-битные кривые, OID {@code 1.2.643.7.1.1.3.3}</li>
 * </ul>
 *
 * <h3>Регистрация провайдера:</h3>
 * <pre>{@code
 * Security.addProvider(new RssysGostProvider());
 * // или первым приоритетом:
 * Security.insertProviderAt(new RssysGostProvider(), 1);
 * }</pre>
 */
public final class RssysGostProvider extends Provider {

    /** Имя провайдера. */
    public static final String PROVIDER_NAME = "RssysGostProvider";

    /** Версия провайдера. */
    private static final double VERSION = 1.0;

    /** Описание провайдера. */
    private static final String INFO =
        "RssysGost JCA/JCE Provider: GOST R 34.10-2012, GOST R 34.11-2012, GOST R 34.12/13-2015";

    /**
     * Создаёт и регистрирует провайдер.
     */
    public RssysGostProvider() {
        super(PROVIDER_NAME, VERSION, INFO);
        registerAlgorithms();
    }

    /** Регистрирует все алгоритмы провайдера в реестре JCA. */
    private void registerAlgorithms() {
        registerMessageDigests();
        registerMacs();
        registerCiphers();
        registerKeyGenerators();
        registerKeyPairGenerators();
        registerKeyFactories();
        registerSecretKeyFactories();
        registerKeyAgreements();
        registerVkoKeyAgreements();
        registerSignatures();
    }

    /**
     * Хэш-функции Стрибог (ГОСТ Р 34.11-2012 / RFC 6986).
     * Основные имена: GOST3411-2012-256 / GOST3411-2012-512.
     * Алиасы по коротким именам и OID.
     */
    private void registerMessageDigests() {
        String spi256 = GostMessageDigestSpi.Streebog256Spi.class.getName();
        String spi512 = GostMessageDigestSpi.Streebog512Spi.class.getName();

        // Стрибог-256
        put("MessageDigest.GOST3411-2012-256",                  spi256);
        put("Alg.Alias.MessageDigest.Streebog-256",             "GOST3411-2012-256");
        put("Alg.Alias.MessageDigest.STREEBOG256",              "GOST3411-2012-256");
        put("Alg.Alias.MessageDigest.1.2.643.7.1.1.2.2",        "GOST3411-2012-256");

        // Стрибог-512
        put("MessageDigest.GOST3411-2012-512",                  spi512);
        put("Alg.Alias.MessageDigest.Streebog-512",             "GOST3411-2012-512");
        put("Alg.Alias.MessageDigest.STREEBOG512",              "GOST3411-2012-512");
        put("Alg.Alias.MessageDigest.1.2.643.7.1.1.2.3",        "GOST3411-2012-512");
    }

    /**
     * Коды аутентификации сообщений.
     * HMAC-Стрибог по RFC 7836, CMAC-Кузнечик по ГОСТ Р 34.13-2015.
     */
    private void registerMacs() {
        String hmac256    = GostMacSpi.HmacStreebog256Spi.class.getName();
        String hmac512    = GostMacSpi.HmacStreebog512Spi.class.getName();
        String cmacKuz    = GostMacSpi.CmacKuznyechikSpi.class.getName();

        // HMAC-Стрибог-256
        put("Mac.HmacGOST3411-2012-256",                        hmac256);
        put("Alg.Alias.Mac.HMAC-Streebog-256",                  "HmacGOST3411-2012-256");
        put("Alg.Alias.Mac.1.2.643.7.1.1.4.1",                  "HmacGOST3411-2012-256");

        // HMAC-Стрибог-512
        put("Mac.HmacGOST3411-2012-512",                        hmac512);
        put("Alg.Alias.Mac.HMAC-Streebog-512",                  "HmacGOST3411-2012-512");
        put("Alg.Alias.Mac.1.2.643.7.1.1.4.2",                  "HmacGOST3411-2012-512");

        // CMAC-Кузнечик
        put("Mac.CMAC-Kuznyechik",                              cmacKuz);
        put("Alg.Alias.Mac.Kuznyechik-CMAC",                    "CMAC-Kuznyechik");
    }

    /**
     * Блочный шифр Кузнечик (ГОСТ Р 34.12-2015) в режимах ГОСТ Р 34.13-2015.
     * Трансформации вида "Kuznyechik/режим/padding".
     * MGM (RFC 9058) регистрируется отдельным SPI — у него своя семантика AEAD.
     */
    private void registerCiphers() {
        String spi    = GostCipherSpi.class.getName();
        String mgmSpi = GostMgmCipherSpi.class.getName();

        // JCA использует трансформацию "алгоритм/режим/padding";
        // регистрируем базовый алгоритм, а режим/padding задаются при getInstance
        put("Cipher.Kuznyechik",                                spi);
        put("Alg.Alias.Cipher.GOST3412-2015",                   "Kuznyechik");

        // MGM — AEAD-режим (RFC 9058), отдельный SPI с полной обработкой тега
        // OID: id-tc26-cipher-gostr3412-2015-kuznyechik-ctracpkm-omac = 1.2.643.7.1.1.5.1
        // (kuznyechik-mgm в нотации OpenSSL)
        put("Cipher.Kuznyechik-MGM",                            mgmSpi);
        put("Alg.Alias.Cipher.1.2.643.7.1.1.5.1",               "Kuznyechik-MGM");
        // Алиас в стандартной JCA-нотации алгоритм/режим/padding
        put("Alg.Alias.Cipher.Kuznyechik/MGM/NoPadding",        "Kuznyechik-MGM");

        // CTR-ACPKM (RFC 9337 §5) — два варианта, два отдельных SPI-подкласса
        String withoutOmac = GostCtrAcpkmCipherSpi.WithoutOmac.class.getName();
        String withOmac    = GostCtrAcpkmCipherSpi.WithOmac.class.getName();
        put("Cipher.Kuznyechik/CTR-ACPKM/NoPadding",            withoutOmac);
        put("Cipher.Kuznyechik/CTR-ACPKM-OMAC/NoPadding",       withOmac);
        put("Alg.Alias.Cipher.1.2.643.7.1.1.5.2.1",            "Kuznyechik/CTR-ACPKM/NoPadding");
        put("Alg.Alias.Cipher.1.2.643.7.1.1.5.2.2",            "Kuznyechik/CTR-ACPKM-OMAC/NoPadding");
    }

    /**
     * Генераторы симметричных ключей.
     */
    private void registerKeyGenerators() {
        String spi = GostKeyGeneratorSpi.class.getName();

        put("KeyGenerator.Kuznyechik",                          spi);
        put("Alg.Alias.KeyGenerator.GOST3412-2015",             "Kuznyechik");
    }

    /**
     * Генераторы ключевых пар ЭП ГОСТ Р 34.10-2012.
     */
    private void registerKeyPairGenerators() {
        String spi = GostKeyPairGeneratorSpi.class.getName();

        put("KeyPairGenerator.ECGOST3410-2012",                 spi);
        put("Alg.Alias.KeyPairGenerator.1.2.643.7.1.1.1.1",     "ECGOST3410-2012");
        put("Alg.Alias.KeyPairGenerator.1.2.643.7.1.1.1.2",     "ECGOST3410-2012");
    }

    /**
     * Фабрики ключей ЭП ГОСТ Р 34.10-2012.
     */
    private void registerKeyFactories() {
        String spi = GostKeyFactorySpi.class.getName();

        put("KeyFactory.ECGOST3410-2012",                       spi);
        put("Alg.Alias.KeyFactory.1.2.643.7.1.1.1.1",           "ECGOST3410-2012");
        put("Alg.Alias.KeyFactory.1.2.643.7.1.1.1.2",           "ECGOST3410-2012");
    }

    /**
     * Фабрики симметричных ключей.
     */
    private void registerSecretKeyFactories() {
        String spi = GostSecretKeyFactorySpi.class.getName();

        put("SecretKeyFactory.Kuznyechik",                      spi);
        put("Alg.Alias.SecretKeyFactory.GOST3412-2015",         "Kuznyechik");

        String pbkdf2Spi = GostPbkdf2SecretKeyFactorySpi.class.getName();
        put("SecretKeyFactory.PBKDF2WithHmacStreebog512",       pbkdf2Spi);
        put("Alg.Alias.SecretKeyFactory.PBKDF2WithHmacGOST3411-2012-512",
                                                                 "PBKDF2WithHmacStreebog512");
    }

    /**
     * Согласование ключей ECDH (ГОСТ Р 34.10-2012).
     *
     * <p>JCA-имя: {@code ECDHGOST2012}.
     */
    private void registerKeyAgreements() {
        String spi = GostKeyAgreementSpi.class.getName();

        put("KeyAgreement.ECDHGOST2012", spi);
        put("Alg.Alias.KeyAgreement.1.2.643.7.1.1.6.2", "ECDHGOST2012");
    }

    /**
     * Согласование ключей VKO_GOSTR3410_2012_256 (RFC 7836 §4.3.1).
     *
     * <p>JCA-имя: {@code VKOGOST3410-2012-256}.
     * OID: 1.2.643.7.1.1.6.1 (перенесён с ECDHGOST2012).
     */
    private void registerVkoKeyAgreements() {
        String vkoSpi = GostVkoKeyAgreementSpi.class.getName();

        put("KeyAgreement.VKOGOST3410-2012-256", vkoSpi);
        put("Alg.Alias.KeyAgreement.1.2.643.7.1.1.6.1", "VKOGOST3410-2012-256");
    }

    /**
     * Алгоритм электронной подписи ГОСТ Р 34.10-2012 (RFC 7091).
     * Два варианта: для 256-битных и 512-битных кривых.
     */
    private void registerSignatures() {
        String spi256 = GostSignatureSpi.Ecgost3410_256Spi.class.getName();
        String spi512 = GostSignatureSpi.Ecgost3410_512Spi.class.getName();

        // ГОСТ Р 34.10-2012 / 256-битные кривые
        put("Signature.ECGOST3410-2012-256",                    spi256);
        put("Alg.Alias.Signature.1.2.643.7.1.1.3.2",            "ECGOST3410-2012-256");

        // ГОСТ Р 34.10-2012 / 512-битные кривые
        put("Signature.ECGOST3410-2012-512",                    spi512);
        put("Alg.Alias.Signature.1.2.643.7.1.1.3.3",            "ECGOST3410-2012-512");
    }
}
