package org.rssys.gost.pkix.cert;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import org.rssys.gost.api.Signature;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.util.CryptoRandom;
import org.rssys.gost.util.DerCodec;
import org.rssys.gost.util.PasswordUtf8;

/**
 * Создание PFX-контейнеров ГОСТ (PKCS#12, RFC 7292).
 * <p>
 * Fluent Builder API:
 * <pre>
 * byte[] pfx = GostPkcs12Builder.create()
 *     .key(privateKey)
 *     .certificate(leafCert)
 *     .caCertificate(caCert1)
 *     .password("changeit".toCharArray())
 *     .friendlyName("server-cert")
 *     .build();
 * </pre>
 * <p>
 * По умолчанию: PBES2-GOST с Кузнечиком CTR-ACPKM-OMAC, 2000 итераций PBKDF2,
 * MAC целостности HMAC-Streebog-512 (RFC 9548 §7), соль PBKDF2 32 байта.
 */
public final class GostPkcs12Builder {

    private GostPkcs12Builder() {}

    public static Builder create() {
        return new Builder();
    }

    public static final class Builder {
        private static final int LOCAL_KEY_ID_LEN = 20;
        // friendlyName кодируется в BMPString (UTF-16BE). Лимит задаём в байтах UTF-16BE,
        // чтобы проверка совпадала с фактическим размером атрибута; 128 байт = 64 BMP-символа
        // (сохраняет прежний бюджет для ASCII-имён).
        private static final int MAX_FRIENDLY_NAME_BMP_BYTES = 128;

        private PrivateKeyParameters key;
        private GostCertificate certificate;
        private final List<GostCertificate> caCertificates = new ArrayList<>();
        private char[] password = new char[0];
        private String encSchemeOid = GostOids.KUZ_CTR_ACPKM_OMAC;
        private int iterations = GostOids.PBE_DEFAULT_ITERATIONS;
        private String friendlyName;
        // build() затирает пароль, поэтому повторная сборка собрала бы PFX с пустым паролем.
        // Билдер не потокобезопасен по замыслу (как и остальные поля), атомарность не нужна.
        private boolean consumed;

        private Builder() {}

        // --- обязательные ---

        public Builder key(PrivateKeyParameters key) {
            if (key == null) throw new IllegalArgumentException("key must not be null");
            this.key = key;
            return this;
        }

        public Builder certificate(GostCertificate certificate) {
            if (certificate == null) {
                throw new IllegalArgumentException("certificate must not be null");
            }
            this.certificate = certificate;
            return this;
        }

        /**
         * Пароль для шифрования ключа и MAC (RFC 7292).
         * {@code null} трактуется как пустой пароль, согласно RFC 7292.
         * Результат идентичен {@code password(new char[0])} и отсутствию
         * вызова {@code password()} (поле по умолчанию {@code new char[0]}).
         */
        public Builder password(char[] password) {
            this.password = password != null ? password.clone() : new char[0];
            return this;
        }

        // --- опциональные ---

        public Builder caCertificate(GostCertificate caCert) {
            if (caCert == null) {
                throw new IllegalArgumentException("caCertificate must not be null");
            }
            this.caCertificates.add(caCert);
            return this;
        }

        public Builder encScheme(String encSchemeOid) {
            if (!GostOids.KUZ_CTR_ACPKM_OMAC.equals(encSchemeOid)
                    && !GostOids.KUZ_CTR_ACPKM.equals(encSchemeOid)) {
                throw new IllegalArgumentException(
                        "Unsupported encryption scheme: " + encSchemeOid);
            }
            this.encSchemeOid = encSchemeOid;
            return this;
        }

        public Builder iterations(int iterations) {
            if (iterations < 1) {
                throw new IllegalArgumentException("iterations must be >= 1");
            }
            this.iterations = iterations;
            return this;
        }

        public Builder friendlyName(String friendlyName) {
            if (friendlyName != null) {
                // Измеряем в тех же байтах UTF-16BE, что и реальное кодирование в BMPString
                // (buildFriendlyNameAttribute): иначе проверка UTF-8 не отражала бы фактический
                // размер атрибута (BMPString вдвое длиннее для ASCII).
                int bmpBytes = friendlyName.getBytes(StandardCharsets.UTF_16BE).length;
                if (bmpBytes > MAX_FRIENDLY_NAME_BMP_BYTES) {
                    throw new IllegalArgumentException(
                            "friendlyName too long: "
                                    + bmpBytes
                                    + " UTF-16BE bytes (max "
                                    + MAX_FRIENDLY_NAME_BMP_BYTES
                                    + ")");
                }
            }
            this.friendlyName = friendlyName;
            return this;
        }

        // --- терминальные ---

        /**
         * Собирает PFX-контейнер и возвращает DER-байты.
         *
         * <p>Метод терминальный: пароль затирается при любом исходе после проверки наличия
         * ключа и сертификата, поэтому повторный вызов (после успеха или после ошибки внутри
         * сборки, например несовпадения ключа и сертификата) недопустим. Отсутствие ключа или
         * сертификата - ошибка конфигурации: билдер при этом не расходуется, её можно
         * исправить и вызвать метод снова.</p>
         *
         * @return DER-кодированный PFX
         * @throws IllegalStateException если билдер уже использован, либо не задан ключ или
         *     сертификат
         * @throws IllegalArgumentException если сертификат не соответствует ключу или пароль
         *     содержит непарный суррогат (его нельзя закодировать в UTF-8)
         */
        public byte[] build() {
            if (consumed) {
                throw new IllegalStateException("builder is already used");
            }
            if (key == null) {
                throw new IllegalStateException("key is required");
            }
            if (certificate == null) {
                throw new IllegalStateException("certificate is required");
            }
            consumed = true;

            // Объявлен до try, чтобы finally затирал его при любой ошибке сборки.
            byte[] passwordBytes = null;
            try {
                if (!Objects.equals(Signature.derivePublicKey(key), certificate.getPublicKey())) {
                    throw new IllegalArgumentException(
                            "PKCS12: certificate does not match private key");
                }
                passwordBytes = PasswordUtf8.encode(password);
                byte[] localKeyId = new byte[LOCAL_KEY_ID_LEN];
                CryptoRandom.INSTANCE.nextBytes(localKeyId);

                // 1. pkcs8ShroudedKeyBag
                byte[] encryptedKeyBag =
                        GostPbes2.encryptKey(key, passwordBytes, encSchemeOid, iterations);
                byte[] keyBag = buildKeyBag(encryptedKeyBag, localKeyId);

                // 2. leaf certBag (с localKeyId)
                byte[] leafCertBag =
                        buildCertBag(certificate.getEncoded(), localKeyId, friendlyName);

                // 3. CA certBags (без localKeyId)
                List<byte[]> allBags = new ArrayList<>();
                allBags.add(keyBag);
                allBags.add(leafCertBag);
                for (GostCertificate ca : caCertificates) {
                    allBags.add(buildCertBag(ca.getEncoded(), null, null));
                }

                // 4. SafeContents
                byte[] safeContents = DerCodec.encodeSequence(allBags.toArray(new byte[0][]));

                // 5. ContentInfo(pkcs7-data) с SafeContents
                byte[] dataContentInfo =
                        DerCodec.encodeSequence(
                                DerCodec.encodeOid(GostOids.PKCS7_DATA),
                                DerCodec.encodeContextConstructed(
                                        0, DerCodec.encodeOctetString(safeContents)));

                // 6. AuthenticatedSafe = SEQUENCE OF ContentInfo (1 элемент)
                byte[] authSafe = DerCodec.encodeSequence(dataContentInfo);

                // 7. authSafeRawContent = байты AuthenticatedSafe (target для MAC)
                byte[] authSafeRawContent = authSafe;

                // 8. outer ContentInfo(pkcs7-data) с AuthenticatedSafe
                byte[] outerContentInfo =
                        DerCodec.encodeSequence(
                                DerCodec.encodeOid(GostOids.PKCS7_DATA),
                                DerCodec.encodeContextConstructed(
                                        0, DerCodec.encodeOctetString(authSafe)));

                // 9. MAC
                byte[] salt = new byte[GostOids.PBKDF2_SALT_LEN];
                CryptoRandom.INSTANCE.nextBytes(salt);
                byte[] macData =
                        GostPkcs12Mac.compute(authSafeRawContent, passwordBytes, iterations, salt);

                // 10. PFX outer: SEQUENCE { INTEGER 3, outerContentInfo, macData }
                return DerCodec.encodeSequence(
                        DerCodec.encodeInteger(3), outerContentInfo, macData);
            } finally {
                Arrays.fill(password, '\0');
                if (passwordBytes != null) {
                    Arrays.fill(passwordBytes, (byte) 0);
                }
            }
        }

        /**
         * Собирает PFX и сохраняет DER-байты в файл (temp + rename для атомарности).
         *
         * <p>Метод терминальный, как и {@link #build()}: повторный вызов даёт
         * {@link IllegalStateException}.</p>
         *
         * @param path путь результата
         * @throws IOException при ошибке записи
         */
        public void buildAndWriteTo(Path path) throws IOException {
            byte[] pfx = build();
            Path parent = path.getParent() != null ? path.getParent() : Path.of(".");
            Path tmp = Files.createTempFile(parent, ".pfx-", ".tmp");
            try {
                Files.write(tmp, pfx);
                Files.move(
                        tmp,
                        path,
                        StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } catch (Exception e) {
                Files.deleteIfExists(tmp);
                throw e;
            }
        }

        // ---------------------------------------------------------------
        // Внутренние построители DER-структур
        // ---------------------------------------------------------------

        private byte[] buildKeyBag(byte[] encryptedKeyBagDer, byte[] localKeyId) {
            byte[] bagValue = DerCodec.encodeContextConstructed(0, encryptedKeyBagDer);
            if (friendlyName != null) {
                byte[] localKeyIdAttr = buildLocalKeyIdAttribute(localKeyId);
                byte[] friendlyNameAttr = buildFriendlyNameAttribute(friendlyName);
                byte[] attrs = DerCodec.encodeSet(localKeyIdAttr, friendlyNameAttr);
                return DerCodec.encodeSequence(
                        DerCodec.encodeOid(GostOids.BAG_PKCS8_SHROUDED_KEY), bagValue, attrs);
            }
            byte[] attrs = DerCodec.encodeSet(buildLocalKeyIdAttribute(localKeyId));
            return DerCodec.encodeSequence(
                    DerCodec.encodeOid(GostOids.BAG_PKCS8_SHROUDED_KEY), bagValue, attrs);
        }

        private byte[] buildCertBag(byte[] certDer, byte[] localKeyId, String name) {
            // CertBag ::= SEQUENCE { certId OID, certValue [0] EXPLICIT OCTET STRING }
            byte[] certBagContent =
                    DerCodec.encodeSequence(
                            DerCodec.encodeOid(GostOids.PKCS9_X509_CERT),
                            DerCodec.encodeContextConstructed(
                                    0, DerCodec.encodeOctetString(certDer)));
            byte[] bagValue = DerCodec.encodeContextConstructed(0, certBagContent);

            if (localKeyId != null) {
                if (name != null) {
                    byte[] attrs =
                            DerCodec.encodeSet(
                                    buildLocalKeyIdAttribute(localKeyId),
                                    buildFriendlyNameAttribute(name));
                    return DerCodec.encodeSequence(
                            DerCodec.encodeOid(GostOids.BAG_CERT), bagValue, attrs);
                }
                byte[] attrs = DerCodec.encodeSet(buildLocalKeyIdAttribute(localKeyId));
                return DerCodec.encodeSequence(
                        DerCodec.encodeOid(GostOids.BAG_CERT), bagValue, attrs);
            }
            // CA-сертификаты без атрибутов
            return DerCodec.encodeSequence(DerCodec.encodeOid(GostOids.BAG_CERT), bagValue);
        }

        /**
         * Attribute ::= SEQUENCE { attrId OID, attrValues SET OF ANY }
         * localKeyId = SET { OCTET STRING keyIdBytes }
         */
        private byte[] buildLocalKeyIdAttribute(byte[] keyId) {
            return DerCodec.encodeSequence(
                    DerCodec.encodeOid(GostOids.ATTR_LOCAL_KEY_ID),
                    DerCodec.encodeSet(DerCodec.encodeOctetString(keyId)));
        }

        /**
         * friendlyName = SET { BMPString name } (RFC 7292 §B.1).
         * BMPString (UCS-2) — tag 0x1E.
         */
        private byte[] buildFriendlyNameAttribute(String name) {
            byte[] nameBytes = name.getBytes(StandardCharsets.UTF_16BE);
            return DerCodec.encodeSequence(
                    DerCodec.encodeOid(GostOids.ATTR_FRIENDLY_NAME),
                    DerCodec.encodeSet(DerCodec.encodeTlv(0x1E, nameBytes)));
        }
    }
}
