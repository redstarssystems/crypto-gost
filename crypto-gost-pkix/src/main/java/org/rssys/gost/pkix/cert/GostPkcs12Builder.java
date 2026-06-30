package org.rssys.gost.pkix.cert;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.util.CryptoRandom;
import org.rssys.gost.util.DerCodec;

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
 * HMAC-Streebog-512 (.macHashLen(32) — Streebog-256).
 */
public final class GostPkcs12Builder {

    private GostPkcs12Builder() {}

    public static Builder create() {
        return new Builder();
    }

    public static final class Builder {
        private static final int LOCAL_KEY_ID_LEN = 20;

        private PrivateKeyParameters key;
        private GostCertificate certificate;
        private final List<GostCertificate> caCertificates = new ArrayList<>();
        private char[] password = new char[0];
        private String encSchemeOid = GostOids.KUZ_CTR_ACPKM_OMAC;
        private int iterations = GostOids.PBE_DEFAULT_ITERATIONS;
        private int macHashLen = GostOids.STREEBOG_512_HASH_LEN;
        private String friendlyName;

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

        public Builder macHashLen(int hlen) {
            if (hlen != GostOids.STREEBOG_256_HASH_LEN && hlen != GostOids.STREEBOG_512_HASH_LEN) {
                throw new IllegalArgumentException(
                        "macHashLen must be 32 (Streebog-256) or 64 (Streebog-512), got: " + hlen);
            }
            this.macHashLen = hlen;
            return this;
        }

        public Builder friendlyName(String friendlyName) {
            if (friendlyName != null) {
                byte[] utf8 = friendlyName.getBytes(StandardCharsets.UTF_8);
                if (utf8.length > 64) {
                    throw new IllegalArgumentException(
                            "friendlyName too long: " + utf8.length + " UTF-8 bytes (max 64)");
                }
            }
            this.friendlyName = friendlyName;
            return this;
        }

        // --- терминальные ---

        /**
         * Собирает PFX-контейнер и возвращает DER-байты.
         */
        public byte[] build() {
            if (key == null) {
                throw new IllegalStateException("key is required");
            }
            if (certificate == null) {
                throw new IllegalStateException("certificate is required");
            }

            byte[] passwordBytes = toUtf8Bytes(password);
            try {
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
                byte[] salt = new byte[16];
                CryptoRandom.INSTANCE.nextBytes(salt);
                byte[] macData =
                        GostPkcs12Mac.compute(
                                authSafeRawContent, passwordBytes, iterations, salt, macHashLen);

                // 10. PFX outer: SEQUENCE { INTEGER 3, outerContentInfo, macData }
                return DerCodec.encodeSequence(
                        DerCodec.encodeInteger(3), outerContentInfo, macData);
            } finally {
                Arrays.fill(password, '\0');
                Arrays.fill(passwordBytes, (byte) 0);
            }
        }

        /**
         * Собирает PFX и сохраняет DER-байты в файл (temp + rename для атомарности).
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

    private static byte[] toUtf8Bytes(char[] password) {
        if (password == null || password.length == 0) return new byte[0];
        java.nio.ByteBuffer buf = StandardCharsets.UTF_8.encode(java.nio.CharBuffer.wrap(password));
        byte[] result = new byte[buf.remaining()];
        buf.get(result);
        return result;
    }
}
