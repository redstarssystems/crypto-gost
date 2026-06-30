package org.rssys.gost.pkix.cert;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.rssys.gost.jca.RssysGostProvider;
import org.rssys.gost.jca.key.GostECPrivateKey;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostPkcs12Parser.ContentInfoData;
import org.rssys.gost.pkix.cert.GostPkcs12Parser.EncryptedPrivateKeyInfo;
import org.rssys.gost.pkix.cert.GostPkcs12Parser.MacData;
import org.rssys.gost.pkix.cert.GostPkcs12Parser.PfxData;
import org.rssys.gost.pkix.cert.GostPkcs12Parser.SafeBagData;
import org.rssys.gost.signature.PrivateKeyParameters;

/**
 * Загрузчик PKCS12 (PFX) с нативной поддержкой ГОСТ.
 * <p>
 * Разбирает PFX самостоятельно, без делегации JDK {@link KeyStore}.
 * PBES2 (RFC 9337) — родной. Остальные схемы (стандартные JDK PBE,
 * КриптоПро .80) — fallback на JDK KeyStore.
 */
public final class GostPkcs12Loader {

    private static final Logger LOG = System.getLogger("org.rssys.gost.pkix.cert.GostPkcs12Loader");

    static {
        if (Security.getProvider("RssysGostProvider") == null) {
            Security.addProvider(new RssysGostProvider());
        }
    }

    private GostPkcs12Loader() {}

    public static final class Result {
        private final PrivateKeyParameters privateKey;
        private final List<GostCertificate> certificateChain;

        Result(PrivateKeyParameters privateKey, List<GostCertificate> certificateChain) {
            this.privateKey = privateKey;
            this.certificateChain = certificateChain;
        }

        public PrivateKeyParameters getPrivateKey() {
            return privateKey;
        }

        public List<GostCertificate> getCertificateChain() {
            return certificateChain;
        }
    }

    /**
     * Загружает PFX.
     *
     * @param pfxData           DER-байты PFX
     * @param password          пароль
     * @param allowJdkFallback  {@code true} — разрешить fallback на JDK KeyStore для не-ГОСТ контейнеров
     * @return Result с ключом и цепочкой
     */
    public static Result load(byte[] pfxData, char[] password, boolean allowJdkFallback) {
        LOG.log(Level.INFO, "Loading PKCS12 container");
        PfxData pfx = GostPkcs12Parser.parsePfx(pfxData);
        byte[] passwordBytes = toUtf8Bytes(password);

        try {
            if (hasGostPbes2Key(pfx)) {
                MacData md = pfx.getMacData();
                if (md != null) {
                    GostPkcs12Mac.verify(md, passwordBytes, pfx.getAuthSafeRawContent());
                }
                return loadGost(pfx, passwordBytes);
            }
            if (!allowJdkFallback) {
                throw new IllegalArgumentException(
                        "PKCS12: non-GOST PBES2 key found, JDK fallback disabled");
            }
            return loadJdkFallback(pfxData, password);
        } finally {
            Arrays.fill(passwordBytes, (byte) 0);
        }
    }

    /**
     * Расшифровывает standalone EncryptedPrivateKeyInfo (PKCS#8) по ГОСТ PBES2.
     * <p>
     * Отличается от {@link #load(byte[], char[])} тем, что принимает
     * не PFX-контейнер, а одиночный зашифрованный ключ (как в PEM
     * {@code -----BEGIN ENCRYPTED PRIVATE KEY-----}).
     * <p>
     * Поддерживает только PBES2 с ГОСТ-шифрованием (Кузнечик CTR-ACPKM).
     * Для не-ГОСТ PBE бросает {@link IllegalArgumentException}.
     *
     * @param encryptedDer DER EncryptedPrivateKeyInfo
     * @param password     пароль
     * @return расшифрованный закрытый ключ
     */
    public static PrivateKeyParameters decryptPrivateKey(byte[] encryptedDer, char[] password) {
        GostPkcs12Parser.EncryptedPrivateKeyInfo epki =
                GostPkcs12Parser.parseEncryptedPrivateKeyInfo(encryptedDer);
        byte[] passwordBytes = toUtf8Bytes(password);
        try {
            return GostPbes2.decryptKey(epki, passwordBytes);
        } finally {
            Arrays.fill(passwordBytes, (byte) 0);
        }
    }

    private static boolean hasGostPbes2Key(PfxData pfx) {
        for (ContentInfoData ci : pfx.getAuthSafe().getContentInfos()) {
            if (!GostOids.PKCS7_DATA.equals(ci.getContentType())) continue;
            byte[] safeContentsDer = GostPkcs12Parser.unwrapOctetString(ci.getContent());
            List<SafeBagData> bags = GostPkcs12Parser.parseSafeContents(safeContentsDer);
            for (SafeBagData bag : bags) {
                if (GostOids.BAG_PKCS8_SHROUDED_KEY.equals(bag.getBagId())) {
                    EncryptedPrivateKeyInfo epki =
                            GostPkcs12Parser.parseEncryptedPrivateKeyInfo(bag.getBagValue());
                    if (GostOids.PBES2.equals(epki.getEncryptionAlgorithmOid())) {
                        String encOid = getEncryptionSchemeOid(epki.getEncryptionParams());
                        if (GostOids.KUZ_CTR_ACPKM.equals(encOid)
                                || GostOids.KUZ_CTR_ACPKM_OMAC.equals(encOid)) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

    private static String getEncryptionSchemeOid(byte[] pbes2Params) {
        if (pbes2Params == null) return null;
        byte[][] seq = GostPkcs12Parser.parseSequence(pbes2Params, new int[] {0});
        if (seq.length < 2) return null;
        byte[][] encAlgId = GostPkcs12Parser.parseSequence(seq[1], new int[] {0});
        return GostPkcs12Parser.parseOid(encAlgId[0], new int[] {0});
    }

    /**
     * Загружает ключ и цепочку сертификатов из PFX.
     * <p>
     * Одноходовой обход bags: keyBag -> decrypt + запомнить keyLocalKeyId;
     * certBag -> накопление в {@link RawCert}. После обхода — пост-фильтрация
     * по keyLocalKeyId и топологическая сортировка цепочки (leaf-first
     * по issuer->subject DER-совпадению).
     * <p>
     * Фильтрация: сертификаты с localKeyId, отличным от keyLocalKeyId,
     * отбрасываются. Сертификаты без localKeyId (CA) всегда включаются.
     * Если ключ не имеет localKeyId, все сертификаты проходят без фильтрации.
     * <p>
     * Цепочка: leaf (isCA == false) на chain[0], CA упорядочены по
     * issuer->subject DER-совпадению. Не сортируется только если цепочка
     * не содержит non-CA сертификатов.
     */
    private static Result loadGost(PfxData pfx, byte[] passwordBytes) {
        PrivateKeyParameters privateKey = null;
        byte[] keyLocalKeyId = null;
        List<RawCert> rawCerts = new ArrayList<>();

        for (ContentInfoData ci : pfx.getAuthSafe().getContentInfos()) {
            if (!GostOids.PKCS7_DATA.equals(ci.getContentType())) continue;
            byte[] safeContentsDer = GostPkcs12Parser.unwrapOctetString(ci.getContent());
            List<SafeBagData> bags = GostPkcs12Parser.parseSafeContents(safeContentsDer);
            for (SafeBagData bag : bags) {
                String bagId = bag.getBagId();
                if (GostOids.BAG_PKCS8_SHROUDED_KEY.equals(bagId)) {
                    if (privateKey == null) {
                        EncryptedPrivateKeyInfo epki =
                                GostPkcs12Parser.parseEncryptedPrivateKeyInfo(bag.getBagValue());
                        privateKey = GostPbes2.decryptKey(epki, passwordBytes);
                        keyLocalKeyId = GostPkcs12Parser.findLocalKeyId(bag.getAttributes());
                    }
                } else if (GostOids.BAG_CERT.equals(bagId)) {
                    byte[] certDer = GostPkcs12Parser.parseCertBag(bag.getBagValue());
                    byte[] certLocalKeyId = GostPkcs12Parser.findLocalKeyId(bag.getAttributes());
                    rawCerts.add(new RawCert(certDer, certLocalKeyId));
                }
            }
        }

        if (privateKey == null) {
            throw new IllegalArgumentException("PKCS12: no private key found");
        }

        List<GostCertificate> chain = filterCerts(rawCerts, keyLocalKeyId);
        chain = orderChain(chain);
        LOG.log(Level.INFO, "PKCS12 loaded via GOST: {0} certificate(s) in chain", chain.size());
        return new Result(privateKey, chain);
    }

    private static List<GostCertificate> filterCerts(List<RawCert> rawCerts, byte[] keyLocalKeyId) {
        List<GostCertificate> chain = new ArrayList<>();
        for (RawCert rc : rawCerts) {
            if (keyLocalKeyId != null
                    && rc.localKeyId != null
                    && !Arrays.equals(keyLocalKeyId, rc.localKeyId)) {
                continue;
            }
            chain.add(new GostCertificate(rc.der));
        }
        if (chain.isEmpty()) {
            throw new IllegalArgumentException("PKCS12: no certificates found after filtering");
        }
        return chain;
    }

    private static List<GostCertificate> orderChain(List<GostCertificate> chain) {
        int n = chain.size();
        if (n <= 1) return chain;

        int leafIdx = -1;
        for (int i = 0; i < n; i++) {
            if (!chain.get(i).isCA()) {
                leafIdx = i;
                break;
            }
        }
        if (leafIdx < 0) return chain;

        List<GostCertificate> result = new ArrayList<>(n);
        boolean[] used = new boolean[n];
        result.add(chain.get(leafIdx));
        used[leafIdx] = true;

        int current = leafIdx;
        while (result.size() < n) {
            byte[] issuerDn = chain.get(current).getIssuerDnBytes();
            boolean found = false;
            for (int i = 0; i < n; i++) {
                if (used[i]) continue;
                if (Arrays.equals(issuerDn, chain.get(i).getSubjectDnBytes())) {
                    result.add(chain.get(i));
                    used[i] = true;
                    current = i;
                    found = true;
                    break;
                }
            }
            if (!found) break;
        }

        for (int i = 0; i < n; i++) {
            if (!used[i]) result.add(chain.get(i));
        }
        return result;
    }

    private static final class RawCert {
        final byte[] der;
        final byte[] localKeyId;

        RawCert(byte[] der, byte[] localKeyId) {
            this.der = der;
            this.localKeyId = localKeyId;
        }
    }

    private static Result loadJdkFallback(byte[] pfxData, char[] password) {
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(new ByteArrayInputStream(pfxData), password);

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
            List<GostCertificate> ourChain = new ArrayList<>();
            for (Certificate cert : jdkChain) {
                ourChain.add(new GostCertificate(cert.getEncoded()));
            }
            LOG.log(
                    Level.INFO,
                    "PKCS12 loaded via JDK fallback: {0} certificate(s) in chain",
                    ourChain.size());
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

    public static PrivateKeyParameters adaptPrivateKey(PrivateKey jdkKey) {
        if (jdkKey instanceof GostECPrivateKey) {
            return ((GostECPrivateKey) jdkKey).toPrivateKeyParameters();
        }
        return GostDerCodec.decodePrivateKey(jdkKey.getEncoded());
    }

    static byte[] toUtf8Bytes(char[] password) {
        if (password == null || password.length == 0) return new byte[0];
        java.nio.ByteBuffer buf =
                java.nio.charset.StandardCharsets.UTF_8.encode(java.nio.CharBuffer.wrap(password));
        byte[] result = new byte[buf.remaining()];
        buf.get(result);
        return result;
    }
}
