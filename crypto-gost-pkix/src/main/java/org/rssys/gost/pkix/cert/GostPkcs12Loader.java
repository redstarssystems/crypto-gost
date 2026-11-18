package org.rssys.gost.pkix.cert;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.rssys.gost.api.Signature;
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
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.util.GostLogger;
import org.rssys.gost.util.GostLogger.Level;
import org.rssys.gost.util.PasswordUtf8;

/**
 * Загрузчик PKCS12 (PFX) с нативной поддержкой ГОСТ.
 * <p>
 * Разбирает PFX самостоятельно, без делегации JDK {@link KeyStore}.
 * PBES2 (RFC 9337) — родной. Остальные схемы (стандартные JDK PBE,
 * КриптоПро .80) — fallback на JDK KeyStore.
 */
public final class GostPkcs12Loader {

    private static final GostLogger LOG =
            GostLogger.getLogger("org.rssys.gost.pkix.cert.GostPkcs12Loader");

    static {
        if (Security.getProvider("RssysGostProvider") == null) {
            Security.addProvider(new RssysGostProvider());
        }
    }

    private GostPkcs12Loader() {}

    /**
     * Политика проверки MAC контейнера PKCS#12.
     */
    public enum MacPolicy {
        /** MAC обязателен; отсутствие MacData — ошибка. */
        REQUIRED,
        /**
         * Разрешить контейнер без MacData для legacy-файлов из доверенного источника.
         * <p>
         * Целостность контейнера в этом режиме не гарантируется. Проверка связности
         * отсекает лишь несвязанные и склеенные сертификаты; полностью самосогласованную
         * подмену (свой конечный сертификат на открытый ключ жертвы плюс свой CA) она
         * не ловит, потому что связность не равна доверию. Аутентичность в этом режиме
         * возможна только через внешний якорь или пиннинг сертификата.
         */
        ALLOW_MISSING
    }

    public static final class Result {
        private final PrivateKeyParameters privateKey;
        private final List<GostCertificate> certificateChain;
        private final List<GostCertificate> allCertificates;

        Result(
                PrivateKeyParameters privateKey,
                List<GostCertificate> certificateChain,
                List<GostCertificate> allCertificates) {
            this.privateKey = privateKey;
            this.certificateChain = certificateChain;
            this.allCertificates = allCertificates;
        }

        public PrivateKeyParameters getPrivateKey() {
            return privateKey;
        }

        /**
         * @return связанная цепочка от сертификата закрытого ключа до последнего доступного
         *     в контейнере CA (корня в контейнере может не быть); если сертификат ключа —
         *     CA, цепочка строится от него; несвязанные сертификаты в неё не включаются
         */
        public List<GostCertificate> getCertificateChain() {
            return certificateChain;
        }

        /**
         * Кандидаты в цепочку: сертификаты контейнера, прошедшие фильтр по localKeyId,
         * без проверки связности. Нужен для trust-бандлов, где контейнер хранит
         * несколько независимых корней.
         * <p>
         * На пути JDK-fallback это цепочка из {@code KeyStore} плюс видимые через него
         * доверенные записи, а не обязательно все SafeBag контейнера; сертификаты
         * не-ГОСТ алгоритмов из этих записей не включаются.
         *
         * @return неизменяемый список сертификатов
         */
        public List<GostCertificate> getAllCertificates() {
            return allCertificates;
        }

        /**
         * @return число кандидатов (см. {@link #getAllCertificates()}), не вошедших в цепочку;
         *     на пути JDK-fallback считается только по сертификатам, видимым через
         *     {@code KeyStore}, без не-ГОСТ записей
         */
        public int getDroppedCertificateCount() {
            return allCertificates.size() - certificateChain.size();
        }
    }

    /**
     * Загружает PFX с порогом минимальных итераций PBKDF2 по умолчанию
     * ({@link GostOids#MIN_PBKDF2_ITERATIONS_PFX} = 1000).
     *
     * @param pfxData           DER-байты PFX
     * @param password          пароль
     * @param allowJdkFallback  {@code true} — разрешить fallback на JDK KeyStore для не-ГОСТ контейнеров
     * @return Result с ключом и цепочкой
     * @throws IllegalArgumentException если контейнер повреждён, не проходит проверку или пароль
     *     содержит непарный суррогат (его нельзя закодировать в UTF-8)
     */
    public static Result load(byte[] pfxData, char[] password, boolean allowJdkFallback) {
        return load(
                pfxData,
                password,
                allowJdkFallback,
                GostOids.MIN_PBKDF2_ITERATIONS_PFX,
                MacPolicy.REQUIRED);
    }

    /**
     * Загружает PFX с настраиваемым порогом минимальных итераций PBKDF2.
     * Вызывающий может снизить порог для legacy-файлов из доверенного источника.
     *
     * @param pfxData                DER-байты PFX
     * @param password               пароль
     * @param allowJdkFallback       {@code true} — разрешить fallback на JDK KeyStore
     * @param minPbkdf2Iterations    минимально допустимое число итераций PBKDF2
     * @return Result с ключом и цепочкой
     * @throws IllegalArgumentException если контейнер повреждён, не проходит проверку или пароль
     *     содержит непарный суррогат (его нельзя закодировать в UTF-8)
     */
    public static Result load(
            byte[] pfxData, char[] password, boolean allowJdkFallback, int minPbkdf2Iterations) {
        return load(pfxData, password, allowJdkFallback, minPbkdf2Iterations, MacPolicy.REQUIRED);
    }

    /**
     * Загружает PFX с явной политикой проверки MAC.
     * <p>
     * По умолчанию (в перегрузках без {@link MacPolicy}) MAC обязателен:
     * без него открытый SafeContents с сертификатами можно подменить, не зная
     * пароль. {@link MacPolicy#ALLOW_MISSING} разрешает только legacy-файлы
     * из доверенного источника. Связность цепочки проверяется и в этом режиме,
     * но это не защита от подмены: самосогласованную пару «свой сертификат на
     * открытый ключ жертвы плюс свой CA» она пропускает (см. {@link MacPolicy#ALLOW_MISSING}).
     *
     * @param pfxData                DER-байты PFX
     * @param password               пароль
     * @param allowJdkFallback       {@code true} — разрешить fallback на JDK KeyStore
     * @param minPbkdf2Iterations    минимально допустимое число итераций PBKDF2
     * @param macPolicy              политика проверки MAC
     * @return Result с ключом и цепочкой
     * @throws IllegalArgumentException если контейнер повреждён, не проходит проверку или пароль
     *     содержит непарный суррогат (его нельзя закодировать в UTF-8)
     */
    public static Result load(
            byte[] pfxData,
            char[] password,
            boolean allowJdkFallback,
            int minPbkdf2Iterations,
            MacPolicy macPolicy) {
        if (macPolicy == null) {
            throw new IllegalArgumentException("macPolicy must not be null");
        }
        LOG.log(Level.DEBUG, "Loading PKCS12 container");
        PfxData pfx = GostPkcs12Parser.parsePfx(pfxData, minPbkdf2Iterations);
        char[] pwd = password.clone();
        // Объявлен до try, чтобы finally затирал его и копию пароля при любой ошибке,
        // в том числе при отказе кодирования (непарный суррогат)
        byte[] passwordBytes = null;

        try {
            passwordBytes = PasswordUtf8.encode(pwd);
            MacData md = pfx.getMacData();
            if (md == null) {
                if (macPolicy == MacPolicy.REQUIRED) {
                    throw new IllegalArgumentException(
                            "PKCS12: MacData is missing; integrity cannot be verified");
                }
                LOG.log(Level.WARNING, "PKCS12 without MAC: integrity not verified");
            }
            if (hasGostPbes2Key(pfx)) {
                if (md != null) {
                    GostPkcs12Mac.verify(md, passwordBytes, pfx.getAuthSafeRawContent());
                }
                return loadGost(pfx, passwordBytes, minPbkdf2Iterations);
            }
            if (!allowJdkFallback) {
                throw new IllegalArgumentException(
                        "PKCS12: non-GOST PBES2 key found, JDK fallback disabled");
            }
            return loadJdkFallback(pfxData, pwd);
        } finally {
            if (passwordBytes != null) {
                Arrays.fill(passwordBytes, (byte) 0);
            }
            Arrays.fill(pwd, '\0');
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
     * @throws IllegalArgumentException если данные повреждены, схема не поддерживается или пароль
     *     содержит непарный суррогат (его нельзя закодировать в UTF-8)
     */
    public static PrivateKeyParameters decryptPrivateKey(byte[] encryptedDer, char[] password) {
        return decryptPrivateKey(encryptedDer, password, GostOids.MIN_PBKDF2_ITERATIONS_PFX);
    }

    /**
     * Расшифровывает standalone EncryptedPrivateKeyInfo с настраиваемым порогом.
     *
     * @throws IllegalArgumentException если данные повреждены, схема не поддерживается или пароль
     *     содержит непарный суррогат (его нельзя закодировать в UTF-8)
     */
    public static PrivateKeyParameters decryptPrivateKey(
            byte[] encryptedDer, char[] password, int minPbkdf2Iterations) {
        GostPkcs12Parser.EncryptedPrivateKeyInfo epki =
                GostPkcs12Parser.parseEncryptedPrivateKeyInfo(encryptedDer);
        char[] pwd = password.clone();
        byte[] passwordBytes = null;
        try {
            passwordBytes = PasswordUtf8.encode(pwd);
            return GostPbes2.decryptKey(epki, passwordBytes, minPbkdf2Iterations);
        } finally {
            if (passwordBytes != null) {
                Arrays.fill(passwordBytes, (byte) 0);
            }
            Arrays.fill(pwd, '\0');
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
     * Цепочка начинается с сертификата, чей ключ совпал с закрытым (сначала ищется
     * конечный, и только если ни один не-CA не совпал — CA), далее звенья по
     * issuer->subject и подписи.
     * Остальные сертификаты в цепочку не входят, но доступны через
     * {@link Result#getAllCertificates()}.
     */
    private static Result loadGost(PfxData pfx, byte[] passwordBytes, int minPbkdf2Iterations) {
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
                        privateKey = GostPbes2.decryptKey(epki, passwordBytes, minPbkdf2Iterations);
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

        List<GostCertificate> filtered = filterCerts(rawCerts, keyLocalKeyId);
        List<GostCertificate> chain =
                buildVerifiedChain(filtered, Signature.derivePublicKey(privateKey));
        LOG.log(Level.DEBUG, "PKCS12 loaded via GOST: {0} certificate(s) in chain", chain.size());
        return new Result(privateKey, chain, List.copyOf(filtered));
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

    /**
     * Строит связанную цепочку от сертификата закрытого ключа, проверяет, что ключ
     * принадлежит её первому звену, и сообщает на DEBUG об отброшенных сертификатах.
     * <p>
     * Общая точка для ГОСТ-пути и JDK-fallback: цепочка, собранная самим
     * {@code KeyStore}, сопоставляет сертификаты только по DN и подписи не проверяет.
     *
     * @param candidates сертификаты контейнера после фильтра по localKeyId
     * @param keyPublic  открытый ключ, выведенный из закрытого
     * @return связанная цепочка, первое звено которой соответствует ключу
     */
    private static List<GostCertificate> buildVerifiedChain(
            List<GostCertificate> candidates, PublicKeyParameters keyPublic) {
        List<GostCertificate> chain = orderChain(candidates, keyPublic);
        requireKeyMatchesCertificate(keyPublic, chain);
        int dropped = candidates.size() - chain.size();
        if (dropped > 0) {
            // Лишние сертификаты в контейнере обычны (выгрузка из браузера или хранилища ОС);
            // на ключ и цепочку они не влияют, поэтому на DEBUG
            LOG.log(
                    Level.DEBUG,
                    "PKCS12: {0} unrelated certificate(s) dropped from chain",
                    dropped);
        }
        return chain;
    }

    /**
     * Строит связанную цепочку: сертификат ключа -> CA.
     * <p>
     * Связь подтверждается совпадением issuer/subject DN и проверкой подписи
     * следующего сертификата. Несвязанные сертификаты не включаются в результат.
     * Это отсекает склеенные и посторонние сертификаты, но не доказывает
     * подлинность: самосогласованную подмену при отсутствии MAC такая проверка
     * пропустит (см. {@link MacPolicy#ALLOW_MISSING}).
     */
    private static List<GostCertificate> orderChain(
            List<GostCertificate> chain, PublicKeyParameters keyPublic) {
        int n = chain.size();
        if (n <= 1) return chain;

        // Порядок SafeBag в RFC 7292 не задан. Начало цепочки выбираем по
        // совпадению ключа, а не по позиции: иначе при наличии старого
        // сертификата без localKeyId загрузка зависела бы от порядка bags.
        // Сначала конечный (не-CA) сертификат, затем CA: контейнер УЦ хранит
        // ключ самого УЦ, и цепочка у него строится от этого CA.
        int leafIdx = indexOfKeyHolder(chain, keyPublic, false);
        if (leafIdx < 0) {
            leafIdx = indexOfKeyHolder(chain, keyPublic, true);
        }
        if (leafIdx < 0) {
            // Ключ не совпал ни с одним сертификатом: оставляем первый не-CA,
            // чтобы requireKeyMatchesCertificate дал явную ошибку.
            for (int i = 0; i < n; i++) {
                if (!chain.get(i).isCA()) {
                    leafIdx = i;
                    break;
                }
            }
        }
        if (leafIdx < 0) {
            // Нет совпадения и нет не-CA: requireKeyMatchesCertificate отклонит набор.
            return chain;
        }

        List<GostCertificate> result = new ArrayList<>(n);
        boolean[] used = new boolean[n];
        result.add(chain.get(leafIdx));
        used[leafIdx] = true;

        int current = leafIdx;
        while (result.size() < n) {
            GostCertificate currentCert = chain.get(current);
            byte[] issuerDn = currentCert.getIssuerDnBytes();
            boolean found = false;
            for (int i = 0; i < n; i++) {
                if (used[i]) continue;
                GostCertificate candidate = chain.get(i);
                if (!Arrays.equals(issuerDn, candidate.getSubjectDnBytes())) {
                    continue;
                }
                // Подпись обязательна: одного совпадения DN недостаточно,
                // иначе чужой сертификат с тем же subject попадёт в цепочку.
                if (!currentCert.verifySignature(candidate.getPublicKey())) {
                    continue;
                }
                result.add(candidate);
                used[i] = true;
                current = i;
                found = true;
                break;
            }
            if (!found) break;
        }

        return result;
    }

    private static int indexOfKeyHolder(
            List<GostCertificate> certs, PublicKeyParameters keyPublic, boolean wantCa) {
        for (int i = 0; i < certs.size(); i++) {
            GostCertificate cert = certs.get(i);
            if (cert.isCA() == wantCa && Objects.equals(keyPublic, cert.getPublicKey())) {
                return i;
            }
        }
        return -1;
    }

    /**
     * Требует, чтобы закрытый ключ соответствовал первому звену цепочки.
     * <p>
     * Без этой проверки контейнер мог вернуть ключ от одного субъекта вместе
     * с сертификатом другого; приложение считало бы сертификат своим. Проверяется
     * именно начало цепочки, а не любое звено: иначе произвольный CA с тем же
     * открытым ключом удовлетворил бы проверку, а настоящий сертификат ключа
     * остался бы незамеченным.
     */
    private static void requireKeyMatchesCertificate(
            PublicKeyParameters keyPublic, List<GostCertificate> chain) {
        if (chain.isEmpty() || !Objects.equals(keyPublic, chain.get(0).getPublicKey())) {
            throw new IllegalArgumentException("PKCS12: private key does not match certificate");
        }
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
            Enumeration<String> aliases = ks.aliases();
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
            if (jdkChain == null || jdkChain.length == 0) {
                throw new IllegalArgumentException("PKCS12: no certificate chain found");
            }

            // KeyStore сопоставляет сертификаты только по DN и не проверяет подписи,
            // поэтому его цепочка лишь поставляет кандидатов: порядок и связность
            // устанавливаем сами, как на ГОСТ-пути.
            Map<ByteBuffer, GostCertificate> candidates = new LinkedHashMap<>();
            for (Certificate cert : jdkChain) {
                addCandidate(candidates, cert);
            }
            // Прочие записи KeyStore не относятся к ключу: контейнер может хранить
            // и доверенные сертификаты других алгоритмов (RSA, ECDSA), которые
            // ГОСТ-разбор не принимает. Их пропуск не должен ронять загрузку ключа,
            // в отличие от собственной цепочки ключа, где ошибка обязана быть фатальной.
            Enumeration<String> otherAliases = ks.aliases();
            while (otherAliases.hasMoreElements()) {
                String other = otherAliases.nextElement();
                if (!other.equals(alias)) {
                    addForeignCandidate(candidates, ks.getCertificate(other));
                }
            }

            List<GostCertificate> allCertificates = List.copyOf(candidates.values());
            List<GostCertificate> ourChain =
                    buildVerifiedChain(allCertificates, Signature.derivePublicKey(ourKey));
            LOG.log(
                    Level.DEBUG,
                    "PKCS12 loaded via JDK fallback: {0} certificate(s) in chain",
                    ourChain.size());
            return new Result(ourKey, ourChain, allCertificates);

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

    /** Добавляет сертификат, не разбираемый как ГОСТ, в набор кандидатов, пропуская его. */
    private static void addForeignCandidate(
            Map<ByteBuffer, GostCertificate> candidates, Certificate cert)
            throws CertificateEncodingException {
        try {
            addCandidate(candidates, cert);
        } catch (RuntimeException e) {
            LOG.log(Level.DEBUG, "PKCS12: non-GOST certificate skipped");
        }
    }

    /** Добавляет сертификат в набор кандидатов; повтор по DER-байтам игнорируется. */
    private static void addCandidate(Map<ByteBuffer, GostCertificate> candidates, Certificate cert)
            throws CertificateEncodingException {
        if (cert == null) return;
        byte[] der = cert.getEncoded();
        candidates.computeIfAbsent(ByteBuffer.wrap(der), key -> new GostCertificate(der));
    }

    public static PrivateKeyParameters adaptPrivateKey(PrivateKey jdkKey) {
        if (jdkKey instanceof GostECPrivateKey) {
            return ((GostECPrivateKey) jdkKey).toPrivateKeyParameters();
        }
        byte[] encoded = jdkKey.getEncoded();
        try {
            return GostDerCodec.decodePrivateKey(encoded);
        } finally {
            Arrays.fill(encoded, (byte) 0);
        }
    }
}
