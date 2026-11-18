package org.rssys.gost.pkix.cert;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.rssys.gost.api.Digest;

/**
 * Набор доверенных якорей-сертификатов.
 *
 * <p>Сертификат-якорь — единственный источник ограничений
 * {@code NameConstraints} и {@code pathLenConstraint} корня. Якорь сравнивается
 * с сертификатом по полному DER, а не по открытому ключу, поэтому сертификат с
 * тем же ключом, но другим DER, якорем не считается.</p>
 *
 * <p>Каждый сертификат, помещённый в trust store, считается отдельным якорем.
 * Если в trust store лежит промежуточный CA, он становится якорем: ограничения
 * расположенного выше корня для него уже не применяются.</p>
 *
 * <p>Для явного небезопасного режима без якорей используйте {@link #empty()}.</p>
 *
 * <p>Потокобезопасен: список неизменяемый, поле final.</p>
 */
public final class TrustAnchors {

    /** Доменный тег отпечатка: отделяет его от любых других хэшей от тех же данных. */
    private static final byte[] FINGERPRINT_DOMAIN_TAG =
            "gost-pkix-trust-anchors-v1".getBytes(StandardCharsets.US_ASCII);

    // Объявлен раньше EMPTY: конструктор EMPTY уже использует тег.
    private static final TrustAnchors EMPTY =
            new TrustAnchors(List.of(), AnchorExpiryPolicy.DEFAULT);

    private final List<GostCertificate> certificates;
    private final AnchorExpiryPolicy expiryPolicy;
    private final byte[] fingerprint;

    private TrustAnchors(List<GostCertificate> certificates, AnchorExpiryPolicy expiryPolicy) {
        this.certificates = certificates;
        this.expiryPolicy = expiryPolicy;
        // Набор неизменяем и переиспользуется между соединениями: отпечаток считается один
        // раз здесь, а не на каждом обращении потребителя.
        this.fingerprint = computeFingerprint(certificates, expiryPolicy);
    }

    /**
     * Создаёт набор якорей-сертификатов из списка.
     *
     * <p>Когда какую фабрику брать: один якорь - {@link #ofCertificate(GostCertificate)};
     * несколько известных заранее - {@link #ofCertificates(GostCertificate...)}; список,
     * собранный в коде (например, из хранилища), - этот метод.
     *
     * @param certificates сертификаты якорей (не null, не пусто, без null-элементов)
     * @return набор якорей
     * @throws IllegalArgumentException если список null/пуст или содержит null
     * @see #ofCertificate(GostCertificate)
     * @see #ofCertificates(GostCertificate...)
     */
    public static TrustAnchors ofCertificates(List<GostCertificate> certificates) {
        if (certificates == null || certificates.isEmpty()) {
            throw new IllegalArgumentException("certificates must not be null or empty");
        }
        for (GostCertificate cert : certificates) {
            if (cert == null) {
                throw new IllegalArgumentException("certificates must not contain null");
            }
        }
        return new TrustAnchors(List.copyOf(certificates), AnchorExpiryPolicy.DEFAULT);
    }

    /**
     * Создаёт набор якорей-сертификатов из перечисленных сертификатов.
     *
     * <p>Для нескольких якорей, известных заранее. Один якорь проще задать через
     * {@link #ofCertificate(GostCertificate)}, список из кода - через
     * {@link #ofCertificates(List)}.
     *
     * @param certificates сертификаты якорей (не null, не пусто, без null-элементов)
     * @return набор якорей
     * @throws IllegalArgumentException если массив null/пуст или содержит null
     * @see #ofCertificate(GostCertificate)
     * @see #ofCertificates(List)
     */
    public static TrustAnchors ofCertificates(GostCertificate... certificates) {
        if (certificates == null) {
            throw new IllegalArgumentException("certificates must not be null or empty");
        }
        return ofCertificates(java.util.Arrays.asList(certificates));
    }

    /**
     * Создаёт набор из одного сертификата-якоря: самый частый случай, один корневой УЦ.
     * Результат тот же, что у {@code ofCertificates(certificate)}.
     *
     * @param certificate сертификат-якорь (не null)
     * @return набор якорей
     * @throws IllegalArgumentException если сертификат null
     * @see #ofCertificates(GostCertificate...)
     * @see #ofCertificates(List)
     */
    public static TrustAnchors ofCertificate(GostCertificate certificate) {
        if (certificate == null) {
            throw new IllegalArgumentException("certificate must not be null");
        }
        return new TrustAnchors(List.of(certificate), AnchorExpiryPolicy.DEFAULT);
    }

    /**
     * Пустой набор якорей. Допустим только для явного небезопасного режима,
     * в котором проверка цепочки отключена.
     *
     * @return пустой набор
     */
    public static TrustAnchors empty() {
        return EMPTY;
    }

    /**
     * Возвращает набор с явной политикой срока якоря; исходный набор не меняется.
     *
     * <p>{@link AnchorExpiryPolicy#DEFAULT} допустим как сброс: тогда политику выбирает
     * потребитель набора.</p>
     *
     * @param policy политика (не null)
     * @return новый набор с теми же сертификатами
     * @throws IllegalArgumentException если политика null
     */
    public TrustAnchors withExpiryPolicy(AnchorExpiryPolicy policy) {
        if (policy == null) {
            throw new IllegalArgumentException("policy must not be null");
        }
        return new TrustAnchors(certificates, policy);
    }

    /** @return политика срока якоря (не null, по умолчанию {@link AnchorExpiryPolicy#DEFAULT}) */
    public AnchorExpiryPolicy expiryPolicy() {
        return expiryPolicy;
    }

    /**
     * Возвращает отпечаток набора: Стрибог-256 от доменного тега, политики срока и
     * отсортированных хэшей полного DER каждого якоря.
     *
     * <p>Не зависит от порядка якорей. Меняется при любом изменении состава набора или
     * {@link #expiryPolicy()}, поэтому годится как идентификатор модели доверия для
     * привязки состояния, выведенного из проверки по этому набору (например, PSK-тикетов).</p>
     *
     * @return новый массив, 32 байта
     */
    public byte[] fingerprint() {
        return fingerprint.clone();
    }

    /** @return true, если набор пуст */
    public boolean isEmpty() {
        return certificates.isEmpty();
    }

    /** @return неизменяемый список сертификатов-якорей */
    public List<GostCertificate> certificates() {
        return certificates;
    }

    /**
     * Проверяет, является ли сертификат локальным якорем.
     *
     * <p>Сравнение — по полному DER через {@link GostCertificate#equals(Object)}.</p>
     *
     * @param cert сертификат для проверки (может быть null)
     * @return true, если сертификат побайтово равен одному из якорей
     */
    public boolean containsCertificate(GostCertificate cert) {
        return cert != null && certificates.contains(cert);
    }

    private static byte[] computeFingerprint(
            List<GostCertificate> certificates, AnchorExpiryPolicy expiryPolicy) {
        // Сортировка хэшей делает отпечаток независимым от порядка якорей; хэш DER (а не
        // сам DER) держит размер входа итогового хэша пропорциональным числу якорей.
        List<byte[]> certDigests = new ArrayList<>(certificates.size());
        for (GostCertificate cert : certificates) {
            certDigests.add(Digest.digest256(cert.getEncoded()));
        }
        certDigests.sort(Arrays::compareUnsigned);

        byte[] policyName = expiryPolicy.name().getBytes(StandardCharsets.US_ASCII);
        // Длины с префиксами исключают неоднозначность склейки полей.
        ByteBuffer canonical =
                ByteBuffer.allocate(
                        FINGERPRINT_DOMAIN_TAG.length
                                + Integer.BYTES
                                + policyName.length
                                + Integer.BYTES
                                + certDigests.size() * 32);
        canonical.put(FINGERPRINT_DOMAIN_TAG);
        canonical.putInt(policyName.length).put(policyName);
        canonical.putInt(certDigests.size());
        for (byte[] digest : certDigests) {
            canonical.put(digest);
        }
        return Digest.digest256(canonical.array());
    }

    /** @return описание без ключевого материала: количество якорей и политика срока */
    @Override
    public String toString() {
        if (isEmpty()) {
            return "TrustAnchors{empty}";
        }
        return "TrustAnchors{certificates="
                + certificates.size()
                + ", expiryPolicy="
                + expiryPolicy
                + "}";
    }
}
