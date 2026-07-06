package org.rssys.gost.pkix.cms;

/**
 * Константы версий для структур CMS (RFC 5652).
 */
public final class CmsConstants {

    /** SignedData version при eContentType = id-data (RFC 5652 §5.1) */
    public static final int SIGNED_DATA_V1 = 1;

    /** SignedData version при eContentType != id-data (RFC 5652 §5.1) */
    public static final int SIGNED_DATA_V3 = 3;

    /** SignerInfo version при использовании IssuerAndSerialNumber (RFC 5652 §5.3) */
    public static final int SIGNER_INFO_V1 = 1;

    /** EnvelopedData version при наличии KeyAgreeRecipientInfo (RFC 5652 §6.1) */
    public static final int ENVELOPED_DATA_V3 = 3;

    /** KeyAgreeRecipientInfo version (RFC 5652 §6.2.2) */
    public static final int KEY_AGREE_V3 = 3;

    /** Максимальная длина цепочки сертификатов в SignedData. Защита от DoS. */
    public static final int MAX_CERT_CHAIN_LENGTH = 10;

    // Реальный CMS содержит единицы вложенных сертификатов (цепочка подписанта);
    // потолок отсекает crafted SignedData с массовым parseCert без ограничения
    // общего размера контента (encapsulated eContent может быть большим легитимно).
    /** Максимум встроенных сертификатов в SignedData.certificates. Защита от DoS. */
    public static final int MAX_EMBEDDED_CERTS = 64;

    // Каждый SignerInfo влечёт полноценную ГОСТ-verify (CPU-heavy); потолок
    // ограничивает CPU-амплификацию на crafted-множестве подписантов.
    /** Максимум SignerInfo в SignedData.signerInfos. Защита от CPU-DoS. */
    public static final int MAX_SIGNER_INFOS = 50;

    // Извлечение сертификатов из .p7b (GostPkcs7) не выполняет крипто-верификацию —
    // только DER-парсинг, поэтому экономика атаки иная, чем у MAX_EMBEDDED_CERTS
    // (там на каждый серт дорогая ГОСТ-verify). Легитимные CA-бандлы РФ-PKI содержат
    // десятки сертификатов, поэтому потолок выше, но конечен — защита от DoS сохраняется.
    /** Максимум сертификатов при извлечении из PKCS#7/.p7b. Защита от DoS. */
    public static final int MAX_P7B_CERTS = 256;

    // Отсекает pathological-вход до аллокаций парсера. Легитимный .p7b с сотнями
    // сертификатов укладывается в единицы МБ; потолок совпадает с лимитом PEM.
    /** Максимальный размер входного PKCS#7/.p7b в байтах. Защита от DoS. */
    public static final int MAX_P7B_SIZE = 10_485_760;

    private CmsConstants() {}
}
