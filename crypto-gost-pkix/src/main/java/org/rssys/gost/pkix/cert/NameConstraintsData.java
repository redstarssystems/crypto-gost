package org.rssys.gost.pkix.cert;

/**
 * Распарсенные данные расширения Name Constraints (RFC 5280 §4.2.1.10).
 *
 * <p>Содержит списки permitted/excluded имён для поддерживаемых типов GeneralName
 * (dNSName, iPAddress) и флаги для неподдерживаемых случаев (unsupported name type,
 * invalid min/max, non-critical).</p>
 *
 * <p>Потокобезопасен: все поля final.</p>
 */
public final class NameConstraintsData {

    /** permittedSubtrees dNSName — null если ограничений этого типа нет */
    public final String[] permittedDnsNames;

    /** permittedSubtrees iPAddress — 8 байт (IPv4) или 32 байта (IPv6) */
    public final byte[][] permittedIps;

    /** permittedSubtrees rfc822Name — null если ограничений этого типа нет */
    public final String[] permittedRfc822Names;

    /** permittedSubtrees URI — IA5String, null если нет */
    public final String[] permittedUris;

    /** permittedSubtrees directoryName — raw DER DN, null если нет */
    public final byte[][] permittedDirectoryNames;

    /** excludedSubtrees dNSName */
    public final String[] excludedDnsNames;

    /** excludedSubtrees iPAddress — 8 байт (IPv4) или 32 байта (IPv6) */
    public final byte[][] excludedIps;

    /** excludedSubtrees rfc822Name */
    public final String[] excludedRfc822Names;

    /** excludedSubtrees URI */
    public final String[] excludedUris;

    /** excludedSubtrees directoryName — raw DER DN */
    public final byte[][] excludedDirectoryNames;

    /**
     * Встречен неподдерживаемый тип GeneralName (otherName).
     * Неподдерживаемые типы НЕ могут быть проверены, поэтому
     * ChainValidator НЕ reject'ит цепочку, если лист НЕ содержит
     * имён этих типов в SAN — только WARNING.
     * Если же лист содержит otherName в SAN, а NameConstraints
     * имеют otherName ограничения — REJECT (fail-closed).
     */
    public final boolean hasUnsupportedNameType;

    /**
     * Встречена rfc822Name-запись в mailbox-форме ({@code root@example.com}).
     * RFC 5280 §4.2.1.10 разрешает такую форму, но библиотека поддерживает
     * только доменную форму (hostname / .domain). Fail-closed: если ограничение
     * содержит mailbox-форму, а лист имеет rfc822Name в SAN — REJECT.
     */
    public final boolean hasUnsupportedRfc822Form;

    /** min != 0 или max присутствует в любом subtree (RFC 5280 §4.2.1.10). */
    public final boolean hasInvalidMinMax;

    /** Расширение было non-critical — нарушение RFC 5280 §4.2.1.10 "MUST be critical". */
    public final boolean nonCritical;

    public NameConstraintsData(
            String[] permittedDnsNames,
            byte[][] permittedIps,
            String[] permittedRfc822Names,
            String[] permittedUris,
            byte[][] permittedDirectoryNames,
            String[] excludedDnsNames,
            byte[][] excludedIps,
            String[] excludedRfc822Names,
            String[] excludedUris,
            byte[][] excludedDirectoryNames,
            boolean hasUnsupportedNameType,
            boolean hasUnsupportedRfc822Form,
            boolean hasInvalidMinMax,
            boolean nonCritical) {
        this.permittedDnsNames = permittedDnsNames;
        this.permittedIps = permittedIps;
        this.permittedRfc822Names = permittedRfc822Names;
        this.permittedUris = permittedUris;
        this.permittedDirectoryNames = permittedDirectoryNames;
        this.excludedDnsNames = excludedDnsNames;
        this.excludedIps = excludedIps;
        this.excludedRfc822Names = excludedRfc822Names;
        this.excludedUris = excludedUris;
        this.excludedDirectoryNames = excludedDirectoryNames;
        this.hasUnsupportedNameType = hasUnsupportedNameType;
        this.hasUnsupportedRfc822Form = hasUnsupportedRfc822Form;
        this.hasInvalidMinMax = hasInvalidMinMax;
        this.nonCritical = nonCritical;
    }

    /** Пустой объект — сертификат без NameConstraints. */
    public static final NameConstraintsData EMPTY =
            new NameConstraintsData(
                    null, null, null, null, null, null, null, null, null, null, false, false, false,
                    false);

    /**
     * Есть ли хоть какие-то ограничения (permitted или excluded любого типа).
     *
     * <p>Флаги ошибок ({@code hasUnsupportedNameType}, {@code hasInvalidMinMax},
     * {@code nonCritical}) намеренно входят в проверку: {@code ChainValidator} использует
     * {@code if (!nc.isEmpty())} как единственный вход в блок fail-closed-проверок.
     * Если бы {@code isEmpty()} учитывал только списки permitted/excluded, то
     * NameConstraints со взведённым флагом ошибки и пустыми списками дал бы
     * {@code isEmpty()==true}, блок был бы пропущен целиком, и цепочка прошла бы
     * валидацию (fail-open) вопреки требованию отклонять такие сертификаты.</p>
     *
     * @return true если объект не содержит ни ограничений, ни флагов ошибок
     */
    public boolean isEmpty() {
        return permittedDnsNames == null
                && permittedIps == null
                && permittedRfc822Names == null
                && permittedUris == null
                && permittedDirectoryNames == null
                && excludedDnsNames == null
                && excludedIps == null
                && excludedRfc822Names == null
                && excludedUris == null
                && excludedDirectoryNames == null
                && !hasUnsupportedNameType
                && !hasUnsupportedRfc822Form
                && !hasInvalidMinMax
                && !nonCritical;
    }
}
