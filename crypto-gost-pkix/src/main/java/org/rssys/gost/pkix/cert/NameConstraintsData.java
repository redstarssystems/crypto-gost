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

    /** excludedSubtrees dNSName */
    public final String[] excludedDnsNames;

    /** excludedSubtrees iPAddress — 8 байт (IPv4) или 32 байта (IPv6) */
    public final byte[][] excludedIps;

    /**
     * Встречен неподдерживаемый тип GeneralName
     * (rfc822Name, directoryName, URI, otherName).
     * ChainValidator не reject'ит цепочку при этом флаге, а выводит WARNING:
     * ограничения неподдерживаемых типов игнорируются.
     * Безопасность: GostCertificate не экспонирует accessor'ы для этих форм
     * из SAN — злоумышленный rfc822Name/URI/otherName физически не может
     * повлиять ни на одно решение библиотеки.
     */
    public final boolean hasUnsupportedNameType;

    /** min != 0 или max присутствует в любом subtree (RFC 5280 §4.2.1.10). */
    public final boolean hasInvalidMinMax;

    /** Расширение было non-critical — нарушение RFC 5280 §4.2.1.10 "MUST be critical". */
    public final boolean nonCritical;

    public NameConstraintsData(
            String[] permittedDnsNames,
            byte[][] permittedIps,
            String[] excludedDnsNames,
            byte[][] excludedIps,
            boolean hasUnsupportedNameType,
            boolean hasInvalidMinMax,
            boolean nonCritical) {
        this.permittedDnsNames = permittedDnsNames;
        this.permittedIps = permittedIps;
        this.excludedDnsNames = excludedDnsNames;
        this.excludedIps = excludedIps;
        this.hasUnsupportedNameType = hasUnsupportedNameType;
        this.hasInvalidMinMax = hasInvalidMinMax;
        this.nonCritical = nonCritical;
    }

    /** Пустой объект — сертификат без NameConstraints. */
    public static final NameConstraintsData EMPTY =
            new NameConstraintsData(null, null, null, null, false, false, false);

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
                && excludedDnsNames == null
                && excludedIps == null
                && !hasUnsupportedNameType
                && !hasInvalidMinMax
                && !nonCritical;
    }
}
