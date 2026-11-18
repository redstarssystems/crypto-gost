package org.rssys.gost.cipher.mode;

/**
 * Размеры секций ACPKM для разных профилей использования.
 *
 * <p>Секционная смена ключа (ACPKM) по Р 1323565.1.017-2018, RFC 8645:
 * каждые {@code sectionSize} байт ключ переразвёртывается через
 * {@code E_K(D[0..15]) || E_K(D[16..31])}.
 *
 * <p>Значение sectionSize фиксируется конкретным протоколом
 * (RFC 9337 §7.3). Все значения обязаны быть кратны размеру блока
 * Кузнечика (16 байт) — RFC 8645 §6.2.1.
 */
public final class AcpkmSectionSize {

    /**
     * Базовый размер секции для Кузнечика — 4096 байт.
     * Р 1323565.1.017-2018, RFC 8645; RFC 9189 (TLS 1.2 GOST);
     * gost-engine (не-CMS дефолт).
     */
    public static final int DEFAULT = 4096;

    /**
     * Размер секции для CMS EnvelopedData — 256 КБ.
     * gost-engine {@code gost_grasshopper_set_asn1_parameters}
     * и {@code gost_grasshopper_get_asn1_parameters}:
     * {@code /* CMS implies 256kb section_size * /}.
     */
    public static final int CMS = 256 * 1024;

    private AcpkmSectionSize() {}
}
