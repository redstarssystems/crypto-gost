package org.rssys.gost.pkix.cert;

/**
 * Запись otherName в SAN/IAN (RFC 5280 §4.2.1.6).
 *
 * <p>Используется единообразно в write-пути ({@link GostCertificateBuilder},
 * {@link GostCsrBuilder}) и read-пути ({@link GostCertificate},
 * {@link GostExtensionParser.ExtensionsResult}).</p>
 *
 * @param oid      OID типа otherName (например, {@code "1.3.6.1.4.1.311.20.2.3"} для UPN)
 * @param valueDer DER-кодированное значение внутри [0] EXPLICIT (со своим тегом)
 */
public record OtherNameEntry(String oid, byte[] valueDer) {}
