package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificateBuilder.KeyUsage;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.util.DerCodec;

/**
 * {@link GostCertificate#getExtensionValue(String)}: значение расширения (extnValue) из того же
 * строгого разбора, что и остальные свойства сертификата.
 */
@DisplayName("GostCertificate.getExtensionValue")
class GostCertificateExtensionValueTest {

    private static final int TAG_BIT_STRING = 0x03;

    private static GostCertificateBuilder baseBuilder(KeyPair kp, ECParameters params) {
        byte[] dn = GostDnParser.encodeDn("CN=Extension Value");
        return GostCertificateBuilder.create(params, dn)
                .publicKey(kp.getPublic())
                .notBeforeNow()
                .validForDays(30)
                .issuerDn(dn)
                .randomSerial();
    }

    @Test
    @DisplayName("присутствующее расширение: значение - DER значения расширения без обёртки")
    void presentExtensionReturnsExtnValue() {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        GostCertificate cert =
                baseBuilder(kp, params)
                        .keyUsage(KeyUsage.DIGITAL_SIGNATURE)
                        .extendedKeyUsage("1.3.6.1.5.5.7.3.2")
                        .sign(kp.getPrivate());

        byte[] keyUsage = cert.getExtensionValue(GostOids.EXT_KU);
        assertNotNull(keyUsage, "KeyUsage есть в сертификате");
        assertEquals(TAG_BIT_STRING, keyUsage[0] & 0xFF, "значение KeyUsage - BIT STRING");
        assertEquals(0x80, keyUsage[keyUsage.length - 1] & 0xFF, "установлен бит digitalSignature");

        byte[] eku = cert.getExtensionValue(GostOids.EXT_EKU);
        assertNotNull(eku, "ExtendedKeyUsage есть в сертификате");
        assertEquals(0x30, eku[0] & 0xFF, "значение EKU - SEQUENCE");
        assertArrayEquals(
                DerCodec.encodeSequence(DerCodec.encodeOid("1.3.6.1.5.5.7.3.2")),
                eku,
                "значение EKU - SEQUENCE из заданных OID");
    }

    @Test
    @DisplayName("отсутствующее расширение -> null")
    void absentExtensionReturnsNull() {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        GostCertificate cert = baseBuilder(kp, params).sanDns("example.org").sign(kp.getPrivate());

        assertNull(cert.getExtensionValue(GostOids.EXT_KU), "KeyUsage не задан");
        assertNotNull(cert.getExtensionValue("2.5.29.17"), "SubjectAltName задан");
        assertNull(cert.getExtensionValue("1.2.3.4.5.6"), "неизвестный OID");
    }

    @Test
    @DisplayName("критичность расширения значение не меняет")
    void criticalityDoesNotChangeValue() {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        GostCertificate noncritical =
                baseBuilder(kp, params)
                        .extendedKeyUsage(false, "1.3.6.1.5.5.7.3.1")
                        .sign(kp.getPrivate());
        GostCertificate critical =
                baseBuilder(kp, params)
                        .extendedKeyUsage(true, "1.3.6.1.5.5.7.3.1")
                        .sign(kp.getPrivate());

        assertArrayEquals(
                noncritical.getExtensionValue(GostOids.EXT_EKU),
                critical.getExtensionValue(GostOids.EXT_EKU),
                "значение не включает флаг критичности");
    }

    @Test
    @DisplayName("возвращается копия: изменение результата не влияет на сертификат")
    void returnedValueIsACopy() {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        GostCertificate cert =
                baseBuilder(kp, params).keyUsage(KeyUsage.DIGITAL_SIGNATURE).sign(kp.getPrivate());

        byte[] first = cert.getExtensionValue(GostOids.EXT_KU);
        byte[] original = first.clone();
        first[0] = 0x00;

        assertArrayEquals(original, cert.getExtensionValue(GostOids.EXT_KU));
        assertNotEquals(first[0], cert.getExtensionValue(GostOids.EXT_KU)[0]);
    }

    @Test
    @DisplayName("oid = null -> IllegalArgumentException")
    void nullOidRejected() {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        GostCertificate cert = baseBuilder(kp, params).sign(kp.getPrivate());

        assertThrows(IllegalArgumentException.class, () -> cert.getExtensionValue(null));
    }

    @Test
    @DisplayName("повторяющееся расширение отвергается при разборе: значения по OID однозначны")
    void duplicateExtensionRejectedByParser() {
        byte[] keyUsageValue = DerCodec.encodeBitString(new byte[] {(byte) 0x80});
        byte[] oid = DerCodec.encodeOid(GostOids.EXT_KU);
        byte[] one = DerCodec.encodeSequence(oid, DerCodec.encodeOctetString(keyUsageValue));
        byte[] twice = DerCodec.encodeSequence(one, one);

        assertThrows(
                IllegalArgumentException.class,
                () -> GostExtensionParser.parseExtensionsFromSequence(twice, 0),
                "второе расширение с тем же OID не должно подменять первое");
    }
}
