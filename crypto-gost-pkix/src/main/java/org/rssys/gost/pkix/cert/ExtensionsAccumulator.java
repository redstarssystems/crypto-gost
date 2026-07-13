package org.rssys.gost.pkix.cert;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import org.rssys.gost.api.Digest;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.util.DerCodec;

/**
 * Накопитель общих расширений X.509v3 для {@link GostCertificateBuilder} и
 * {@link GostCsrBuilder}.
 *
 * <p>Содержит поля и fluent-сеттеры для расширений, общих для сертификата и CSR:
 * SubjectAltName, KeyUsage, ExtendedKeyUsage, BasicConstraints,
 * CertificatePolicies, SubjectKeyIdentifier и сырых дополнительных расширений.
 * Специфичные для сертификата расширения (IssuerAltName, AIA, CDP,
 * FreshestCRL, AuthorityKeyIdentifier, NameConstraints) остаются в
 * {@code GostCertificateBuilder}.</p>
 *
 * <p>Порядок записи в {@link #writeExtensions(ByteArrayOutputStream)}:
 * SAN → KeyUsage → EKU → BasicConstraints → CertificatePolicies → SKI.
 * {@code additionalExtensions} пишется вызывающим кодом явно последним шагом.</p>
 */
public final class ExtensionsAccumulator {

    String[] sanDnsNames;
    String[] sanIps;
    String[] sanRfc822Names;
    String[] sanUris;
    byte[][] sanDirectoryNames;
    OtherNameEntry[] sanOtherNames;
    byte[] keyUsageFlags;
    String[] ekuOids;
    boolean ekuCritical;
    Boolean isCA;
    Integer pathLen;
    byte[] skiBytes;
    CertificatePolicy[] certificatePolicies;
    byte[] additionalExtensions;

    public ExtensionsAccumulator sanDns(String... names) {
        this.sanDnsNames = names;
        return this;
    }

    public ExtensionsAccumulator sanIp(String... ips) {
        this.sanIps = ips;
        return this;
    }

    public ExtensionsAccumulator sanRfc822Name(String... emails) {
        this.sanRfc822Names = emails;
        return this;
    }

    public ExtensionsAccumulator sanUri(String... uris) {
        this.sanUris = uris;
        return this;
    }

    public ExtensionsAccumulator sanDirectoryName(byte[]... dnDer) {
        this.sanDirectoryNames = dnDer;
        return this;
    }

    public ExtensionsAccumulator sanOtherName(String oid, byte[] valueDer) {
        this.sanOtherNames = new OtherNameEntry[] {new OtherNameEntry(oid, valueDer)};
        return this;
    }

    public ExtensionsAccumulator sanUpn(String upn) {
        byte[] upnValue = DerCodec.encodeUTF8String(upn);
        return sanOtherName(GostOids.ID_MS_UPN, upnValue);
    }

    public ExtensionsAccumulator keyUsage(GostCertificateBuilder.KeyUsage... usages) {
        this.keyUsageFlags = keyUsageFlags(usages);
        return this;
    }

    public ExtensionsAccumulator extendedKeyUsage(String... oids) {
        this.ekuOids = oids;
        this.ekuCritical = false;
        return this;
    }

    public ExtensionsAccumulator extendedKeyUsage(boolean critical, String... oids) {
        this.ekuOids = oids;
        this.ekuCritical = critical;
        return this;
    }

    public ExtensionsAccumulator basicConstraints(boolean isCA, Integer pathLen) {
        if (pathLen != null && !isCA) {
            throw new IllegalArgumentException("pathLen requires isCA=true");
        }
        this.isCA = isCA;
        this.pathLen = pathLen;
        return this;
    }

    /**
     * Устанавливает предвычисленный SubjectKeyIdentifier.
     * Вызывается билдерами из метода {@code ski()}.
     */
    public ExtensionsAccumulator ski(byte[] bytes) {
        this.skiBytes = bytes;
        return this;
    }

    public ExtensionsAccumulator certificatePolicies(String... policyOids) {
        if (policyOids != null) {
            this.certificatePolicies = CertificatePolicy.fromOids(policyOids);
        }
        return this;
    }

    public ExtensionsAccumulator certificatePolicyInfos(CertificatePolicy... policies) {
        this.certificatePolicies = policies;
        return this;
    }

    public ExtensionsAccumulator additionalExtensions(byte[] der) {
        this.additionalExtensions = der;
        return this;
    }

    boolean hasAnyExtensions() {
        return (sanDnsNames != null && sanDnsNames.length > 0)
                || (sanIps != null && sanIps.length > 0)
                || (sanRfc822Names != null && sanRfc822Names.length > 0)
                || (sanUris != null && sanUris.length > 0)
                || (sanDirectoryNames != null && sanDirectoryNames.length > 0)
                || (sanOtherNames != null && sanOtherNames.length > 0)
                || keyUsageFlags != null
                || ekuOids != null
                || isCA != null
                || skiBytes != null
                || (certificatePolicies != null && certificatePolicies.length > 0)
                || additionalExtensions != null;
    }

    boolean hasAnySanNames() {
        return (sanDnsNames != null && sanDnsNames.length > 0)
                || (sanIps != null && sanIps.length > 0)
                || (sanRfc822Names != null && sanRfc822Names.length > 0)
                || (sanUris != null && sanUris.length > 0)
                || (sanDirectoryNames != null && sanDirectoryNames.length > 0)
                || (sanOtherNames != null && sanOtherNames.length > 0);
    }

    /**
     * Записывает accumulator-расширения в поток.
     * Порядок: SAN → KeyUsage → EKU → BasicConstraints → CertificatePolicies → SKI.
     * additionalExtensions не пишется — вызывающий код делает это явно.
     */
    void writeExtensions(ByteArrayOutputStream out) throws IOException {
        if (hasAnySanNames()) {
            out.write(
                    buildSanExtension(
                            sanDnsNames,
                            sanIps,
                            sanRfc822Names,
                            sanUris,
                            sanDirectoryNames,
                            sanOtherNames));
        }
        if (keyUsageFlags != null) {
            out.write(buildKeyUsageExtension(keyUsageFlags, true));
        }
        if (ekuOids != null) {
            out.write(buildEkuExtension(ekuOids, ekuCritical));
        }
        if (isCA != null) {
            out.write(buildBasicConstraintsExtension(isCA, pathLen));
        }
        if (certificatePolicies != null && certificatePolicies.length > 0) {
            out.write(buildCertificatePoliciesExtension(certificatePolicies));
        }
        if (skiBytes != null) {
            out.write(buildSkiExtensionBytes(skiBytes));
        }
    }

    // ========================================================================
    // Статические строители расширений
    // ========================================================================

    public static byte[] keyUsageFlags(GostCertificateBuilder.KeyUsage... usages) {
        int mask = 0;
        for (GostCertificateBuilder.KeyUsage u : usages) {
            mask |= u.mask;
        }
        return new byte[] {(byte) mask};
    }

    public static byte[] buildKeyUsageExtension(GostCertificateBuilder.KeyUsage... usages) {
        return buildKeyUsageExtension(keyUsageFlags(usages), false);
    }

    public static byte[] buildKeyUsageExtension(byte[] kuFlags, boolean critical) {
        byte[] extValue = DerCodec.encodeOctetString(DerCodec.encodeBitString(kuFlags));
        if (critical) {
            return DerCodec.encodeSequence(
                    DerCodec.encodeOid(GostOids.EXT_KU), DerCodec.encodeBoolean(true), extValue);
        }
        return DerCodec.encodeSequence(DerCodec.encodeOid(GostOids.EXT_KU), extValue);
    }

    public static byte[] buildEkuExtension(String[] oids, boolean critical) {
        ByteArrayOutputStream ekuSeq = new ByteArrayOutputStream();
        for (String oid : oids) {
            try {
                ekuSeq.write(DerCodec.encodeOid(oid));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        if (critical) {
            return DerCodec.encodeSequence(
                    DerCodec.encodeOid(GostOids.EXT_EKU),
                    DerCodec.encodeBoolean(true),
                    DerCodec.encodeOctetString(DerCodec.encodeSequence(ekuSeq.toByteArray())));
        }
        return DerCodec.encodeSequence(
                DerCodec.encodeOid(GostOids.EXT_EKU),
                DerCodec.encodeOctetString(DerCodec.encodeSequence(ekuSeq.toByteArray())));
    }

    public static byte[] buildCertificatePoliciesExtension(CertificatePolicy[] policies) {
        ByteArrayOutputStream cpSeq = new ByteArrayOutputStream();
        for (CertificatePolicy policy : policies) {
            try {
                ByteArrayOutputStream piSeq = new ByteArrayOutputStream();
                piSeq.write(DerCodec.encodeOid(policy.policyOid()));
                if (policy.cpsUri() != null) {
                    byte[] qualifierSeq =
                            DerCodec.encodeSequence(
                                    DerCodec.encodeOid(GostOids.POLICY_QT_CPS),
                                    DerCodec.encodeTlv(
                                            DerCodec.TAG_IA5_STRING,
                                            policy.cpsUri().getBytes(StandardCharsets.US_ASCII)));
                    byte[] qualifiersSeq = DerCodec.encodeSequence(qualifierSeq);
                    piSeq.write(qualifiersSeq);
                }
                cpSeq.write(DerCodec.encodeSequence(piSeq.toByteArray()));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        return DerCodec.encodeSequence(
                DerCodec.encodeOid(GostOids.EXT_CP),
                DerCodec.encodeOctetString(DerCodec.encodeSequence(cpSeq.toByteArray())));
    }

    public static byte[] buildBasicConstraintsExtension(boolean isCA, Integer pathLen) {
        if (pathLen != null && !isCA) {
            throw new IllegalArgumentException("pathLen requires isCA=true");
        }
        ByteArrayOutputStream bcSeq = new ByteArrayOutputStream();
        try {
            if (isCA) {
                bcSeq.write(new byte[] {0x01, 0x01, (byte) 0xFF});
            }
            if (pathLen != null) {
                bcSeq.write(DerCodec.encodeInteger(pathLen));
            }
        } catch (IOException e) {
            throw new RuntimeException("Unexpected IOException from ByteArrayOutputStream", e);
        }
        byte[] bcContent = DerCodec.encodeSequence(bcSeq.toByteArray());
        byte[] extValue = DerCodec.encodeOctetString(bcContent);
        if (isCA) {
            return DerCodec.encodeSequence(
                    DerCodec.encodeOid(GostOids.EXT_BC), DerCodec.encodeBoolean(true), extValue);
        }
        return DerCodec.encodeSequence(DerCodec.encodeOid(GostOids.EXT_BC), extValue);
    }

    public static byte[] buildAiaExtension(String ocspUri, String caIssuersUri) {
        if (ocspUri == null && caIssuersUri == null) {
            throw new IllegalArgumentException(
                    "At least one of ocspUri or caIssuersUri must be non-null");
        }
        ByteArrayOutputStream aiaSeq = new ByteArrayOutputStream();
        if (ocspUri != null) {
            byte[] ocspAccessDesc = accessDescription(GostOids.OCSP_AD, ocspUri);
            aiaSeq.write(ocspAccessDesc, 0, ocspAccessDesc.length);
        }
        if (caIssuersUri != null) {
            byte[] caIssuersAccessDesc = accessDescription(GostOids.CA_ISSUERS_AD, caIssuersUri);
            aiaSeq.write(caIssuersAccessDesc, 0, caIssuersAccessDesc.length);
        }
        byte[] aiaSeqEncoded = DerCodec.encodeSequence(aiaSeq.toByteArray());
        byte[] extValue = DerCodec.encodeOctetString(aiaSeqEncoded);
        return DerCodec.encodeSequence(DerCodec.encodeOid(GostOids.EXT_AIA), extValue);
    }

    private static byte[] accessDescription(String accessMethodOid, String uri) {
        byte[] uriBytes = uri.getBytes(StandardCharsets.US_ASCII);
        return DerCodec.encodeSequence(
                DerCodec.encodeOid(accessMethodOid), DerCodec.encodeTlv(0x86, uriBytes));
    }

    public static byte[] buildOcspNoCheckExtension() {
        return DerCodec.encodeSequence(
                DerCodec.encodeOid(GostOids.EXT_OCSP_NOCHECK),
                DerCodec.encodeOctetString(DerCodec.encodeNull()));
    }

    public static byte[] buildSanExtension(
            String[] dnsNames,
            String[] ipAddresses,
            String[] rfc822Names,
            String[] uris,
            byte[][] directoryNames,
            OtherNameEntry[] otherNames) {
        byte[] gnSeq =
                encodeGeneralNamesAllTypes(
                        dnsNames, ipAddresses, rfc822Names, uris, directoryNames, otherNames);
        byte[] extValue = DerCodec.encodeOctetString(gnSeq);
        return DerCodec.encodeSequence(DerCodec.encodeOid(GostOids.EXT_SAN), extValue);
    }

    public static byte[] buildIssuerAltNameExtension(
            String[] dnsNames,
            String[] ipAddresses,
            String[] rfc822Names,
            String[] uris,
            byte[][] directoryNames,
            OtherNameEntry[] otherNames) {
        byte[] gnSeq =
                encodeGeneralNamesAllTypes(
                        dnsNames, ipAddresses, rfc822Names, uris, directoryNames, otherNames);
        byte[] extValue = DerCodec.encodeOctetString(gnSeq);
        return DerCodec.encodeSequence(DerCodec.encodeOid(GostOids.EXT_IAN), extValue);
    }

    private static byte[] encodeGeneralNamesAllTypes(
            String[] dnsNames,
            String[] ipAddresses,
            String[] rfc822Names,
            String[] uris,
            byte[][] directoryNames,
            OtherNameEntry[] otherNames) {
        ArrayList<byte[]> names = new ArrayList<>();
        if (dnsNames != null) {
            for (String name : dnsNames) {
                names.add(GeneralNameCodec.encodeDnsName(name));
            }
        }
        if (ipAddresses != null) {
            for (String ip : ipAddresses) {
                names.add(GeneralNameCodec.encodeIpAddress(ip));
            }
        }
        if (rfc822Names != null) {
            for (String email : rfc822Names) {
                names.add(GeneralNameCodec.encodeRfc822Name(email));
            }
        }
        if (uris != null) {
            for (String uri : uris) {
                names.add(GeneralNameCodec.encodeUri(uri));
            }
        }
        if (directoryNames != null) {
            for (byte[] dn : directoryNames) {
                names.add(GeneralNameCodec.encodeDirectoryName(dn));
            }
        }
        if (otherNames != null) {
            for (OtherNameEntry entry : otherNames) {
                names.add(GeneralNameCodec.encodeOtherName(entry.oid(), entry.valueDer()));
            }
        }
        return GeneralNameCodec.encodeGeneralNames(names.toArray(new byte[0][]));
    }

    public static byte[] buildCdpExtension(String... crlUris) {
        return buildDistributionPointExtension(GostOids.EXT_CDP, crlUris);
    }

    public static byte[] buildFreshestCrlExtension(String... uris) {
        return buildDistributionPointExtension(GostOids.EXT_FRESHEST_CRL, uris);
    }

    static byte[] buildDistributionPointExtension(String oid, String... uris) {
        ByteArrayOutputStream dps = new ByteArrayOutputStream();
        for (String uri : uris) {
            byte[] uriBytes = uri.getBytes(StandardCharsets.US_ASCII);
            byte[] gnUri = DerCodec.encodeTlv(0x86, uriBytes);
            byte[] fullName = DerCodec.encodeTlv(0xA0, gnUri);
            byte[] distPointContent = DerCodec.encodeTlv(0xA0, fullName);
            byte[] distPointSeq = DerCodec.encodeSequence(distPointContent);
            try {
                dps.write(distPointSeq);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        byte[] distributionPoints = DerCodec.encodeSequence(dps.toByteArray());
        byte[] extValue = DerCodec.encodeOctetString(distributionPoints);
        return DerCodec.encodeSequence(DerCodec.encodeOid(oid), extValue);
    }

    public static byte[] buildSkiExtension(PublicKeyParameters pub) {
        byte[] pointBytes = GostDerCodec.subjectPublicKeyPointBytes(pub);
        byte[] ski = Digest.digest256(pointBytes);
        byte[] skiOctet = DerCodec.encodeOctetString(ski);
        byte[] extValue = DerCodec.encodeOctetString(skiOctet);
        return DerCodec.encodeSequence(DerCodec.encodeOid(GostOids.EXT_SKI), extValue);
    }

    public static byte[] buildAkiExtension(byte[] issuerSkiBytes) {
        byte[] keyIdentifier = DerCodec.encodeTlv(0x80, issuerSkiBytes);
        byte[] akiValue = DerCodec.encodeSequence(keyIdentifier);
        byte[] extValue = DerCodec.encodeOctetString(akiValue);
        return DerCodec.encodeSequence(DerCodec.encodeOid(GostOids.EXT_AKI), extValue);
    }

    public static byte[] buildAkiExtension(PublicKeyParameters issuerPub) {
        byte[] pointBytes = GostDerCodec.subjectPublicKeyPointBytes(issuerPub);
        byte[] ski = Digest.digest256(pointBytes);
        return buildAkiExtension(ski);
    }

    public static byte[] buildNameConstraintsExtension(
            String[] permittedDns,
            String[] permittedIps,
            String[] excludedDns,
            String[] excludedIps) {
        if (isEmptyNc(permittedDns)
                && isEmptyNc(permittedIps)
                && isEmptyNc(excludedDns)
                && isEmptyNc(excludedIps)) {
            throw new IllegalArgumentException(
                    "NameConstraints must contain at least one constraint");
        }
        ByteArrayOutputStream ncSeq = new ByteArrayOutputStream();
        try {
            if (!isEmptyNc(permittedDns) || !isEmptyNc(permittedIps)) {
                byte[] gsP = encodeGeneralSubtreesNc(permittedDns, permittedIps);
                ncSeq.write(DerCodec.encodeContextConstructed(0, gsP));
            }
            if (!isEmptyNc(excludedDns) || !isEmptyNc(excludedIps)) {
                byte[] gsE = encodeGeneralSubtreesNc(excludedDns, excludedIps);
                ncSeq.write(DerCodec.encodeContextConstructed(1, gsE));
            }
        } catch (IOException e) {
            throw new RuntimeException("Unexpected IOException from ByteArrayOutputStream", e);
        }
        byte[] ncContent = DerCodec.encodeSequence(ncSeq.toByteArray());
        byte[] extValue = DerCodec.encodeOctetString(ncContent);
        return DerCodec.encodeSequence(
                DerCodec.encodeOid(GostOids.EXT_NAME_CONSTRAINTS),
                DerCodec.encodeBoolean(true),
                extValue);
    }

    private static boolean isEmptyNc(String[] arr) {
        return arr == null || arr.length == 0;
    }

    private static byte[] encodeGeneralSubtreesNc(String[] dnsNames, String[] ips) {
        ByteArrayOutputStream gs = new ByteArrayOutputStream();
        try {
            if (dnsNames != null) {
                for (String dns : dnsNames) {
                    byte[] gn = GeneralNameCodec.encodeDnsName(dns);
                    gs.write(encodeGeneralSubtree(gn));
                }
            }
            if (ips != null) {
                for (String ipCidr : ips) {
                    byte[] gn = GeneralNameCodec.encodeIpConstraint(ipCidr);
                    gs.write(encodeGeneralSubtree(gn));
                }
            }
        } catch (IOException e) {
            throw new RuntimeException("Unexpected IOException from ByteArrayOutputStream", e);
        }
        return DerCodec.encodeSequence(gs.toByteArray());
    }

    private static byte[] encodeGeneralSubtree(byte[] baseGeneralName) {
        return DerCodec.encodeSequence(baseGeneralName);
    }

    private static byte[] buildSkiExtensionBytes(byte[] ski) {
        byte[] skiOctet = DerCodec.encodeOctetString(ski);
        byte[] extValue = DerCodec.encodeOctetString(skiOctet);
        return DerCodec.encodeSequence(DerCodec.encodeOid(GostOids.EXT_SKI), extValue);
    }
}
