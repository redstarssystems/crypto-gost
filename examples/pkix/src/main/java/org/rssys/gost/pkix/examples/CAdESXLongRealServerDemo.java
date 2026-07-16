package org.rssys.gost.pkix.examples;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCertificateBuilder;
import org.rssys.gost.pkix.cert.GostCrl;
import org.rssys.gost.pkix.cert.GostCrlBuilder;
import org.rssys.gost.pkix.cert.GostDnParser;
import org.rssys.gost.pkix.cert.GostOcspResponse;
import org.rssys.gost.pkix.cert.GostOcspResponseBuilder;
import org.rssys.gost.pkix.cms.CAdESExtender;
import org.rssys.gost.pkix.cms.CAdESSignerResult;
import org.rssys.gost.pkix.cms.CmsSignedDataBuilder;
import org.rssys.gost.pkix.cms.VerifiedCAdESData;
import org.rssys.gost.pkix.tsp.JdkHttpTspTransport;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.util.CryptoRandom;

public final class CAdESXLongRealServerDemo {

    private static final String TSA_URL = "http://pki.skbkontur.ru/tsp2012/tsp.srf";
    private static final ECParameters PARAMS = ECParameters.tc26a256();

    public static void main(String[] args) throws Exception {
        System.out.println("=== CAdES-X Long Type 1 + TSP Контура ===\n");

        KeyPair rootKp = KeyGenerator.generateKeyPair(PARAMS, CryptoRandom.INSTANCE);
        KeyPair intKp = KeyGenerator.generateKeyPair(PARAMS, CryptoRandom.INSTANCE);
        KeyPair leafKp = KeyGenerator.generateKeyPair(PARAMS, CryptoRandom.INSTANCE);

        byte[] rootDn = GostDnParser.encodeDn("CN=CAdES-XL Demo Root CA,O=crypto-gost,C=RU");
        byte[] intDn = GostDnParser.encodeDn("CN=CAdES-XL Demo Intermediate CA,O=crypto-gost,C=RU");
        byte[] leafDn = GostDnParser.encodeDn("CN=CAdES-XL Demo Leaf Signer,O=crypto-gost,C=RU");

        GostCertificate rootCert =
                GostCertificateBuilder.create(PARAMS, rootDn)
                        .publicKey(rootKp.getPublic())
                        .notBeforeNow()
                        .validForDays(365 * 10)
                        .keyUsage(GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN)
                        .basicConstraints(true, 1)
                        .serial(GostCertificateBuilder.generateSerial())
                        .sign(rootKp.getPrivate());

        GostCertificate intCert =
                GostCertificateBuilder.create(PARAMS, intDn)
                        .publicKey(intKp.getPublic())
                        .issuerDn(rootDn)
                        .notBeforeNow()
                        .validForDays(365 * 10)
                        .keyUsage(GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN)
                        .basicConstraints(true, 0)
                        .serial(GostCertificateBuilder.generateSerial())
                        .sign(rootKp.getPrivate());

        GostCertificate leafCert =
                GostCertificateBuilder.create(PARAMS, leafDn)
                        .publicKey(leafKp.getPublic())
                        .issuerDn(intDn)
                        .notBeforeNow()
                        .validForDays(365 * 10)
                        .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                        .serial(GostCertificateBuilder.generateSerial())
                        .sign(intKp.getPrivate());

        System.out.println("Цепочка: Root CA -> Intermediate CA -> Leaf");

        byte[] data = "CAdES-XL demo with Kontur TSP".getBytes(StandardCharsets.UTF_8);
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(leafKp.getPrivate(), leafCert)
                        .withCAdES()
                        .build();
        System.out.println("CAdES-BES: " + cadesBes.length + " байт");

        GostCertificate sertumCa = loadCert("sertum-q-2025.der");
        GostCertificate guc2022 = loadCert("guc2022.der");
        GostCertificate[] tsaTrusted = {sertumCa, guc2022};
        System.out.println("TSP: запрос к " + TSA_URL + " ...");

        byte[] cadesT =
                CAdESExtender.addTimestamp(
                        cadesBes, TSA_URL, new JdkHttpTspTransport(), tsaTrusted);
        System.out.println("CAdES-T: " + cadesT.length + " байт");

        byte[] crlDer =
                GostCrlBuilder.create(rootCert.getSubjectDnBytes())
                        .thisUpdateNow()
                        .nextUpdateDays(30)
                        .withCrlNumber(1)
                        .sign(rootKp.getPrivate());
        GostCrl crl = new GostCrl(crlDer);
        System.out.println("CRL от RootCA: " + crlDer.length + " байт");

        byte[] ocspDer =
                GostOcspResponseBuilder.create(leafCert.getSerialNumber())
                        .issuerDn(intCert.getSubjectDnBytes())
                        .good()
                        .sign(intKp.getPrivate());
        GostOcspResponse ocsp = new GostOcspResponse(ocspDer);
        System.out.println("OCSP от IntCA (leaf=good): " + ocspDer.length + " байт");

        System.out.println("Сборка CAdES-XL ...");
        List<GostCertificate> chain = Arrays.asList(leafCert, intCert, rootCert);
        List<GostCrl> crls = Arrays.asList(null, crl, null);
        List<GostOcspResponse> ocspList = Arrays.asList(ocsp, null, null);

        byte[] cadesXLong =
                CAdESExtender.embedXLongType1(cadesT, chain, crls, ocspList, null, null);
        System.out.println("CAdES-XL: " + cadesXLong.length + " байт");

        VerifiedCAdESData result =
                CAdESExtender.verifyCAdESXLong(cadesXLong, rootCert, sertumCa, guc2022);
        System.out.println("verifyCAdESXLong: пройдена");
        System.out.println("Данные: " + new String(result.data(), StandardCharsets.UTF_8));

        for (CAdESSignerResult sr : result.signers()) {
            System.out.println("Подписант: " + sr.signerCertificate().getSubjectDnForLog(60));
            System.out.println("  Меток времени: " + sr.timestamps().size());
            System.out.println("  CertificateValues: " + sr.certificateValues().size() + " серт.");
            System.out.println(
                    "  RevocationValues: CRL="
                            + sr.revocationValues().crls().size()
                            + ", OCSP="
                            + sr.revocationValues().ocspResponses().size());
        }

        System.out.println("\nПолный цикл CAdES-XL Type 1 с TSP Контура пройден.");
    }

    private static GostCertificate loadCert(String resource) throws Exception {
        try (InputStream is =
                CAdESXLongRealServerDemo.class.getClassLoader().getResourceAsStream(resource)) {
            if (is == null) {
                throw new RuntimeException("Ресурс не найден: " + resource);
            }
            return GostCertificate.fromDer(is.readAllBytes());
        }
    }
}
