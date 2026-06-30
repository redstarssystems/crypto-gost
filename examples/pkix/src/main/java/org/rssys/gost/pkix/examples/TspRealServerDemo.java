package org.rssys.gost.pkix.examples;

import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCertificateBuilder;
import org.rssys.gost.pkix.cms.CAdESExtender;
import org.rssys.gost.pkix.cms.CAdESSignerResult;
import org.rssys.gost.pkix.cms.CmsSignedDataBuilder;
import org.rssys.gost.pkix.cms.VerifiedCAdESData;
import org.rssys.gost.pkix.tsp.JdkHttpTspTransport;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.util.CryptoRandom;

/**
 * Демонстрация полного цикла CAdES + TSP с боевым сервером СКБ Контур.
 *
 * <p>Запуск из корня проекта:
 * <pre>
 * mvn -f examples/pkix compile exec:java \
 *   -Dexec.mainClass=org.rssys.gost.pkix.examples.TspRealServerDemo
 * </pre>
 *
 * <p>TSP-сервер: {@code http://pki.skbkontur.ru/tsp2012/tsp.srf}
 * <p>Сертификаты УЦ (ООО «Сертум-Про» + Минцифры России) —
 *    встроены в ресурсы примера.
 */
public final class TspRealServerDemo {

    private static final String TSA_URL = "http://pki.skbkontur.ru/tsp2012/tsp.srf";
    private static final ECParameters PARAMS = ECParameters.tc26a256();

    public static void main(String[] args) throws Exception {
        System.out.println("=== TSP Real Server Demo ===\n");

        // ---------------------------------------------------------------
        // 0. Ключи и самоподписанный сертификат подписанта
        // ---------------------------------------------------------------
        KeyPair signerKp = KeyGenerator.generateKeyPair(PARAMS, CryptoRandom.INSTANCE);
        GostCertificate signerCert =
                GostCertificateBuilder.create(PARAMS, "CN=Demo Signer")
                        .publicKey(signerKp.getPublic())
                        .notBefore("20250101000000Z")
                        .notAfter("20350101000000Z")
                        .serial(new BigInteger(63, CryptoRandom.INSTANCE))
                        .assembleCert(signerKp.getPrivate());

        byte[] data = "TSP demo data".getBytes(StandardCharsets.UTF_8);
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .withCAdES()
                        .build();
        System.out.println("CAdES-BES: " + cadesBes.length + " байт");

        // ---------------------------------------------------------------
        // 1. Доверенные сертификаты TSA из ресурсов
        // ---------------------------------------------------------------
        GostCertificate sertumCa = loadCert("sertum-q-2025.der");
        GostCertificate guc2022 = loadCert("guc2022.der");
        System.out.println("Сертум-Про: " + sertumCa.getSubjectDnForLog(60));
        System.out.println("Минцифры:   " + guc2022.getSubjectDnForLog(60));

        GostCertificate[] tsaTrusted = {sertumCa, guc2022};

        // ---------------------------------------------------------------
        // 2. CAdES-T — один вызов: запрос, verify nonce, встраивание
        // ---------------------------------------------------------------
        System.out.println("\nЗапрос метки времени на " + TSA_URL + " ...");
        byte[] cadesT =
                CAdESExtender.addTimestamp(
                        cadesBes, TSA_URL, new JdkHttpTspTransport(), tsaTrusted);
        System.out.println("CAdES-T: " + cadesT.length + " байт");

        // ---------------------------------------------------------------
        // 3. Проверка CAdES-T
        // ---------------------------------------------------------------
        VerifiedCAdESData result =
                CAdESExtender.verifyCAdEST(cadesT, signerCert, sertumCa, guc2022);
        System.out.println("verifyCAdEST: пройдена");
        System.out.println("Данные: " + new String(result.data(), StandardCharsets.UTF_8));
        System.out.println("Подписант: " + result.signerCertificate().getSubjectDnForLog(60));

        for (CAdESSignerResult sr : result.signers()) {
            sr.timestamps()
                    .forEach(
                            tst ->
                                    System.out.println(
                                            "  Метка: genTime="
                                                    + tst.genTime()
                                                    + "  policy="
                                                    + tst.policyOid()
                                                    + "  serial="
                                                    + tst.serialNumber()));
        }

        System.out.println("\nПолный цикл CAdES-BES -> TSP -> CAdES-T -> verify пройден.");
    }

    private static GostCertificate loadCert(String resource) throws Exception {
        try (InputStream is =
                TspRealServerDemo.class.getClassLoader().getResourceAsStream(resource)) {
            if (is == null) {
                throw new RuntimeException("Ресурс не найден: " + resource);
            }
            return GostCertificate.fromDer(is.readAllBytes());
        }
    }
}
