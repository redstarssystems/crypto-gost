package org.rssys.gost.crossval.cadest;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import org.rssys.gost.pkix.cms.CmsSignedDataBuilder;
import org.rssys.gost.util.DerCodec;

/**
 * Инструмент получения вектора CAdES-X Long с промежуточными УЦ через {@code cryptcp -enhance}.
 *
 * <p>Команды:
 * <ul>
 *   <li>{@code prepare <каталог>} - выпускает и пишет сертификаты УЦ, данные и detached CAdES-BES,
 *       подписанный crypto-gost (закрытый ключ КриптоПро не нужен);</li>
 *   <li>{@code serve <тот же каталог>} - поднимает локальный TSA, OCSP и CRL до нажатия Enter.</li>
 * </ul>
 * Затем: {@code cryptcp -enhance -xlongtype1 -enhall -cadestsa http://127.0.0.1:18080/tsp bes.p7s}.
 */
public final class CryptoproIntermediateVectorTool {

    private static final String DATA_FILE = "data.txt";
    private static final String BES_FILE = "xlong.p7s";
    private static final String ATTACHED_BES_FILE = "attached.p7s";
    private static final String SIGNING_TIME_OID = "1.2.840.113549.1.9.5";
    private static final int UTC_TIME_TAG = 0x17;
    private static final DateTimeFormatter SIGNING_TIME_FORMAT =
            DateTimeFormatter.ofPattern("yyMMddHHmmss'Z'").withZone(ZoneOffset.UTC);
    private static final String DATA_TEXT = "intermediate vector\n";

    private CryptoproIntermediateVectorTool() {}

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            usage();
            return;
        }
        // оба режима работают с одним каталогом, чтобы сертификаты совпадали побайтно
        Path stateDir = Paths.get(args.length > 1 ? args[1] : ".");
        CryptoproIntermediateFixtures fixtures = new CryptoproIntermediateFixtures(stateDir);
        switch (args[0]) {
            case "prepare" -> prepare(fixtures, stateDir);
            case "serve" -> serve(fixtures);
            default -> usage();
        }
    }

    private static void prepare(CryptoproIntermediateFixtures fixtures, Path outDir)
            throws Exception {
        Files.createDirectories(outDir);
        byte[] data = DATA_TEXT.getBytes(StandardCharsets.UTF_8);
        Files.write(outDir.resolve(DATA_FILE), data);
        Files.write(outDir.resolve("root.cer"), fixtures.root().cert().getEncoded());
        Files.write(outDir.resolve(BES_FILE), buildBes(fixtures, data, true));
        Files.write(outDir.resolve(ATTACHED_BES_FILE), buildBes(fixtures, data, false));
        System.out.println("Записано в " + outDir.toAbsolutePath());
    }

    private static byte[] buildBes(
            CryptoproIntermediateFixtures fixtures, byte[] data, boolean detached) {
        byte[] bes =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .detached(detached)
                        .addSigner(fixtures.signer().key(), fixtures.signer().cert())
                        // промежуточный УЦ передан явно: КриптоПро строит цепочку из сообщения
                        .addCertificate(fixtures.signerCa().cert())
                        .withCAdES()
                        // КриптоПро читает signingTime при усовершенствовании подписи
                        .addSignedAttribute(SIGNING_TIME_OID, signingTime())
                        .build();
        return DerAlgorithmIdentifierNormalizer.normalizeContentInfo(bes);
    }

    /** UTCTime (RFC 5652 §11.3) текущего момента, как кодирует КриптоПро. */
    private static byte[] signingTime() {
        byte[] text = SIGNING_TIME_FORMAT.format(Instant.now()).getBytes(StandardCharsets.US_ASCII);
        return DerCodec.encodeTlv(UTC_TIME_TAG, text);
    }

    private static void serve(CryptoproIntermediateFixtures fixtures) throws Exception {
        try (CryptoproVectorServer server = new CryptoproVectorServer(fixtures)) {
            server.start();
            System.out.println(
                    "Сервер на "
                            + CryptoproIntermediateFixtures.SERVER_BASE_URL
                            + ", Enter - остановить");
            System.in.read();
        }
    }

    private static void usage() {
        System.out.println("Использование: prepare <каталог> | serve <тот же каталог>");
    }
}
