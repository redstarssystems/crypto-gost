package org.rssys.bench.crl;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
import org.rssys.gost.pkix.cert.CrlBenchAccess;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCrl;
import org.rssys.gost.signature.PublicKeyParameters;

/**
 * Контроль синтетики на настоящем CRL.
 *
 * <p>Настоящий CRL и синтетика с тем же числом записей разбираются одинаково:
 * {@code verifySignatureAndParse(caKey, allowDelta=false)} (подпись, строгий разбор записей, без
 * проверки срока: срок настоящего CRL истекает, и контроль перестал бы воспроизводиться). Пороги
 * заданы заранее: байты на запись в пределах ±10%, время в пределах ±30%. Выход за них означает,
 * что остальной сетке доверять нельзя, пока причина не найдена.</p>
 */
final class Control {

    private static final double BYTES_TOLERANCE = 0.10;
    private static final double TIME_TOLERANCE = 0.30;
    private static final int WARMUP = 2;
    private static final int RUNS = 5;

    private Control() {}

    static void main(String[] args) throws Exception {
        Path fnsCrl = Path.of(args[1]);
        Path fnsCrt = Path.of(args[2]);
        byte[] fnsDer = Files.readAllBytes(fnsCrl);
        PublicKeyParameters fnsKey =
                GostCertificate.fromDer(Files.readAllBytes(fnsCrt)).getPublicKey();

        GostCrl fns =
                CrlBenchAccess.verifyAndParse(
                        fnsDer, fnsKey, CrlBench.LIMITS);
        int entries = fns.getRevokedCertificates().size();
        System.out.printf(
                Locale.ROOT,
                "CRL ФНС: файл=%s, размер=%d байт, записей=%d, thisUpdate=%s, nextUpdate=%s%n",
                fnsCrl.getFileName(),
                fnsDer.length,
                entries,
                fns.getThisUpdate(),
                fns.getNextUpdate());
        long fnsNanos = medianParse(fnsDer, fnsKey);

        DataGen.Built synthetic = DataGen.build(entries);
        long synNanos = medianParse(synthetic.crl(), synthetic.caKey());

        double fnsBytes = (double) fnsDer.length / entries;
        double synBytes = (double) synthetic.crl().length / entries;
        double bytesDiff = synBytes / fnsBytes - 1;
        double timeDiff = (double) synNanos / fnsNanos - 1;
        boolean bytesOk = Math.abs(bytesDiff) <= BYTES_TOLERANCE;
        boolean timeOk = Math.abs(timeDiff) <= TIME_TOLERANCE;
        System.out.printf(
                Locale.ROOT,
                "ФНС:       %s байт на запись, подпись+хэш+разбор %s мс%n",
                CrlBench.f1(fnsBytes),
                CrlBench.f1(CrlBench.ms(fnsNanos)));
        System.out.printf(
                Locale.ROOT,
                "Синтетика: %s байт на запись, подпись+хэш+разбор %s мс%n",
                CrlBench.f1(synBytes),
                CrlBench.f1(CrlBench.ms(synNanos)));
        System.out.printf(
                Locale.ROOT,
                "Расхождение: байты %+.1f%% (порог ±10%%): %s; время %+.1f%% (порог ±30%%): %s%n",
                bytesDiff * 100,
                bytesOk ? "норма" : "ВЫХОД ЗА ПОРОГ",
                timeDiff * 100,
                timeOk ? "норма" : "ВЫХОД ЗА ПОРОГ");
        System.out.println(
                bytesOk && timeOk
                        ? "КОНТРОЛЬ ПРОЙДЕН"
                        : "КОНТРОЛЬ НЕ ПРОЙДЕН: сетке не доверять, пока причина не найдена");
    }

    private static long medianParse(byte[] der, PublicKeyParameters key) throws Exception {
        for (int i = 0; i < WARMUP; i++) {
            CrlBenchAccess.verifyAndParse(
                    der, key, CrlBench.LIMITS);
        }
        long[] runs = new long[RUNS];
        for (int i = 0; i < RUNS; i++) {
            long t0 = System.nanoTime();
            CrlBenchAccess.verifyAndParse(
                    der, key, CrlBench.LIMITS);
            runs[i] = System.nanoTime() - t0;
        }
        return CrlBench.median(runs);
    }
}
