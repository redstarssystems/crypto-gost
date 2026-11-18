package org.rssys.bench.crl;

import java.nio.file.Path;
import org.rssys.gost.api.Digest;
import org.rssys.gost.pkix.cert.CrlBenchAccess;
import org.rssys.gost.pkix.cert.CrlVerifier;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCrl;
import org.rssys.gost.signature.PublicKeyParameters;

/**
 * Разбивка одного вызова {@code verify} на хэш, подпись и разбор, плюс удерживаемая память.
 *
 * <p>Хэш считается Стрибогом над всем файлом (подписывается только {@code tbsCertList}, разница
 * в сотню байт). Подпись берётся как постоянная из CRL без записей. Разбор - остаток. Один поток,
 * прогретый вызов. Удерживаемая память: сколько кучи занимает {@code GostCrl}, пока на него есть
 * ссылка, после {@code System.gc()}; в {@code checkCrl} после проверки остаётся только DER, так
 * что это нужно лишь для оценки кэша разбора.</p>
 */
final class Stages {

    private static final int WARMUP = 2;
    private static final int RUNS = 5;
    private static final int GC_REPEATS = 3;

    private Stages() {}

    static void main(String[] args) throws Exception {
        Path dir = Path.of(args[0]);
        String name = args[1];
        try {
            run(dir, name);
        } catch (OutOfMemoryError e) {
            CrlBench.result("outcome", "OOM");
        } catch (Throwable e) {
            CrlBench.result(
                    "outcome", "ERROR", "detail", e.getClass().getSimpleName() + ":" + e.getMessage());
        }
    }

    private static void run(Path dir, String name) throws Exception {
        long totalNanos = verifyMedian(dir, name);
        long signatureNanos = verifyMedian(dir, "empty");
        byte[] crlDer = CrlBench.read(dir, name, CrlBench.CRL_SUFFIX);
        for (int i = 0; i < WARMUP; i++) {
            Digest.digest256(crlDer);
        }
        long[] hashRuns = new long[RUNS];
        for (int i = 0; i < RUNS; i++) {
            long t0 = System.nanoTime();
            Digest.digest256(crlDer);
            hashRuns[i] = System.nanoTime() - t0;
        }
        long hashNanos = CrlBench.median(hashRuns);
        long parseNanos = Math.max(0, totalNanos - hashNanos - signatureNanos);

        GostCertificate ca = GostCertificate.fromDer(CrlBench.read(dir, name, CrlBench.CA_SUFFIX));
        long retained = retainedBytes(crlDer, ca.getPublicKey());
        CrlBench.result(
                "outcome", "OK",
                "crlMb", CrlBench.f1(CrlBench.mb(crlDer.length)),
                "totalMs", CrlBench.f1(CrlBench.ms(totalNanos)),
                "hashMs", CrlBench.f1(CrlBench.ms(hashNanos)),
                "signatureMs", CrlBench.f1(CrlBench.ms(signatureNanos)),
                "parseMs", CrlBench.f1(CrlBench.ms(parseNanos)),
                "retainedGostCrlMb", CrlBench.f1(CrlBench.mb(retained)));
    }

    private static long verifyMedian(Path dir, String name) throws Exception {
        byte[] crlDer = CrlBench.read(dir, name, CrlBench.CRL_SUFFIX);
        GostCertificate ca =
                GostCertificate.fromDer(CrlBench.read(dir, name, CrlBench.CA_SUFFIX));
        GostCertificate leaf =
                GostCertificate.fromDer(CrlBench.read(dir, name, CrlBench.LEAF_SUFFIX));
        for (int i = 0; i < WARMUP; i++) {
            verifyOnce(crlDer, leaf, ca);
        }
        long[] runs = new long[RUNS];
        for (int i = 0; i < RUNS; i++) {
            long t0 = System.nanoTime();
            verifyOnce(crlDer, leaf, ca);
            runs[i] = System.nanoTime() - t0;
        }
        return CrlBench.median(runs);
    }

    private static void verifyOnce(byte[] crlDer, GostCertificate leaf, GostCertificate ca)
            throws Exception {
        CrlVerifier.verify(crlDer, leaf, ca, null, CrlBench.LIMITS);
    }

    /** Разница занятой кучи после сборки мусора до и после разбора с удержанием {@code GostCrl}. */
    private static long retainedBytes(byte[] crlDer, PublicKeyParameters caKey) throws Exception {
        long before = usedAfterGc();
        GostCrl held =
                CrlBenchAccess.verifyAndParse(
                        crlDer, caKey, CrlBench.LIMITS);
        long after = usedAfterGc();
        // Ссылка нужна живой до замера: без неё сборщик освободил бы объект раньше
        if (held.getCrlNumber() == null) {
            throw new IllegalStateException("cRLNumber expected");
        }
        return after - before;
    }

    private static long usedAfterGc() {
        for (int i = 0; i < GC_REPEATS; i++) {
            System.gc();
        }
        Runtime rt = Runtime.getRuntime();
        return rt.totalMemory() - rt.freeMemory();
    }
}
