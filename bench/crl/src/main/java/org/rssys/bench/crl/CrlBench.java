package org.rssys.bench.crl;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import org.rssys.gost.pkix.cert.CrlLimits;

/**
 * Замер стоимости проверки большого CRL: точка входа и общие помощники.
 *
 * <p>Каждая ячейка сетки выполняется в отдельной JVM, чтобы кучу определял сценарий, а не
 * окружение, и итерации не влияли друг на друга. Ячейка печатает последней строкой
 * {@code RESULT key=value ...}; ведущий процесс ({@code grid}) читает только её.</p>
 */
public final class CrlBench {

    /** Начало строки результата ячейки. */
    static final String RESULT_PREFIX = "RESULT ";

    /** Предел размера CRL в замере: поднят явно, чтобы 2 и 4 млн записей не упёрлись в 64 МиБ. */
    static final int MAX_CRL_SIZE = 1 << 30;

    /** Предел числа записей в замере: поднят явно по той же причине. */
    static final int MAX_REVOKED_ENTRIES = 10_000_000;

    /** Пределы замера: заведомо выше значений по умолчанию, чтобы они не влияли на результат. */
    static final CrlLimits LIMITS = new CrlLimits(MAX_CRL_SIZE, MAX_REVOKED_ENTRIES);

    static final String CRL_SUFFIX = ".crl";
    static final String CA_SUFFIX = ".ca.der";
    static final String LEAF_SUFFIX = ".leaf.der";

    private CrlBench() {}

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            usage();
            return;
        }
        String[] rest = Arrays.copyOfRange(args, 1, args.length);
        switch (args[0]) {
            case "gen" -> DataGen.main(rest);
            case "control" -> Control.main(rest);
            case "cell-a" -> CellA.main(rest);
            case "cell-b" -> CellB.main(rest);
            case "cell-c" -> CellC.main(rest);
            case "serve" -> Server.main(rest);
            case "stages" -> Stages.main(rest);
            case "grid" -> Grid.main(rest);
            default -> usage();
        }
    }

    private static void usage() {
        System.err.println(
                """
                Использование: CrlBench <режим> ...
                  gen <каталог> <имя> <записей>
                  control <каталог> <fns.crl> <fns.crt>
                  cell-a <каталог> <имя> <потоков> <раундов>
                  cell-b <каталог> <имя> <потоков> <порт>
                  cell-c <каталог> <имя> <потоков> <раундов>
                  serve <файл> <порт>
                  stages <каталог> <имя>
                  grid <каталог> <jar> <java21> <java25>""");
    }

    /** Печатает строку результата ячейки. */
    static void result(String... keyValues) {
        StringBuilder sb = new StringBuilder(RESULT_PREFIX);
        for (int i = 0; i < keyValues.length; i += 2) {
            if (i > 0) sb.append(' ');
            sb.append(keyValues[i]).append('=').append(keyValues[i + 1]);
        }
        System.out.println(sb);
        System.out.flush();
    }

    static byte[] read(Path dir, String name, String suffix) throws IOException {
        return Files.readAllBytes(dir.resolve("crl-" + name + suffix));
    }

    static double ms(long nanos) {
        return nanos / 1_000_000.0;
    }

    static double mb(long bytes) {
        return bytes / (1024.0 * 1024.0);
    }

    static String f1(double v) {
        return String.format(java.util.Locale.ROOT, "%.1f", v);
    }

    static long median(long[] values) {
        long[] sorted = values.clone();
        Arrays.sort(sorted);
        return sorted[sorted.length / 2];
    }
}
