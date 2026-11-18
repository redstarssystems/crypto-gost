package org.rssys.gost.crossval.cadest;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import org.rssys.gost.crossval.util.CertmgrStore;
import org.rssys.gost.crossval.util.CryptoProChecker;
import org.rssys.gost.crossval.util.ProcessProbe;
import org.rssys.gost.crossval.util.RootMark;
import org.rssys.gost.crossval.util.RootStore;
import org.rssys.gost.crossval.util.TrustedRootSession;
import org.rssys.gost.crossval.util.XSession;
import org.rssys.gost.pkix.cert.GostCertificate;

/**
 * Операторская команда для тестового корня в {@code uRoot} КриптоПро: {@code install},
 * {@code remove}, {@code status}. Нужна для аварийной очистки (прогон убит, метка осталась) и для
 * ручных сценариев, которым корень нужен вне тестов (например, генерация вектора).
 *
 * <p>Запуск: {@code make cryptopro-root-remove} собирает модуль и вызывает {@code remove}.
 *
 * <ul>
 *   <li>{@code status} - показывает метку и состояние корня, ничего не меняет;</li>
 *   <li>{@code install} - ставит корень и оставляет его; требует {@code --yes} или
 *       {@code -Dcrossval.cryptopro.trustRoot=true};</li>
 *   <li>{@code remove} - удаляет корень с нашим DER, в том числе без метки, и снимает метку.
 *       При нескольких сертификатах с этим {@code keyid} ничего не удаляет и печатает подсказку;
 *       удаляет все только с {@code --force}. Чужой DER под тем же {@code keyid} не трогает.
 *       Корень живого прогона не трогает никогда; снять его можно только явным
 *       {@code --force-live}. Код выхода ненулевой, если хоть одна метка не убрана.</li>
 * </ul>
 */
public final class CryptoproRootTool {

    private CryptoproRootTool() {}

    /**
     * @param args {@code install --yes}, {@code remove [--force]} или {@code status}
     */
    public static void main(String[] args) {
        System.exit(execute(args));
    }

    /** Выполняет команду и возвращает код выхода; отдельно от {@link #main}, чтобы проверять в тестах. */
    static int execute(String[] args) {
        try {
            return run(args);
        } catch (IOException | RuntimeException e) {
            System.err.println("Error: " + e.getMessage());
            return 1;
        }
    }

    private static int run(String[] args) throws IOException {
        if (args.length == 0) {
            usage();
            return 2;
        }
        GostCertificate root = CryptoproFixtureGenerator.buildCa().cert();
        byte[] der = root.getEncoded();
        byte[] keyId = root.getSubjectKeyIdentifier();
        Path markPath = RootMark.defaultPath(keyId);
        return switch (args[0]) {
            case "status" -> status(new CertmgrStore(), markPath, der, keyId);
            case "install" -> install(args, der, keyId);
            case "remove" -> remove(args, new CertmgrStore(), markPath, der, keyId);
            default -> {
                usage();
                yield 2;
            }
        };
    }

    private static void usage() {
        System.err.println(
                "usage: CryptoproRootTool install --yes | remove [--force] [--force-live] | status");
    }

    private static int status(RootStore store, Path markPath, byte[] der, byte[] keyId)
            throws IOException {
        System.out.println("mark of the fixture root: " + markPath);
        List<Path> marks = RootMark.listMarks(RootMark.defaultDirectory());
        if (marks.isEmpty()) {
            System.out.println("marks of this user: none");
        }
        for (Path markFile : marks) {
            RootMark mark = RootMark.read(markFile);
            if (mark == null) {
                continue;
            }
            boolean alive = ProcessProbe.SYSTEM.isSameLiveProcess(mark.pid(), mark.startedAt());
            System.out.println(
                    "mark "
                            + markFile.getFileName()
                            + ": "
                            + mark.state()
                            + ", pid "
                            + mark.pid()
                            + (alive ? " (alive)" : " (dead)"));
        }
        int count = store.countByKeyId(keyId);
        System.out.println("certificates with the root keyid in uRoot: " + count);
        if (count == 1) {
            boolean ours = Arrays.equals(store.exportByKeyId(keyId), der);
            System.out.println(ours ? "the certificate is our root" : "the DER differs from ours");
        }
        return 0;
    }

    private static int install(String[] args, byte[] der, byte[] keyId) throws IOException {
        // Подтверждение окном не блокирует, поэтому единственный барьер - явное согласие оператора
        if (!Arrays.asList(args).contains("--yes") && !CryptoProChecker.trustRootEnabled()) {
            System.err.println(
                    "Refusing to put a test root with a published key into the trusted store"
                            + " without --yes or -D"
                            + CryptoProChecker.TRUST_ROOT_PROPERTY
                            + "=true");
            return 2;
        }
        try (TrustedRootSession session = TrustedRootSession.open(der, keyId)) {
            session.keepInstalled();
        }
        System.out.println("The root is installed. Remove it with: make cryptopro-root-remove");
        return 0;
    }

    private static int remove(
            String[] args, RootStore store, Path markPath, byte[] der, byte[] keyId)
            throws IOException {
        // --force относится только к нескольким сертификатам с одним keyid; корень живого прогона
        // снимается отдельным явным --force-live, иначе аварийная команда ломала бы идущий прогон
        boolean force = Arrays.asList(args).contains("--force");
        boolean forceLive = Arrays.asList(args).contains("--force-live");
        RootMark mark = RootMark.read(markPath);
        if (mark != null
                && ProcessProbe.SYSTEM.isSameLiveProcess(mark.pid(), mark.startedAt())
                && !forceLive) {
            System.err.println(
                    "A live run holds the root (pid "
                            + mark.pid()
                            + "); use --force-live to remove it under the running tests");
            return 2;
        }
        int count = store.countByKeyId(keyId);
        if (count != 0) {
            // Доступ к X нужен только для самого удаления: на машине без графики и без корня
            // команда должна сообщить «нечего удалять», а не падать
            XSession.require(System.getenv());
        }
        if (count == 0) {
            System.out.println("The root is not in uRoot, nothing to remove.");
        } else if (count == 1) {
            if (!Arrays.equals(store.exportByKeyId(keyId), der)) {
                System.err.println(
                        "uRoot holds a certificate with this keyid but a different DER; not touching"
                                + " it. Remove it by hand with certmgr -delete -store uRoot"
                                + " -thumbprint <SHA1>");
                return 2;
            }
            store.deleteByKeyId(keyId);
            System.out.println("The root is removed from uRoot.");
        } else if (force) {
            store.deleteByKeyId(keyId);
            System.out.println(
                    "All " + count + " certificates with this keyid are removed (--force).");
        } else {
            System.err.println(
                    count
                            + " certificates share this keyid; not guessing. Remove the extra ones"
                            + " with certmgr -delete -store uRoot -thumbprint <SHA1>, or run with"
                            + " --force to remove all of them:\n"
                            + store.describeByKeyId(keyId));
            return 2;
        }
        if (count != 0 && store.countByKeyId(keyId) != 0) {
            System.err.println("The root is still in uRoot after the delete");
            return 1;
        }
        RootMark.delete(markPath);
        // Корни других УЦ (например, одноразового УЦ пробы) убираем по их меткам по тем же правилам
        boolean complete = true;
        for (TrustedRootSession.MarkCleanup result :
                TrustedRootSession.cleanupMarks(
                        store,
                        RootMark.defaultDirectory(),
                        ProcessProbe.SYSTEM,
                        forceLive,
                        System.getenv())) {
            System.out.println(result.message());
            complete &= result.cleared();
        }
        if (!complete) {
            System.err.println("Cleanup is incomplete: some marks were not cleared");
            return 1;
        }
        return 0;
    }
}
