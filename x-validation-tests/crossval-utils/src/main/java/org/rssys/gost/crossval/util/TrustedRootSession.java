package org.rssys.gost.crossval.util;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Доверенный корень в {@code uRoot} КриптоПро на время прогона тестов.
 *
 * <p>Ключ тестового корня лежит в репозитории, поэтому постоянно он в доверенном хранилище стоять
 * не должен: сессия ставит его при первом {@link #open} и убирает при последнем {@link #close}.
 * Сессия общая: она принимает любой DER, не только корень фикстур {@code cadest}.
 *
 * <p>Политика по {@code keyid} (fail-closed), потому что у старого и нового корня с тем же
 * ключом {@code keyid} один и тот же:
 * <ul>
 *   <li>сертификатов с этим {@code keyid} нет: ставим и проверяем, что в хранилище лёг ровно наш
 *       DER;</li>
 *   <li>один, и его DER равен нашему: корень поставили не мы; не ставим и не удаляем;</li>
 *   <li>один с другим DER или больше одного: отказ, автоматически ничего не удаляется.</li>
 * </ul>
 *
 * <p>Порядок работы с меткой {@link RootMark}: она пишется до установки. Метка живого процесса
 * означает чужой прогон (отказ), метка мёртвого - остаток аварии (корень убирается по тем же
 * правилам). Счётчик ссылок общий для JVM; блокировки только из {@code java.util.concurrent}.
 */
public final class TrustedRootSession implements AutoCloseable {

    private static final System.Logger LOG = System.getLogger(TrustedRootSession.class.getName());
    private static final Registry DEFAULT_REGISTRY = new Registry();

    private final Registry registry;
    private final Shared shared;
    private final AtomicBoolean closed = new AtomicBoolean();

    private TrustedRootSession(Registry registry, Shared shared) {
        this.registry = registry;
        this.shared = shared;
    }

    /**
     * Открывает сессию на реальном КриптоПро с меткой по умолчанию.
     *
     * @param der   DER корня, который ставят
     * @param keyId идентификатор ключа корня
     */
    public static TrustedRootSession open(byte[] der, byte[] keyId) throws IOException {
        return open(
                der,
                keyId,
                new CertmgrStore(),
                RootMark.defaultPath(keyId),
                System.getenv(),
                ProcessProbe.SYSTEM,
                DEFAULT_REGISTRY);
    }

    static TrustedRootSession open(
            byte[] der,
            byte[] keyId,
            RootStore store,
            Path markPath,
            Map<String, String> environment,
            ProcessProbe probe,
            Registry registry)
            throws IOException {
        registry.lock.lock();
        try {
            String key = HexFormat.of().formatHex(keyId);
            Shared existing = registry.sessions.get(key);
            if (existing != null) {
                if (!Arrays.equals(existing.der, der)) {
                    throw new IllegalStateException(
                            "Another certificate is already open for the same keyid");
                }
                existing.references++;
                return new TrustedRootSession(registry, existing);
            }
            XSession.require(environment);
            recoverAfterCrash(store, markPath, probe);
            boolean installedByUs = establish(store, markPath, der, keyId);
            Shared created = new Shared(store, markPath, der.clone(), keyId.clone(), installedByUs);
            created.references = 1;
            registry.sessions.put(key, created);
            return new TrustedRootSession(registry, created);
        } finally {
            registry.lock.unlock();
        }
    }

    /**
     * Оставляет корень установленным после закрытия: метка снимается, и корень считается
     * поставленным вручную. Нужно операторской команде {@code install}.
     */
    public void keepInstalled() throws IOException {
        registry.lock.lock();
        try {
            shared.installedByUs = false;
            RootMark.delete(shared.markPath);
        } finally {
            registry.lock.unlock();
        }
    }

    @Override
    public void close() throws IOException {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        registry.lock.lock();
        try {
            shared.references--;
            if (shared.references > 0) {
                return;
            }
            registry.sessions.remove(HexFormat.of().formatHex(shared.keyId));
            if (shared.installedByUs) {
                removeOurs(shared);
            }
        } finally {
            registry.lock.unlock();
        }
    }

    /** Остаток аварии: метка мёртвого процесса. Живой процесс в метке - чужой прогон. */
    private static void recoverAfterCrash(RootStore store, Path markPath, ProcessProbe probe)
            throws IOException {
        RootMark mark = RootMark.read(markPath);
        if (mark == null || !mark.user().equals(System.getProperty("user.name", ""))) {
            return;
        }
        // Метка этой же JVM - след собственного сбоя установки, а не чужого прогона: иначе после
        // неудачи следующий класс в той же JVM получал бы ложное «идёт другой прогон». Метка
        // своя для каждого корня, а сюда мы попадаем только когда сессии с этим keyid в реестре нет
        // (под блокировкой), поэтому метку открытого корня другого УЦ в этой JVM мы не затронем
        boolean ownFailure =
                mark.pid() == ProcessHandle.current().pid()
                        && ProcessProbe.SYSTEM.isSameLiveProcess(mark.pid(), mark.startedAt());
        if (!ownFailure && probe.isSameLiveProcess(mark.pid(), mark.startedAt())) {
            throw new IllegalStateException(
                    "Another run holds the trusted root (pid "
                            + mark.pid()
                            + ", mark "
                            + markPath
                            + ")");
        }
        LOG.log(
                System.Logger.Level.WARNING,
                "Removing the trusted root left by an earlier failed or dead run (pid {0})",
                mark.pid());
        removeRootOfMark(store, mark);
        RootMark.delete(markPath);
    }

    /**
     * Убирает корень, описанный меткой, по правилам сессии: ровно один сертификат с этим keyid и его
     * DER равен записанному. Иначе отказ с подсказкой, ничего не удаляется.
     */
    private static void removeRootOfMark(RootStore store, RootMark mark) throws IOException {
        int count = store.countByKeyId(mark.keyId());
        if (count == 1 && Arrays.equals(store.exportByKeyId(mark.keyId()), mark.der())) {
            store.deleteByKeyId(mark.keyId());
            requireGone(store, mark.keyId());
        } else if (count != 0) {
            throw new IllegalStateException(
                    "A stale mark exists but uRoot holds "
                            + count
                            + " certificate(s) with its keyid that do not match the mark: "
                            + "run `make cryptopro-root-remove` and check them by hand");
        }
    }

    /**
     * Итог уборки по одной метке.
     *
     * @param message что сделано или почему не сделано (без данных сертификатов)
     * @param cleared {@code true}, если корень убран, а метка снята
     */
    public record MarkCleanup(String message, boolean cleared) {}

    /**
     * Убирает корни по всем меткам пользователя в каталоге: для аварийной очистки и операторской
     * команды {@code remove}. Метку живого процесса не трогает, пока явно не разрешено
     * {@code includeLive}: убрать корень из-под работающего прогона значит сломать его тесты.
     * Доступ к X-сессии требуется, только когда в хранилище есть что удалять.
     *
     * @param includeLive убирать и корни, чья метка принадлежит живому процессу
     * @param environment переменные окружения для проверки доступа к X-серверу
     * @return по одному итогу на метку; не убранные метки имеют {@code cleared == false}
     */
    public static List<MarkCleanup> cleanupMarks(
            RootStore store,
            Path directory,
            ProcessProbe probe,
            boolean includeLive,
            Map<String, String> environment)
            throws IOException {
        List<MarkCleanup> report = new ArrayList<>();
        for (Path markPath : RootMark.listMarks(directory)) {
            RootMark mark = RootMark.read(markPath);
            if (mark == null) {
                continue;
            }
            String label = "mark " + markPath.getFileName();
            if (!includeLive && probe.isSameLiveProcess(mark.pid(), mark.startedAt())) {
                report.add(
                        new MarkCleanup(
                                label + ": a live run holds it (pid " + mark.pid() + "), skipped",
                                false));
                continue;
            }
            try {
                if (store.countByKeyId(mark.keyId()) != 0) {
                    XSession.require(environment);
                }
                removeRootOfMark(store, mark);
                RootMark.delete(markPath);
                report.add(new MarkCleanup(label + ": root removed, mark cleared", true));
            } catch (IllegalStateException | IOException e) {
                report.add(new MarkCleanup(label + ": not removed: " + e.getMessage(), false));
            }
        }
        return report;
    }

    /** @return {@code true}, если корень поставили мы и обязаны убрать */
    private static boolean establish(RootStore store, Path markPath, byte[] der, byte[] keyId)
            throws IOException {
        int count = store.countByKeyId(keyId);
        if (count == 0) {
            // Метка до установки: падение между установкой и записью не оставит корень без следа
            RootMark.ofCurrentProcess(RootMark.State.INSTALLING, keyId, der).write(markPath);
            try {
                store.install(der);
                requireExactly(store, keyId, der, "after the install");
                RootMark.ofCurrentProcess(RootMark.State.INSTALLED, keyId, der).write(markPath);
            } catch (IOException | RuntimeException failure) {
                rollbackFailedInstall(store, markPath, keyId, der, failure);
                throw failure;
            }
            return true;
        }
        if (count == 1) {
            if (Arrays.equals(store.exportByKeyId(keyId), der)) {
                LOG.log(
                        System.Logger.Level.WARNING,
                        "The root is already in uRoot (installed by hand): it stays after the run");
                return false;
            }
            throw new IllegalStateException(
                    "uRoot holds a root with the same keyid but a different DER (outdated or"
                            + " foreign): remove it with `make cryptopro-root-remove` or"
                            + " `certmgr -delete -store uRoot -thumbprint <SHA1>`");
        }
        throw new IllegalStateException(
                "uRoot holds "
                        + count
                        + " certificates with this keyid, refusing to guess which one to use."
                        + " Remove the extra ones by thumbprint:\n"
                        + store.describeByKeyId(keyId));
    }

    /**
     * Сбой после начала установки: сразу убираем корень по тем же правилам (ровно один и наш DER) и
     * снимаем метку. Если в хранилище что-то другое, ничего не трогаем и оставляем метку для разбора.
     * Ошибки отката не скрывают исходную причину и добавляются к ней.
     */
    private static void rollbackFailedInstall(
            RootStore store, Path markPath, byte[] keyId, byte[] der, Exception failure) {
        try {
            int count = store.countByKeyId(keyId);
            if (count == 0) {
                RootMark.delete(markPath);
            } else if (count == 1 && Arrays.equals(store.exportByKeyId(keyId), der)) {
                store.deleteByKeyId(keyId);
                requireGone(store, keyId);
                RootMark.delete(markPath);
            }
        } catch (IOException | RuntimeException rollbackFailure) {
            failure.addSuppressed(rollbackFailure);
        }
    }

    private static void removeOurs(Shared shared) throws IOException {
        RootStore store = shared.store;
        int count = store.countByKeyId(shared.keyId);
        if (count == 0) {
            LOG.log(System.Logger.Level.WARNING, "The root has already been removed from uRoot");
        } else if (count == 1 && Arrays.equals(store.exportByKeyId(shared.keyId), shared.der)) {
            store.deleteByKeyId(shared.keyId);
            requireGone(store, shared.keyId);
        } else {
            // Не наш сертификат под тем же keyid: не трогаем, метку оставляем для разбора
            throw new IllegalStateException(
                    "uRoot no longer holds exactly our root under this keyid, nothing was removed:"
                            + " check it by hand");
        }
        RootMark.delete(shared.markPath);
    }

    private static void requireExactly(RootStore store, byte[] keyId, byte[] der, String when)
            throws IOException {
        int count = store.countByKeyId(keyId);
        if (count != 1 || !Arrays.equals(store.exportByKeyId(keyId), der)) {
            throw new IllegalStateException(
                    "uRoot does not hold exactly the expected root "
                            + when
                            + " (found "
                            + count
                            + ")");
        }
    }

    private static void requireGone(RootStore store, byte[] keyId) throws IOException {
        if (store.countByKeyId(keyId) != 0) {
            throw new IllegalStateException("The root is still in uRoot after the delete");
        }
    }

    /** Общее состояние одного корня в пределах JVM. */
    private static final class Shared {
        final RootStore store;
        final Path markPath;
        final byte[] der;
        final byte[] keyId;
        boolean installedByUs;
        int references;

        Shared(RootStore store, Path markPath, byte[] der, byte[] keyId, boolean installedByUs) {
            this.store = store;
            this.markPath = markPath;
            this.der = der;
            this.keyId = keyId;
            this.installedByUs = installedByUs;
        }
    }

    /** Реестр открытых сессий; отдельный экземпляр для проверки без глобального состояния. */
    static final class Registry {
        final ReentrantLock lock = new ReentrantLock();
        final Map<String, Shared> sessions = new HashMap<>();
    }
}
