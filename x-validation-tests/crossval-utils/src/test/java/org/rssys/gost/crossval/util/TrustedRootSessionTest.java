package org.rssys.gost.crossval.util;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

@DisplayName("TrustedRootSession: корень в uRoot на время прогона")
class TrustedRootSessionTest {

    private static final byte[] KEY_ID = {0x11};
    // Первый байт DER служит keyid в поддельном хранилище (см. FakeRootStore.install)
    private static final byte[] DER = {0x11, 1, 2, 3};
    private static final byte[] OTHER_DER = {0x11, 9, 9, 9};
    private static final Map<String, String> X_ENV = Map.of("DISPLAY", ":0", "XAUTHORITY", "/x");
    private static final ProcessProbe NOBODY_ALIVE = (pid, started) -> false;
    private static final ProcessProbe EVERYBODY_ALIVE = (pid, started) -> true;

    @TempDir Path temp;

    private FakeRootStore store;
    private Path markPath;
    private TrustedRootSession.Registry registry;

    @BeforeEach
    void setUp() {
        store = new FakeRootStore();
        markPath = temp.resolve(RootMark.FILE_NAME);
        registry = new TrustedRootSession.Registry();
    }

    private TrustedRootSession open(ProcessProbe probe, Map<String, String> env)
            throws IOException {
        return TrustedRootSession.open(DER, KEY_ID, store, markPath, env, probe, registry);
    }

    private TrustedRootSession open() throws IOException {
        return open(NOBODY_ALIVE, X_ENV);
    }

    @Test
    @DisplayName("Корня нет: ставится, метка пишется, на последнем close корень и метка уходят")
    void installsAndRemovesAtLastClose() throws Exception {
        try (TrustedRootSession session = open()) {
            assertEquals(1, store.size(), "корень должен быть установлен");
            RootMark mark = RootMark.read(markPath);
            assertNotNull(mark, "метка должна быть записана");
            assertEquals(RootMark.State.INSTALLED, mark.state());
            assertArrayEquals(DER, mark.der(), "метка хранит установленный DER");
            assertEquals(ProcessHandle.current().pid(), mark.pid());
        }
        assertEquals(0, store.size(), "после close корня быть не должно");
        assertFalse(Files.exists(markPath), "метка должна быть удалена");
    }

    @Test
    @DisplayName("Метка пишется до установки: сбой установки оставляет метку INSTALLING")
    void markIsWrittenBeforeInstall() throws Exception {
        store.derStoredByInstall = OTHER_DER;

        assertThrows(IllegalStateException.class, this::open, "постусловие должно сработать");

        RootMark mark = RootMark.read(markPath);
        assertNotNull(mark, "метка нужна для последующей очистки");
        assertEquals(RootMark.State.INSTALLING, mark.state());
    }

    @Test
    @DisplayName("Постусловие install: в хранилище лёг не наш DER - отказ")
    void installPostconditionFailsOnDifferentDer() {
        store.derStoredByInstall = OTHER_DER;

        assertThrows(
                IllegalStateException.class,
                this::open,
                "после установки должен лежать ровно наш DER");
    }

    @Test
    @DisplayName(
            "Сбой после начала установки: корень убирается, метка снимается, повторный open проходит")
    void failedInstallIsRolledBack() throws Exception {
        store.failAfterInstall = true;

        assertThrows(IOException.class, this::open, "сбой установки должен дойти до вызывающего");

        assertEquals(0, store.size(), "положенный корень должен быть убран откатом");
        assertFalse(Files.exists(markPath), "метка должна быть снята");
        store.failAfterInstall = false;
        try (TrustedRootSession session = open()) {
            assertEquals(1, store.size(), "следующая попытка проходит");
        }
    }

    @Test
    @DisplayName("Свой сбой не блокирует следующий open в той же JVM ложным «идёт другой прогон»")
    void ownFailureDoesNotLookLikeAnotherRun() throws Exception {
        store.derStoredByInstall = OTHER_DER;
        assertThrows(
                IllegalStateException.class, this::open, "постусловие install должно сработать");
        store.derStoredByInstall = null;

        // Проба «все живы»: без особого учёта своей метки процесс из неё выглядел бы чужим живым
        IllegalStateException e =
                assertThrows(IllegalStateException.class, () -> open(EVERYBODY_ALIVE, X_ENV));

        assertFalse(
                e.getMessage().contains("Another run"),
                "метка своей JVM - это собственный сбой, а не чужой прогон: " + e.getMessage());
        assertTrue(e.getMessage().contains("stale mark"), "причина: " + e.getMessage());
    }

    @Test
    @DisplayName("Два корня в одной JVM: метки раздельные, закрытие одного не трогает другой")
    void twoRootsInOneJvmHaveSeparateMarks() throws Exception {
        byte[] keyA = {0x11};
        byte[] derA = {0x11, 1, 2, 3};
        byte[] keyB = {0x22};
        byte[] derB = {0x22, 4, 5, 6};
        Path markA = RootMark.pathFor(temp, keyA);
        Path markB = RootMark.pathFor(temp, keyB);

        TrustedRootSession a =
                TrustedRootSession.open(derA, keyA, store, markA, X_ENV, EVERYBODY_ALIVE, registry);
        // Метка A принадлежит этой же JVM; открытие B не должно принять её за собственный сбой
        TrustedRootSession b =
                TrustedRootSession.open(derB, keyB, store, markB, X_ENV, EVERYBODY_ALIVE, registry);

        assertEquals(2, store.size(), "оба корня установлены, A не удалён при открытии B");
        assertTrue(Files.exists(markA) && Files.exists(markB), "у каждого корня своя метка");

        b.close();
        assertEquals(1, store.size(), "закрытие B убирает только B");
        assertTrue(Files.exists(markA), "метка A сохраняется, пока A открыт");
        assertFalse(Files.exists(markB));
        a.close();
        assertEquals(0, store.size());
    }

    @Test
    @DisplayName("Метки пользователя перечисляются по всем корням")
    void listsMarksOfAllRoots() throws Exception {
        RootMark.ofCurrentProcess(RootMark.State.INSTALLED, new byte[] {1}, DER)
                .write(RootMark.pathFor(temp, new byte[] {1}));
        RootMark.ofCurrentProcess(RootMark.State.INSTALLED, new byte[] {2}, DER)
                .write(RootMark.pathFor(temp, new byte[] {2}));
        Files.writeString(temp.resolve(RootMark.FILE_NAME + ".someone-else.01"), "x");

        assertEquals(2, RootMark.listMarks(temp).size(), "только метки текущего пользователя");
    }

    private void putMarkedRoot(byte keyByte, long pid) throws Exception {
        byte[] keyId = {keyByte};
        byte[] der = {keyByte, 1};
        store.put(keyId, der);
        new RootMark(
                        RootMark.State.INSTALLED,
                        keyId,
                        der,
                        pid,
                        null,
                        System.getProperty("user.name", ""),
                        Instant.now())
                .write(RootMark.pathFor(temp, keyId));
    }

    @Test
    @DisplayName(
            "cleanupMarks убирает корни мёртвых процессов и не трогает живые без явного разрешения")
    void cleanupMarksRemovesStaleAndNeverTouchesLiveByDefault() throws Exception {
        long livePid = ProcessHandle.current().pid() + 1;
        putMarkedRoot((byte) 0x11, 4_000_001L);
        putMarkedRoot((byte) 0x22, livePid);
        ProcessProbe onlyLiveAlive = (pid, started) -> pid == livePid;

        var report = TrustedRootSession.cleanupMarks(store, temp, onlyLiveAlive, false, X_ENV);

        assertEquals(2, report.size());
        assertEquals(1, report.stream().filter(r -> r.cleared()).count(), "убран только мёртвый");
        assertEquals(1, store.size(), "корень живого прогона остался");
        assertTrue(Files.exists(RootMark.pathFor(temp, new byte[] {0x22})));
    }

    @Test
    @DisplayName("cleanupMarks с includeLive убирает и корень живого процесса")
    void cleanupMarksCanRemoveLiveWhenExplicitlyAsked() throws Exception {
        long livePid = ProcessHandle.current().pid() + 1;
        putMarkedRoot((byte) 0x22, livePid);

        var report =
                TrustedRootSession.cleanupMarks(store, temp, (pid, started) -> true, true, X_ENV);

        assertTrue(report.get(0).cleared(), "явное разрешение снимает и живую метку");
        assertEquals(0, store.size());
    }

    @Test
    @DisplayName("cleanupMarks без X-сессии не убирает корень и сообщает о неудаче")
    void cleanupMarksWithoutXReportsFailure() throws Exception {
        putMarkedRoot((byte) 0x11, 4_000_001L);

        var report = TrustedRootSession.cleanupMarks(store, temp, NOBODY_ALIVE, false, Map.of());

        assertFalse(report.get(0).cleared(), "без X корень убрать нельзя, это не успех");
        assertTrue(report.get(0).message().contains("X session"), report.get(0).message());
        assertEquals(1, store.size());
        assertFalse(store.mutated(), "ничего не удалено");
    }

    @Test
    @DisplayName("cleanupMarks: метка без корня в хранилище снимается и X не требуется")
    void cleanupMarksWithoutRootDoesNotNeedX() throws Exception {
        byte[] keyId = {0x33};
        new RootMark(
                        RootMark.State.INSTALLED,
                        keyId,
                        new byte[] {0x33, 1},
                        4_000_002L,
                        null,
                        System.getProperty("user.name", ""),
                        Instant.now())
                .write(RootMark.pathFor(temp, keyId));

        var report = TrustedRootSession.cleanupMarks(store, temp, NOBODY_ALIVE, false, Map.of());

        assertTrue(report.get(0).cleared(), "корня нет, снять нужно только метку");
        assertFalse(Files.exists(RootMark.pathFor(temp, keyId)));
    }

    @Test
    @DisplayName("Счётчик ссылок: корень ставится один раз, удаляется после последнего close")
    void referenceCounting() throws Exception {
        TrustedRootSession first = open();
        TrustedRootSession second = open();
        assertEquals(1, store.calls.stream().filter("install"::equals).count(), "одна установка");

        first.close();
        assertEquals(1, store.size(), "пока есть вторая сессия, корень стоит");
        second.close();
        assertEquals(0, store.size(), "после последней корень удалён");
    }

    @Test
    @DisplayName("close() идемпотентен: повторный вызов не уменьшает счётчик второй раз")
    void closeIsIdempotent() throws Exception {
        TrustedRootSession first = open();
        TrustedRootSession second = open();

        first.close();
        first.close();
        first.close();

        assertEquals(1, store.size(), "лишние close не должны снять чужую ссылку");
        second.close();
        assertEquals(0, store.size());
    }

    @Test
    @DisplayName("Корень с нашим DER уже стоит, метки нет: не ставим и не удаляем")
    void existingOwnRootIsLeftAlone() throws Exception {
        store.put(KEY_ID, DER);

        try (TrustedRootSession session = open()) {
            assertFalse(store.mutated(), "ничего не должно меняться");
        }

        assertEquals(1, store.size(), "корень, поставленный не нами, остаётся");
        assertFalse(store.mutated());
    }

    @Test
    @DisplayName("Тот же keyid, другой DER: отказ, хранилище не меняется")
    void foreignDerWithSameKeyIdIsRejected() {
        store.put(KEY_ID, OTHER_DER);

        IllegalStateException e = assertThrows(IllegalStateException.class, this::open);

        assertTrue(e.getMessage().contains("different DER"), "причина: " + e.getMessage());
        assertFalse(store.mutated(), "чужой корень нельзя удалять автоматически");
    }

    @Test
    @DisplayName("Несколько сертификатов с keyid: отказ с подсказкой, даже если один совпал")
    void multipleCertificatesAreRejected() {
        store.put(KEY_ID, DER);
        store.put(KEY_ID, OTHER_DER);

        IllegalStateException e = assertThrows(IllegalStateException.class, this::open);

        assertTrue(
                e.getMessage().contains("thumbprint"),
                "подсказка про отпечаток: " + e.getMessage());
        assertFalse(store.mutated(), "автоматически ничего не удаляется");
    }

    @Test
    @DisplayName("Без DISPLAY или XAUTHORITY отказ до обращения к хранилищу")
    void noXSessionFailsBeforeAnyStoreCall() {
        for (Map<String, String> env :
                new Map[] {Map.of(), Map.of("DISPLAY", ":0"), Map.of("XAUTHORITY", "/x")}) {
            IllegalStateException e =
                    assertThrows(IllegalStateException.class, () -> open(NOBODY_ALIVE, env));
            assertTrue(e.getMessage().contains("X session"), "сообщение: " + e.getMessage());
        }
        assertTrue(store.calls.isEmpty(), "certmgr не должен вызываться без X-сессии");
    }

    @Test
    @DisplayName("Метка живого процесса: другой прогон, отказ без изменений")
    void markOfLiveProcessIsRejected() throws Exception {
        long anotherPid = ProcessHandle.current().pid() + 1;
        new RootMark(
                        RootMark.State.INSTALLED,
                        KEY_ID,
                        DER,
                        anotherPid,
                        null,
                        System.getProperty("user.name", ""),
                        Instant.now())
                .write(markPath);

        IllegalStateException e =
                assertThrows(IllegalStateException.class, () -> open(EVERYBODY_ALIVE, X_ENV));

        assertTrue(e.getMessage().contains("Another run"), "причина: " + e.getMessage());
        assertTrue(store.calls.isEmpty(), "чужой прогон не трогаем");
    }

    @Test
    @DisplayName("Метка мёртвого процесса: остаток убирается, затем корень ставится заново")
    void markOfDeadProcessIsRecovered() throws Exception {
        store.put(KEY_ID, DER);
        RootMark.ofCurrentProcess(RootMark.State.INSTALLED, KEY_ID, DER).write(markPath);

        try (TrustedRootSession session = open()) {
            assertEquals(1, store.size(), "корень поставлен заново");
            assertEquals(
                    1,
                    store.calls.stream().filter("delete"::equals).count(),
                    "остаток прошлого прогона удалён");
        }
        assertEquals(0, store.size());
    }

    @Test
    @DisplayName("Метка мёртвого процесса при чужом DER в хранилище: отказ, ничего не удаляется")
    void staleMarkWithForeignCertificateIsRejected() throws Exception {
        store.put(KEY_ID, OTHER_DER);
        RootMark.ofCurrentProcess(RootMark.State.INSTALLED, KEY_ID, DER).write(markPath);

        assertThrows(IllegalStateException.class, this::open);

        assertFalse(store.mutated(), "чужой сертификат не удаляется");
        assertNotNull(RootMark.read(markPath), "метка остаётся для разбора");
    }

    @Test
    @DisplayName("Метка другого пользователя игнорируется")
    void markOfAnotherUserIsIgnored() throws Exception {
        new RootMark(RootMark.State.INSTALLED, KEY_ID, DER, 1, null, "someone-else", Instant.now())
                .write(markPath);

        try (TrustedRootSession session = open(EVERYBODY_ALIVE, X_ENV)) {
            assertEquals(1, store.size(), "прогон идёт как при отсутствии метки");
        }
    }

    @Test
    @DisplayName("close(): в хранилище уже чужой сертификат с тем же keyid - не удаляем")
    void closeDoesNotDeleteForeignCertificate() throws Exception {
        TrustedRootSession session = open();
        // кто-то заменил наш корень на другой с тем же keyid
        store.derStoredByInstall = null;
        FakeRootStore replaced = store;
        replaced.deleteByKeyId(KEY_ID);
        replaced.put(KEY_ID, OTHER_DER);
        replaced.calls.clear();

        assertThrows(IllegalStateException.class, session::close);

        assertFalse(replaced.mutated(), "чужой сертификат нельзя удалять");
        assertNotNull(RootMark.read(markPath), "метка остаётся для разбора");
    }

    @Test
    @DisplayName("keepInstalled(): корень остаётся, метка снимается")
    void keepInstalledLeavesRootAndClearsMark() throws Exception {
        TrustedRootSession session = open();

        session.keepInstalled();
        session.close();

        assertEquals(1, store.size(), "корень поставлен оператором и остаётся");
        assertNull(RootMark.read(markPath), "метки быть не должно");
    }
}
