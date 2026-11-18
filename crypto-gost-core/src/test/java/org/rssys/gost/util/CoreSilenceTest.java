package org.rssys.gost.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Контракт «core молчит»: примитивы не пишут в журнал и в стандартные потоки, об ошибках они
 * сообщают только исключениями. Проверяется байткод всех классов модуля, а не выполненные пути:
 * запись на редком пути не прошла бы незамеченной.
 *
 * <p>Ищутся константы пула, а не текст исходников: {@code java/lang/System} встречается и в
 * {@code System.arraycopy}, поэтому вывод в консоль определяется по дескриптору
 * {@code Ljava/io/PrintStream;}. Если в core появится законная работа с {@code PrintStream},
 * исключение добавляется осознанно и с обоснованием в этом классе, а не обходом проверки.
 */
@DisplayName("Контракт core: журнал и стандартные потоки не используются")
class CoreSilenceTest {

    private static final String JUL = "java/util/logging";
    private static final String SYSTEM_LOGGER = "java/lang/System$Logger";
    private static final String PRINT_STREAM = "Ljava/io/PrintStream;";
    private static final String PRINT_STACK_TRACE = "printStackTrace";
    private static final String GOST_LOGGER = "org/rssys/gost/util/GostLogger";

    /** Запрещённые константы пула во всех классах core, кроме самой обёртки журнала. */
    private static final List<String> FORBIDDEN =
            List.of(JUL, SYSTEM_LOGGER, PRINT_STREAM, PRINT_STACK_TRACE, GOST_LOGGER);

    /** Обёртка журнала и её вложенные типы (в их пуле есть имя внешнего класса). */
    private static final String LOGGER_CLASS = "org/rssys/gost/util/GostLogger.class";

    private static final String LOGGER_NESTED_PREFIX = "org/rssys/gost/util/GostLogger$";

    @Test
    @DisplayName("Ни один класс core, кроме GostLogger, не ссылается на журнал и консоль")
    void coreClassesAreSilent() throws IOException, URISyntaxException {
        List<String> violations = new ArrayList<>();
        int scanned = 0;
        Path root =
                Path.of(
                        CryptoRandom.class
                                .getProtectionDomain()
                                .getCodeSource()
                                .getLocation()
                                .toURI());
        try (FileSystem jar = Files.isDirectory(root) ? null : FileSystems.newFileSystem(root)) {
            Path classesRoot = jar == null ? root : jar.getPath("/");
            try (Stream<Path> files = Files.walk(classesRoot)) {
                for (Path file :
                        (Iterable<Path>)
                                files.filter(f -> f.toString().endsWith(".class"))::iterator) {
                    String name = classesRoot.relativize(file).toString().replace('\\', '/');
                    if (isLoggerClass(name)) {
                        continue;
                    }
                    scanned++;
                    for (String hit : findForbidden(Files.readAllBytes(file))) {
                        violations.add(name + " -> " + hit);
                    }
                }
            }
        }
        assertTrue(scanned > 100, "проверено подозрительно мало классов core: " + scanned);
        assertEquals(
                List.of(),
                violations,
                "core не должен обращаться к журналу и консоли, нарушения: " + violations);
    }

    @Test
    @DisplayName("Исключение для обёртки журнала действует и на её вложенные типы")
    void loggerExemptionCoversNestedTypes() {
        assertTrue(isLoggerClass("org/rssys/gost/util/GostLogger.class"), "сама обёртка");
        assertTrue(isLoggerClass("org/rssys/gost/util/GostLogger$Level.class"), "Level");
        assertFalse(isLoggerClass("org/rssys/gost/util/SafeText.class"), "посторонний класс");
        assertFalse(isLoggerClass("org/rssys/gost/util/GostLoggerFake.class"), "похожее имя");
    }

    @Test
    @DisplayName(
            "Проверка находит каждое из запрещённых обращений (иначе страж ничего не стережёт)")
    void detectorFindsEveryForbiddenReference() throws IOException {
        assertTrue(findForbidden(classBytes(Probes.Jul.class)).contains(JUL), "JUL");
        assertTrue(
                findForbidden(classBytes(Probes.SystemLoggerUse.class)).contains(SYSTEM_LOGGER),
                "System.Logger");
        assertTrue(
                findForbidden(classBytes(Probes.Console.class)).contains(PRINT_STREAM),
                "System.out и System.err");
        assertTrue(
                findForbidden(classBytes(Probes.StackTrace.class)).contains(PRINT_STACK_TRACE),
                "printStackTrace");
        assertTrue(
                findForbidden(classBytes(Probes.Wrapper.class)).contains(GOST_LOGGER),
                "GostLogger");
        assertEquals(
                List.of(),
                findForbidden(classBytes(Probes.Clean.class)),
                "System.arraycopy не должен считаться выводом в консоль");
    }

    private static boolean isLoggerClass(String classFile) {
        return classFile.equals(LOGGER_CLASS) || classFile.startsWith(LOGGER_NESTED_PREFIX);
    }

    /** Запрещённые константы, которые встречаются в байткоде класса (ASCII совпадает с пулом). */
    private static List<String> findForbidden(byte[] classBytes) {
        String text = new String(classBytes, StandardCharsets.ISO_8859_1);
        List<String> found = new ArrayList<>();
        for (String forbidden : FORBIDDEN) {
            if (text.contains(forbidden)) {
                found.add(forbidden);
            }
        }
        return found;
    }

    private static byte[] classBytes(Class<?> type) throws IOException {
        String resource = type.getName().replace('.', '/') + ".class";
        try (InputStream in = type.getClassLoader().getResourceAsStream(resource)) {
            assertTrue(in != null, "нет файла класса: " + resource);
            return in.readAllBytes();
        }
    }

    /** Образцы запрещённых обращений: по ним проверяется, что страж их различает. */
    static final class Probes {
        private Probes() {}

        static final class Jul {
            Object use() {
                return java.util.logging.Logger.getLogger("probe");
            }
        }

        static final class SystemLoggerUse {
            Object use() {
                return System.getLogger("probe");
            }
        }

        static final class Console {
            void use() {
                System.err.println("probe");
            }
        }

        static final class StackTrace {
            void use(Throwable t) {
                t.printStackTrace();
            }
        }

        static final class Wrapper {
            Object use() {
                return GostLogger.getLogger("probe");
            }
        }

        static final class Clean {
            void use(byte[] a, byte[] b) {
                System.arraycopy(a, 0, b, 0, a.length);
            }
        }
    }
}
