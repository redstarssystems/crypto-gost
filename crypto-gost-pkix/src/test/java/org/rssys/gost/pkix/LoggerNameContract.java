package org.rssys.gost.pkix;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Проверка контракта «имя логгера равно полному имени класса».
 *
 * <p>Обходит исходники модуля и сверяет строку в {@code GostLogger.getLogger("...")} с FQCN
 * файла. Регулярка читает файл целиком, поэтому перенос {@code getLogger(} на следующую строку
 * (так оформлен {@code GostSSLSocket}) её не ломает. Помощник общий: его вызывают pkix, tls13 и
 * jsse, чтобы переименование класса не оставляло старое имя логгера незамеченным.
 */
public final class LoggerNameContract {

    private static final Pattern GET_LOGGER =
            Pattern.compile("GostLogger\\.getLogger\\(\\s*\"([^\"]+)\"\\s*\\)");

    private LoggerNameContract() {}

    /**
     * Проверяет все объявления логгеров в дереве исходников.
     *
     * @param srcMainJava каталог {@code src/main/java} модуля (surefire запускается из каталога
     *     модуля, поэтому достаточно относительного пути)
     * @throws IOException если исходники не читаются
     */
    public static void assertNamesMatchClasses(Path srcMainJava) throws IOException {
        List<String> violations = new ArrayList<>();
        List<Path> files;
        try (Stream<Path> walk = Files.walk(srcMainJava)) {
            files = walk.filter(path -> path.toString().endsWith(".java")).toList();
        }
        for (Path file : files) {
            String source = Files.readString(file);
            String fqcn =
                    srcMainJava
                            .relativize(file)
                            .toString()
                            .replace(File.separatorChar, '/')
                            .replace(".java", "")
                            .replace('/', '.');
            Matcher matcher = GET_LOGGER.matcher(source);
            while (matcher.find()) {
                if (!fqcn.equals(matcher.group(1))) {
                    violations.add(fqcn + " -> " + matcher.group(1));
                }
            }
        }
        assertTrue(
                violations.isEmpty(), "имя логгера должно совпадать с FQCN класса: " + violations);
    }
}
