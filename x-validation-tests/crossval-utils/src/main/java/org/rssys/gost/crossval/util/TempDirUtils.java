package org.rssys.gost.crossval.util;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;

/**
 * Утилиты для работы с временными директориями в тестах.
 */
public final class TempDirUtils {

    private TempDirUtils() {}

    /**
     * Создаёт временную директорию, выполняет {@code action} и гарантированно удаляет
     * директорию со всем содержимым.
     */
    public static <T> T withTempDir(String prefix, ThrowingFunction<Path, T> action)
            throws Exception {
        Path dir = Files.createTempDirectory(prefix);
        try {
            return action.apply(dir);
        } finally {
            deleteRecursively(dir);
        }
    }

    /**
     * Рекурсивно удаляет директорию и всё её содержимое.
     * Files.walk отдаёт родителей раньше потомков, поэтому порядок
     * развёрнут — иначе не удалить непустую директорию.
     */
    public static <T> T withTempFile(String prefix, String suffix, ThrowingFunction<Path, T> action)
            throws Exception {
        Path file = Files.createTempFile(prefix, suffix);
        try {
            return action.apply(file);
        } finally {
            Files.deleteIfExists(file);
        }
    }

    public static void deleteRecursively(Path dir) {
        try (var files = Files.walk(dir)) {
            files.sorted(Comparator.reverseOrder())
                    .forEach(
                            f -> {
                                try {
                                    Files.deleteIfExists(f);
                                } catch (Exception ignored) {
                                }
                            });
        } catch (Exception ignored) {
        }
    }
}
