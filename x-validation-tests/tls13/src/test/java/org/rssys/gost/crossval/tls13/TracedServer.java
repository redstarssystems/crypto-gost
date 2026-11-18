package org.rssys.gost.crossval.tls13;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Запущенный s_server с постоянным чтением вывода с момента старта: вывод процесса буферизуется,
 * а после остановки потоки закрыты, поэтому читать его нужно фоновым потоком, а не по окончании.
 */
final class TracedServer implements AutoCloseable {
    final Process process;
    final StringBuffer output = new StringBuffer();

    TracedServer(Process process) {
        this.process = process;
        Thread collector =
                new Thread(
                        () -> {
                            try (BufferedReader reader =
                                    new BufferedReader(
                                            new InputStreamReader(
                                                    process.getInputStream(),
                                                    StandardCharsets.UTF_8))) {
                                String line;
                                while ((line = reader.readLine()) != null) {
                                    output.append(line).append('\n');
                                }
                            } catch (IOException ignored) {
                                // процесс остановлен тестом
                            }
                        });
        collector.setDaemon(true);
        collector.start();
    }

    boolean awaitOutput(String expected, long timeoutMs) throws InterruptedException {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < deadline) {
            if (output.toString().contains(expected)) {
                return true;
            }
            Thread.sleep(50);
        }
        return output.toString().contains(expected);
    }

    /** Число вхождений шаблона в выводе; вывод s_server буферизуется, поэтому ждём срок. */
    int awaitMatches(Pattern pattern, int atLeast, long timeoutMs) throws InterruptedException {
        long deadline = System.currentTimeMillis() + timeoutMs;
        int count = 0;
        while (System.currentTimeMillis() < deadline) {
            count = 0;
            Matcher matcher = pattern.matcher(output.toString());
            while (matcher.find()) {
                count++;
            }
            if (count >= atLeast) {
                return count;
            }
            Thread.sleep(50);
        }
        return count;
    }

    @Override
    public void close() {
        OpenSslTls13Helper.destroyProcess(process);
    }
}
