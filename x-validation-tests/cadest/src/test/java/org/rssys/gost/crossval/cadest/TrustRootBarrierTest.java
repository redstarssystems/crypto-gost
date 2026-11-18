package org.rssys.gost.crossval.cadest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.crossval.util.CryptoProChecker;

/**
 * Единственный барьер от постановки тестового корня с опубликованным ключом в доверенное хранилище
 * - флаг {@code crossval.cryptopro.trustRoot}: окно подтверждения КриптоПро установку не
 * блокирует. Тесты проверяют, что без флага установка не происходит и флаг не расползся по make.
 */
@DisplayName("Барьер crossval.cryptopro.trustRoot: корень не ставится без явного флага")
class TrustRootBarrierTest {

    private static final Pattern TARGET = Pattern.compile("^([A-Za-z0-9_.-]+):(?!=)");

    /** Выполняет действие при заданном значении флага и возвращает прежнее значение на место. */
    private static <T> T withFlag(String value, java.util.function.Supplier<T> action) {
        String previous = System.getProperty(CryptoProChecker.TRUST_ROOT_PROPERTY);
        try {
            System.setProperty(CryptoProChecker.TRUST_ROOT_PROPERTY, value);
            return action.get();
        } finally {
            if (previous == null) {
                System.clearProperty(CryptoProChecker.TRUST_ROOT_PROPERTY);
            } else {
                System.setProperty(CryptoProChecker.TRUST_ROOT_PROPERTY, previous);
            }
        }
    }

    @Test
    @DisplayName("Флаг выключен: установка корня не запрашивается")
    void disabledFlagMeansNoTrust() {
        assertFalse(
                withFlag("false", CryptoProChecker::trustRootEnabled),
                "при выключенном флаге доверенный корень не запрашивается");
        assertTrue(
                withFlag("true", CryptoProChecker::trustRootEnabled),
                "включённый флаг должен читаться");
    }

    @Test
    @DisplayName("CAdES opt-in следует за флагом (при наличии libcades)")
    void cadesOptInFollowsTheFlag() {
        // Без libcades opt-in выключен независимо от флага, и тест ничего бы не доказывал
        assumeTrue(CryptoProChecker.cadesLibraryAvailable(), "нужна libcades");
        assertFalse(withFlag("false", CryptoproCAdESCrossValidationTest::cadesTrustAvailable));
        assertFalse(withFlag("false", CryptoproCAdESXLongCrossValidationTest::cadesTrustAvailable));
        assertTrue(withFlag("true", CryptoproCAdESCrossValidationTest::cadesTrustAvailable));
        assertTrue(withFlag("true", CryptoproCAdESXLongCrossValidationTest::cadesTrustAvailable));
    }

    @Test
    @DisplayName("Операторская команда install без --yes и без флага отказывает")
    void installWithoutConsentIsRefused() {
        int exit = withFlag("false", () -> CryptoproRootTool.execute(new String[] {"install"}));

        assertEquals(2, exit, "install без согласия оператора обязан отказать и ничего не ставить");
    }

    @Test
    @DisplayName("Флаг trustRoot встречается в Makefile только в цели crossval-cades")
    void makefileSetsTheFlagOnlyInCrossvalCades() throws IOException {
        List<String> lines = Files.readAllLines(findMakefile());
        String target = "";
        int occurrences = 0;
        for (String line : lines) {
            Matcher m = TARGET.matcher(line);
            if (m.find() && !line.startsWith("\t")) {
                target = m.group(1);
            }
            if (line.contains(CryptoProChecker.TRUST_ROOT_PROPERTY) && !line.startsWith("#")) {
                occurrences++;
                assertEquals(
                        "crossval-cades",
                        target,
                        "флаг обнаружен вне цели crossval-cades: " + line.strip());
            }
        }
        assertTrue(occurrences > 0, "флаг должен задаваться в crossval-cades");
    }

    private static Path findMakefile() {
        Path dir = Path.of(System.getProperty("user.dir")).toAbsolutePath();
        for (Path p = dir; p != null; p = p.getParent()) {
            Path candidate = p.resolve("Makefile");
            if (Files.isRegularFile(candidate) && containsTarget(candidate)) {
                return candidate;
            }
        }
        throw new IllegalStateException("корневой Makefile с целью crossval-cades не найден");
    }

    private static boolean containsTarget(Path makefile) {
        try {
            return Files.readString(makefile).contains("\ncrossval-cades:");
        } catch (IOException e) {
            return false;
        }
    }
}
