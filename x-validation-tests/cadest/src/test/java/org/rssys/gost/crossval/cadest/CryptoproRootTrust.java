package org.rssys.gost.crossval.cadest;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import org.rssys.gost.crossval.util.CryptoProChecker;
import org.rssys.gost.crossval.util.TempDirUtils;
import org.rssys.gost.crossval.util.TrustedRootSession;
import org.rssys.gost.pkix.cert.GostCertificate;

/**
 * Тестовый корень в {@code uRoot} КриптоПро на время прогона класса.
 *
 * <p>Ошибка установки не роняет весь класс: ядровые тесты (CMS-проверки без цепочки) корню не
 * нужны и должны остаться зелёными. Причина запоминается и показывается только тестам, которым
 * корень нужен ({@link #requireAvailable()}), а молчаливого пропуска при явном флаге нет.
 */
final class CryptoproRootTrust {

    /** Код КриптоПро «цепочка сертификатов не построена до доверенного корня» (CAdES-BES). */
    static final String CHAIN_NOT_BUILT = "0x800B010A";

    /**
     * Код КриптоПро «подпись не верна» для CAdES-X Long Type 1: этот режим первым проверяет метку
     * времени и её цепочку TSA, и без корня сообщает об отсутствии действительного штампа, а не о
     * цепочке подписанта.
     */
    static final String SIGNATURE_NOT_VALID = "0x200001F9";

    private final TrustedRootSession session;
    private final Exception failure;

    private CryptoproRootTrust(TrustedRootSession session, Exception failure) {
        this.session = session;
        this.failure = failure;
    }

    /** Корень не запрашивался: флаг выключен. */
    static CryptoproRootTrust disabled() {
        return new CryptoproRootTrust(null, null);
    }

    /**
     * Ставит корень фикстур на время прогона.
     *
     * @param root корень тестового УЦ
     */
    static CryptoproRootTrust open(GostCertificate root) {
        try {
            return new CryptoproRootTrust(
                    TrustedRootSession.open(root.getEncoded(), root.getSubjectKeyIdentifier()),
                    null);
        } catch (IOException | RuntimeException e) {
            return new CryptoproRootTrust(null, e);
        }
    }

    /** @return true, если корень установлен и тесты с цепочкой могут идти */
    boolean isAvailable() {
        return session != null;
    }

    /**
     * Тестам, которым нужен корень: падает с исходной причиной, если установка не удалась.
     */
    void requireAvailable() {
        if (failure != null) {
            throw new AssertionError(
                    "Не удалось установить тестовый корень в uRoot: " + failure.getMessage(),
                    failure);
        }
    }

    /** Снимает корень, если ставили его мы. */
    void close() throws IOException {
        if (session != null) {
            session.close();
        }
    }

    /**
     * Негативная проверка после снятия корня: подпись, которую КриптоПро принимал с корнем, теперь
     * не должна приниматься, цепочка не строится. Без неё «корня нет в списке» не доказывает, что
     * доверие снято: КриптоПро может держать результат построения цепочки в кеше.
     *
     * @param expectedCode код ошибки, которым КриптоПро отказывает этому режиму без корня
     * @param signed       подпись, которая до снятия корня проходила проверку
     * @param leafCertDer  DER-файл сертификата подписанта (опция {@code -f})
     * @param flags        опции проверки, с которыми подпись принималась
     * @return нарушения: пусто, если после снятия корня проверка отказывает ожидаемым кодом
     */
    static List<String> chainFailsWithoutRoot(
            String expectedCode, byte[] signed, Path leafCertDer, String... flags)
            throws Exception {
        List<String> violations = new ArrayList<>();
        TempDirUtils.withTempDir(
                "cp-root-gone-",
                dir -> {
                    Path signedPath = TestData.writeDer(dir, "signed.p7s", signed);
                    List<String> cmd = new ArrayList<>();
                    cmd.add(CryptoProChecker.resolveCryptcpBinary());
                    cmd.add("-verify");
                    cmd.addAll(List.of(flags));
                    cmd.addAll(
                            List.of(
                                    "-norev",
                                    "-f",
                                    leafCertDer.toString(),
                                    signedPath.toString(),
                                    dir.resolve("out.bin").toString()));
                    CryptoProChecker.Result r =
                            CryptoProChecker.runWithConfirm(
                                    Duration.ofSeconds(30), cmd.toArray(String[]::new));
                    if (r.exitCode() == 0) {
                        violations.add(
                                "после снятия корня КриптоПро всё ещё принимает подпись:"
                                        + " доверие не снято или цепочка осталась в кеше");
                    } else if (!r.output()
                            .toUpperCase(java.util.Locale.ROOT)
                            .contains(expectedCode.toUpperCase(java.util.Locale.ROOT))) {
                        violations.add(
                                "отказ есть, но не тот (ожидали "
                                        + expectedCode
                                        + "): "
                                        + r.output());
                    }
                    return null;
                });
        return violations;
    }
}
