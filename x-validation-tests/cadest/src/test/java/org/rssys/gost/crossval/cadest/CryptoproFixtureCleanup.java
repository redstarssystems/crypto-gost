package org.rssys.gost.crossval.cadest;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.rssys.gost.crossval.util.CertmgrStore;

/**
 * Уборка сертификатов и CRL фикстур из личного хранилища {@code uMy} после прогона.
 *
 * <p>Удаление идёт по идентификатору ключа своих сертификатов, а не по имени, и каждое проверяется:
 * после удаления с этим {@code keyid} не должно остаться ничего. Сертификаты пользователя не
 * трогаются и не выводятся. Ошибки удаления не глотаются: остаток в хранилище накапливался бы
 * незаметно. Проверки только считают, ничего не печатают.
 */
final class CryptoproFixtureCleanup {

    private CryptoproFixtureCleanup() {}

    /** Снимок хранилищ {@code uMy} и {@code uRoot} до прогона (строки вывода, в памяти). */
    record Snapshot(Map<String, Integer> personal, Map<String, Integer> roots) {}

    /** Снимает хранилища до того, как тест что-либо в них поставит. */
    static Snapshot snapshot() throws IOException {
        return new Snapshot(
                new CertmgrStore(CertmgrStore.PERSONAL_STORE).snapshot(),
                new CertmgrStore(CertmgrStore.ROOT_STORE).snapshot());
    }

    /**
     * Сравнивает хранилища с исходным снимком. Лишнее значит остаток прогона, пропавшее - задет чужой
     * сертификат. Сообщения содержат только число строк, данные сертификатов не выводятся.
     */
    static List<String> compareWith(Snapshot before) {
        List<String> violations = new ArrayList<>();
        try {
            Snapshot after = snapshot();
            check("uMy", before.personal(), after.personal(), violations);
            check("uRoot", before.roots(), after.roots(), violations);
        } catch (IOException e) {
            violations.add("не удалось снять хранилища после прогона: " + e.getMessage());
        }
        return violations;
    }

    private static void check(
            String name,
            Map<String, Integer> before,
            Map<String, Integer> after,
            List<String> violations) {
        long left = surplus(after, before);
        long lost = surplus(before, after);
        if (left > 0) {
            violations.add(name + ": после прогона появилось лишних строк: " + left);
        }
        if (lost > 0) {
            violations.add(name + ": пропало строк исходного снимка (задет чужой сертификат): " + lost);
        }
    }

    /** Сколько строк в {@code a} сверх {@code b} с учётом кратности. */
    private static long surplus(Map<String, Integer> a, Map<String, Integer> b) {
        long total = 0;
        for (Map.Entry<String, Integer> e : a.entrySet()) {
            total += Math.max(0, e.getValue() - b.getOrDefault(e.getKey(), 0));
        }
        return total;
    }

    /**
     * @param certificateKeyIds идентификаторы ключей установленных сертификатов фикстур
     * @param crlIssuerKeyId    идентификатор ключа издателя установленного CRL или {@code null},
     *                          если CRL не ставился
     * @return нарушения: пусто, если своих сертификатов и CRL в {@code uMy} не осталось
     */
    static List<String> remove(List<byte[]> certificateKeyIds, byte[] crlIssuerKeyId) {
        CertmgrStore personal = new CertmgrStore(CertmgrStore.PERSONAL_STORE);
        List<String> violations = new ArrayList<>();
        for (byte[] keyId : certificateKeyIds) {
            try {
                if (personal.countByKeyId(keyId) > 0) {
                    personal.deleteByKeyId(keyId);
                }
                if (personal.countByKeyId(keyId) != 0) {
                    violations.add("сертификат фикстуры остался в uMy");
                }
            } catch (IOException e) {
                violations.add("не удалось убрать сертификат фикстуры из uMy: " + e.getMessage());
            }
        }
        if (crlIssuerKeyId != null) {
            try {
                if (personal.countCrlsByAuthorityKeyId(crlIssuerKeyId) > 0) {
                    personal.deleteCrlsByAuthorityKeyId(crlIssuerKeyId);
                }
                if (personal.countCrlsByAuthorityKeyId(crlIssuerKeyId) != 0) {
                    violations.add("CRL фикстур остался в uMy");
                }
            } catch (IOException e) {
                violations.add("не удалось убрать CRL фикстур из uMy: " + e.getMessage());
            }
        }
        return violations;
    }
}
