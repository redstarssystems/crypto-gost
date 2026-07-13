package org.rssys.gost.pkix.cms;

import static org.junit.jupiter.api.Assertions.*;

import java.io.InputStream;
import java.util.Random;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.cipher.mode.AcpkmSectionSize;
import org.rssys.gost.cipher.mode.CtrAcpkmMode;

/**
 * Regression KAT для ACPKM-рекейинга ГОСТ Р 34.13-2015 §6.2 (CMS-профиль, sectionSize=262144).
 *
 * <p>Провенанс фикстур:
 * <ul>
 *   <li>Контентная крипто-часть (encryptedContent) сгенерирована внешним openssl 3.3.3
 *       (engine gost) — независимая эталонная реализация.</li>
 *   <li>CEK и UKM извлечены из openssl-конверта через ktri-декриптор
 *       ({@link CmsEnvelopedDataDecryptor}), прошедший отдельную независимую
 *       кросс-валидацию — переиспользование уже доказанного компонента.</li>
 *   <li>При генерации выполнена self-check: наш encrypt / CmsOmacHelper.encrypt
 *       побайтово совпал с openssl encryptedContent, и CmsOmacHelper.decrypt
 *       успешно восстанавливает plaintext из той же фикстуры.</li>
 * </ul>
 *
 * <p>Случаи:
 * <ul>
 *   <li><b>NON_OMAC</b> — 2 полные секции (524288 байт), чистый CTR-ACPKM без OMAC.</li>
 *   <li><b>OMAC_A</b> — L=262144 (MAC целиком в свежерекейнутой секции 2),
 *       проверяет точный триггер рекея на границе.</li>
 *   <li><b>OMAC_B</b> — L=262140 (MAC разорван границей секции: 4 байта до рекея,
 *       12 после), проверяет корректность шифрования имитовставки при разрыве.</li>
 * </ul>
 *
 * <p><b>Размер фикстур.</b> NON_OMAC использует 2 полные секции (524288 байт),
 * OMAC_A/B — по одной секции (≈262 КБ). Это осознанный trade-off: размер репо
 * (≈1 МБ бинарных ресурсов) в обмен на полноту покрытия — проверяется устойчивая
 * работа счётчика под двумя разными ключами (исходный + после acpkmNext),
 * а не только пограничная зона переключения. Файлы не минимизированы намеренно.
 */
@DisplayName("ACPKM regression KAT (CMS, sectionSize=262144)")
class CtrAcpkmKatTest {

    private static final String BASE = "org/rssys/gost/pkix/cms/kat/";

    @Test
    @DisplayName("NON_OMAC: 2 секции (524288 байт), encryptOnly совпадает с openssl")
    void nonOmac524288() throws Exception {
        KatFixture f = load("non-omac");
        byte[] plain = generatePlaintext(f.seed(), f.ptlen());
        byte[] ct =
                CtrAcpkmMode.encryptOnly(
                        new SymmetricKey(f.cek()), f.ukm(), plain, AcpkmSectionSize.CMS);
        byte[] expected = f.ct();
        assertArrayEquals(
                expected,
                ct,
                "encryptOnly должен выдавать ровно тот же шифртекст, что и openssl (2 секции ACPKM)");
    }

    @Test
    @DisplayName("NON_OMAC: размер шифртекста равен размеру открытого текста")
    void nonOmacCtSize() throws Exception {
        KatFixture f = load("non-omac");
        assertEquals(
                f.ptlen(),
                f.ct().length,
                "CTR-ACPKM не добавляет overhead — длина шифртекста = длина открытого текста");
    }

    @Test
    @DisplayName(
            "OMAC_A: L=262144, MAC целиком в секции 2, CmsOmacHelper.encrypt совпадает с openssl")
    void omacA262144() throws Exception {
        KatFixture f = load("omac-a");
        byte[] plain = generatePlaintext(f.seed(), f.ptlen());
        CmsOmacHelper.EncryptResult r = CmsOmacHelper.encrypt(plain, f.cek(), f.ukm());
        assertArrayEquals(
                f.ct(),
                r.encryptedContent(),
                "CmsOmacHelper.encrypt должен выдавать тот же encryptedContent, что и openssl");
    }

    @Test
    @DisplayName("OMAC_A: self-check — decrypt возвращает plaintext")
    void omacASelfDecrypt() throws Exception {
        KatFixture f = load("omac-a");
        byte[] plain = generatePlaintext(f.seed(), f.ptlen());
        CmsOmacHelper.EncryptResult r = CmsOmacHelper.encrypt(plain, f.cek(), f.ukm());
        byte[] dec =
                CmsOmacHelper.decrypt(
                        r.encryptedContent(), r.macAttribute().encodedMac(), f.cek(), f.ukm());
        assertArrayEquals(plain, dec, "OMAC self-consistency: encrypt → decrypt = original");
    }

    @Test
    @DisplayName("OMAC_B: L=262140, MAC разорван границей (4 байта до, 12 после)")
    void omacB262140() throws Exception {
        KatFixture f = load("omac-b");
        byte[] plain = generatePlaintext(f.seed(), f.ptlen());
        CmsOmacHelper.EncryptResult r = CmsOmacHelper.encrypt(plain, f.cek(), f.ukm());
        assertArrayEquals(
                f.ct(),
                r.encryptedContent(),
                "CmsOmacHelper.encrypt должен совпадать с openssl (MAC разорван границей секции)");
    }

    @Test
    @DisplayName("OMAC_B: self-check — decrypt возвращает plaintext (MAC через границу)")
    void omacBSelfDecrypt() throws Exception {
        KatFixture f = load("omac-b");
        byte[] plain = generatePlaintext(f.seed(), f.ptlen());
        CmsOmacHelper.EncryptResult r = CmsOmacHelper.encrypt(plain, f.cek(), f.ukm());
        byte[] dec =
                CmsOmacHelper.decrypt(
                        r.encryptedContent(), r.macAttribute().encodedMac(), f.cek(), f.ukm());
        assertArrayEquals(
                plain, dec, "OMAC self-consistency через границу: encrypt → decrypt = original");
    }

    // ========================================================================
    // Helpers
    // ========================================================================

    private static KatFixture load(String tag) throws Exception {
        byte[] cek = resource(tag + ".cek");
        byte[] ukm = resource(tag + ".ukm");
        byte[] ct = resource(tag + ".ct");
        byte[] seedPrefix = resource(tag + ".seed");
        byte[] ptlenBytes = resource(tag + ".ptlen");
        int ptlen = Integer.parseInt(new String(ptlenBytes).trim());
        long seed = Long.parseLong(new String(seedPrefix).trim());
        return new KatFixture(cek, ukm, ptlen, ct, seed);
    }

    private static byte[] resource(String name) throws Exception {
        try (InputStream is =
                CtrAcpkmKatTest.class.getClassLoader().getResourceAsStream(BASE + name)) {
            if (is == null)
                throw new IllegalStateException("KAT resource not found: " + BASE + name);
            return is.readAllBytes();
        }
    }

    private static byte[] generatePlaintext(long seed, int ptlen) {
        byte[] plain = new byte[ptlen];
        new Random(seed).nextBytes(plain);
        return plain;
    }

    // seed — эффективный seed для Random, уже включает длину plaintext (base + ptlen).
    // Не путать с базовым seed из GenKat (0xCAFE0000 / 0xBEEF0000).
    private record KatFixture(byte[] cek, byte[] ukm, int ptlen, byte[] ct, long seed) {}
}
