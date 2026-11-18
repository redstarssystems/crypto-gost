package org.rssys.gost.pkix.cert;

import java.math.BigInteger;
import java.time.Instant;
import java.util.Arrays;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.signature.PublicKeyParameters;

/**
 * Прямой полный CRL с проверенной подписью и разобранными записями, привязанный к ключу
 * издателя.
 *
 * <p>Дорогая часть проверки CRL (хэш Стрибога, подпись ГОСТ, строгий разбор сотен тысяч
 * записей) не зависит от сертификата, который проверяется. {@link CrlVerifier#authenticate}
 * выполняет её один раз, а результат можно хранить и применять к любому числу сертификатов
 * через {@link #verifyFor}. Сроки, соответствие издателя, монотонность {@code cRLNumber},
 * запись об отзыве и область CRL проверяются заново на каждом вызове: срок истекает уже после
 * проверки подписи.</p>
 *
 * <p>Объект неизменяем и потокобезопасен. Конструктор закрыт, создаёт его только
 * {@link CrlVerifier}; внутренний {@link GostCrl} наружу не отдаётся, повторно вызвать на нём
 * проверку подписи нельзя. Тип относится только к прямому полному CRL: делегированные и
 * delta CRL сюда не входят.</p>
 */
public final class VerifiedCrl {

    private final GostCrl crl;
    private final byte[] issuerKeySpki;
    private final long estimatedBytes;

    VerifiedCrl(GostCrl crl, byte[] issuerKeySpki) {
        this.crl = crl;
        this.issuerKeySpki = issuerKeySpki;
        this.estimatedBytes =
                crl.getEncodedLength()
                        + (long) crl.getRevokedCount() * GostOids.CRL_RETAINED_BYTES_PER_ENTRY;
    }

    /** @return {@code cRLNumber} CRL или {@code null}, если расширения нет */
    public BigInteger getCrlNumber() {
        return crl.getCrlNumber();
    }

    /** @return {@code nextUpdate} CRL или {@code null}, если поля нет */
    public Instant getNextUpdate() {
        return crl.getNextUpdate();
    }

    /**
     * Оценка памяти, которую удерживает объект: длина DER плюс число записей, умноженное на
     * {@link GostOids#CRL_RETAINED_BYTES_PER_ENTRY}. Нужна кэшу для бюджета.
     *
     * @return оценка в байтах
     */
    public long getEstimatedBytes() {
        return estimatedBytes;
    }

    /**
     * Проверяет сертификат по этому CRL.
     *
     * <p>Порядок: ключ издателя совпадает с тем, которым проверена подпись, и у издателя есть
     * право подписывать CRL ({@code cRLSign}, если задан KeyUsage; проверка здесь нужна, потому
     * что объект могут получить из кэша, куда он попал для другого сертификата с тем же
     * ключом); {@code thisUpdate}
     * не в будущем; срок CRL не истёк; issuer DN CRL совпадает с издателем сертификата;
     * {@code cRLNumber} не ниже {@code minCrlNumber}; сертификат не отозван
     * ({@code REVOKED}); CRL покрывает сертификат ({@code IDP_NOT_SUPPORTED}). Запись об
     * отзыве проверяется раньше области: отзыв в подлинном CRL не должен зависеть от того,
     * какие сертификаты CRL обязан покрывать.</p>
     *
     * @param cert         проверяемый сертификат
     * @param issuerCa     сертификат издателя; его ключ обязан совпадать с ключом, которым
     *                     проверена подпись CRL
     * @param minCrlNumber минимально допустимый {@code cRLNumber} или {@code null}
     * @throws PkixException если ключ другой, у издателя нет права подписывать CRL
     *                       ({@code MISSING_CRL_SIGN}), CRL просрочен, не подходит сертификату,
     *                       номер понижен, сертификат отозван или не покрыт областью CRL
     */
    public void verifyFor(GostCertificate cert, GostCertificate issuerCa, BigInteger minCrlNumber)
            throws PkixException {
        if (cert == null) {
            throw new PkixException("cert must not be null");
        }
        if (issuerCa == null) {
            throw new PkixException("issuerCa must not be null");
        }
        if (!Arrays.equals(issuerKeySpki, CrlVerifier.encodeIssuerKey(issuerCa.getPublicKey()))) {
            throw new PkixException("CRL was verified with a different issuer key");
        }
        CrlVerifier.requireCrlSign(issuerCa);
        crl.requireValidNow();
        CrlVerifier.checkAuthenticated(crl, cert, minCrlNumber);
    }

    /** Для проверки в тестах: тот же ключ издателя, что у объекта. */
    static byte[] encodeKey(PublicKeyParameters key) {
        return GostDerCodec.encodePublicKey(key);
    }
}
