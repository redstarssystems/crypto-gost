package org.rssys.gost.tls13.cert;

import java.util.List;
import org.rssys.gost.pkix.cert.AnchorExpiryPolicy;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.TrustAnchors;

/**
 * Граница доверия к серверу по сроку его сертификатов.
 *
 * <p>PSK-возобновление не присылает сертификат, поэтому тикет не должен пережить сертификаты, по
 * которым сервер был принят при полном рукопожатии. Граница - наименьший {@code notAfter} среди
 * сертификатов, срок которых проверяет валидатор. Правило вынесено сюда, чтобы TLS-сессия и
 * менеджер доверия JSSE не разошлись в том, что считать границей.</p>
 */
public final class PeerTrustBoundary {

    private static final long MILLIS_PER_SECOND = 1000L;

    private PeerTrustBoundary() {}

    /**
     * Строит цепочку, по сроку которой считается граница доверия.
     *
     * <p>Локальный якорь исключается там, где валидатор его срок игнорирует (RFC 5280 §6.1):
     * цепочка длиннее одного сертификата и политика якорей не {@link AnchorExpiryPolicy#REJECT}.
     * Иначе допущенный истёкший корень обнулил бы границу, и возобновление молча перестало бы
     * работать. Одиночный закреплённый сертификат (он же leaf) и якорь при {@code REJECT}
     * остаются в цепочке: их срок проверяется.</p>
     *
     * @param effective эффективная цепочка пира leaf-first, верх - локальный якорь
     *                  ({@link TlsCertificateValidator#validateStructure})
     * @param anchors   якоря, по которым цепочка проверена
     * @return цепочка границы доверия (не изменяемая вызывающим кодом копия)
     */
    public static List<GostCertificate> boundaryChain(
            List<GostCertificate> effective, TrustAnchors anchors) {
        if (effective == null || effective.isEmpty()) {
            throw new IllegalArgumentException("effective chain must not be empty");
        }
        int size = effective.size();
        GostCertificate top = effective.get(size - 1);
        boolean topExpiryIgnored =
                size > 1
                        && anchors.containsCertificate(top)
                        && anchors.expiryPolicy() != AnchorExpiryPolicy.REJECT;
        return List.copyOf(topExpiryIgnored ? effective.subList(0, size - 1) : effective);
    }

    /**
     * Вычисляет границу доверия.
     *
     * @param boundaryChain цепочка границы доверия ({@link #boundaryChain})
     * @return наименьший {@code notAfter} цепочки в миллисекундах эпохи
     * @throws IllegalArgumentException если цепочка пуста: границу определить нельзя
     */
    public static long validUntil(List<GostCertificate> boundaryChain) {
        if (boundaryChain == null || boundaryChain.isEmpty()) {
            throw new IllegalArgumentException("boundary chain must not be empty");
        }
        long boundary = Long.MAX_VALUE;
        for (GostCertificate cert : boundaryChain) {
            boundary = Math.min(boundary, cert.getNotAfter().toEpochMilli());
        }
        return boundary;
    }

    /**
     * Ограничивает срок жизни тикета остатком до границы доверия.
     *
     * <p>Округление вниз до секунд: тикет не должен пережить границу ни на долю секунды.
     * Результат не больше нуля означает, что тикет выдавать или сохранять нельзя.</p>
     *
     * @param lifetimeSeconds исходный срок жизни тикета в секундах
     * @param validUntil      граница доверия в миллисекундах эпохи
     * @param nowMillis       текущее время в миллисекундах эпохи
     * @return срок жизни в секундах, не больше исходного; {@code <= 0}, если граница достигнута
     */
    public static long clampLifetimeSeconds(long lifetimeSeconds, long validUntil, long nowMillis) {
        long remainingSeconds = Math.floorDiv(validUntil - nowMillis, MILLIS_PER_SECOND);
        return Math.min(lifetimeSeconds, remainingSeconds);
    }
}
