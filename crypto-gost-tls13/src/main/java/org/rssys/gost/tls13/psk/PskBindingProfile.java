package org.rssys.gost.tls13.psk;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import org.rssys.gost.api.Digest;
import org.rssys.gost.tls13.TlsConstants;

/**
 * Единственный вычислитель идентификатора модели доверия для {@link PskBinding}.
 *
 * <p>Возобновление по PSK наследует проверку сервера из исходного рукопожатия, поэтому в
 * идентификатор входит всё, что влияет на принятие сервера: режим проверки, требование
 * OCSP-staple, флаг совместимости подписи, алгоритм хэша KDF набора шифров (RFC 8446 §4.6.1:
 * тикет возобновляется только с набором шифров с тем же хэшем KDF) и «идентичность доверия» -
 * байты, различающие наборы якорей. Модуль tls13 подаёт отпечаток якорей, jsse - случайный
 * идентификатор менеджера доверия. Общий вычислитель исключает дрейф канонической записи между
 * модулями: расхождение привело бы к тихой потере возобновления.</p>
 *
 * <p>Состав записи - перечисление полей; при добавлении настройки, влияющей на принятие
 * сервера, внесите её сюда и поднимите {@link TlsConstants#PSK_BINDING_PROFILE_VERSION}.</p>
 */
public final class PskBindingProfile {

    private static final byte[] DOMAIN_TAG =
            TlsConstants.PSK_BINDING_DOMAIN_TAG.getBytes(StandardCharsets.US_ASCII);

    private PskBindingProfile() {}

    /**
     * Вычисляет идентификатор модели доверия.
     *
     * @param mode                           режим проверки сервера ({@code
     *                                       TlsConstants.PSK_BINDING_MODE_*})
     * @param requireOcspStapling            требуется ли OCSP-staple сервера
     * @param interopAcceptGostBaseSigScheme ослаблена ли проверка схемы подписи сервера
     * @param kdfHash                        алгоритм хэша KDF набора шифров (не длина: разные
     *                                       хэши бывают одной длины)
     * @param trustIdentity                  байты, различающие модели доверия (отпечаток якорей
     *                                       или идентификатор менеджера доверия); {@code null},
     *                                       если доверие не используется
     * @return hex Стрибог-256 от канонической записи
     */
    public static String verificationId(
            byte mode,
            boolean requireOcspStapling,
            boolean interopAcceptGostBaseSigScheme,
            Digest.Algorithm kdfHash,
            byte[] trustIdentity) {
        byte[] kdfName = kdfHash.name().getBytes(StandardCharsets.US_ASCII);
        int identityLen = trustIdentity != null ? trustIdentity.length : 0;
        ByteBuffer canonical =
                ByteBuffer.allocate(
                        DOMAIN_TAG.length
                                + 1 // версия профиля
                                + 1 // режим
                                + 1 // OCSP-staple
                                + 1 // флаг совместимости
                                + Integer.BYTES
                                + kdfName.length
                                + 1 // флаг наличия идентичности доверия
                                + identityLen);
        canonical.put(DOMAIN_TAG);
        canonical.put(TlsConstants.PSK_BINDING_PROFILE_VERSION);
        canonical.put(mode);
        canonical.put((byte) (requireOcspStapling ? 1 : 0));
        canonical.put((byte) (interopAcceptGostBaseSigScheme ? 1 : 0));
        canonical.putInt(kdfName.length).put(kdfName);
        // Флаг наличия отделяет «пустую идентичность» от её отсутствия.
        canonical.put((byte) (trustIdentity != null ? 1 : 0));
        if (trustIdentity != null) {
            canonical.put(trustIdentity);
        }
        return HexFormat.of().formatHex(Digest.digest256(canonical.array()));
    }
}
