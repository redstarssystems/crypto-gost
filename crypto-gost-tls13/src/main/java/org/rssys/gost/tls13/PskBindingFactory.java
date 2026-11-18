package org.rssys.gost.tls13;

import org.rssys.gost.api.Digest;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.tls13.psk.PskBinding;
import org.rssys.gost.tls13.psk.PskBindingProfile;

/**
 * Вычисляет {@link PskBinding} клиентской сессии.
 *
 * <p>Возобновление по PSK наследует проверку сервера из исходного рукопожатия, поэтому в
 * идентификатор модели доверия входит всё, что влияет на принятие сервера: режим проверки,
 * отпечаток якорей (вместе с политикой их срока), требование OCSP-staple, флаг
 * совместимости подписи и хэш KDF набора шифров (RFC 8446 §4.6.1: тикет возобновляется
 * только с набором шифров с тем же хэшем KDF). Сравнение точное: тикет из сессии с более
 * слабой проверкой нельзя использовать в более строгой.</p>
 *
 * <p>Каноническую запись строит {@link PskBindingProfile}; при добавлении в {@code TlsClientConfig}
 * настройки, влияющей на принятие сервера, внесите её туда и поднимите
 * {@link TlsConstants#PSK_BINDING_PROFILE_VERSION}.</p>
 */
final class PskBindingFactory {

    private PskBindingFactory() {}

    /**
     * Строит привязку клиентской сессии.
     *
     * @param serverHostname              имя, отправляемое в SNI (может быть null)
     * @param verifyServerChain           проверяется ли цепочка сервера по якорям
     * @param hostnameVerificationDisabled отключена ли сверка имени с сертификатом
     * @param trustAnchors                якоря (null приравнивается к пустому набору)
     * @param requireOcspStapling         требуется ли OCSP-staple сервера
     * @param interopAcceptGostBaseSigScheme ослаблена ли проверка схемы подписи сервера
     * @param kdfHash                     алгоритм хэша KDF набора шифров (не длина: разные
     *                                    хэши бывают одной длины)
     * @return привязка, или null, если PSK предлагать нельзя: при сверке имени оно пусто, и
     *         привязывать тикет не к чему (полное рукопожатие с проверкой сертификата)
     */
    static PskBinding forClient(
            String serverHostname,
            boolean verifyServerChain,
            boolean hostnameVerificationDisabled,
            TrustAnchors trustAnchors,
            boolean requireOcspStapling,
            boolean interopAcceptGostBaseSigScheme,
            Digest.Algorithm kdfHash) {
        boolean nameBlank = serverHostname == null || serverHostname.isBlank();
        byte mode;
        if (!verifyServerChain) {
            mode = TlsConstants.PSK_BINDING_MODE_NO_SERVER_AUTH;
        } else if (hostnameVerificationDisabled) {
            mode = TlsConstants.PSK_BINDING_MODE_CHAIN_ONLY;
        } else {
            mode = TlsConstants.PSK_BINDING_MODE_CHAIN_AND_NAME;
            if (nameBlank) {
                return null;
            }
        }
        String serverName = nameBlank ? null : serverHostname;

        byte[] anchorsFingerprint =
                (verifyServerChain && trustAnchors != null) ? trustAnchors.fingerprint() : null;
        String verificationId =
                PskBindingProfile.verificationId(
                        mode,
                        requireOcspStapling,
                        interopAcceptGostBaseSigScheme,
                        kdfHash,
                        anchorsFingerprint);
        return new PskBinding(serverName, verificationId);
    }
}
