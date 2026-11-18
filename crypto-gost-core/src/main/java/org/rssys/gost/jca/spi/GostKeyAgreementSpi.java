package org.rssys.gost.jca.spi;

import org.rssys.gost.api.KeyAgreement;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;

/**
 * JCA {@link javax.crypto.KeyAgreementSpi} для алгоритма ECDH (ГОСТ Р 34.10-2012).
 *
 * <p>Поддерживает однофазный ECDH: {@code engineInit(privKey)} -> {@code engineDoPhase(pubKey, true)} ->
 * {@code engineGenerateSecret()}. Параметры инициализации не принимаются: кривая зашита в ключе.
 *
 * <p>Делегирует {@link KeyAgreement#computeSharedSecret(PrivateKeyParameters, PublicKeyParameters)}.
 *
 * <p>Регистрируется в {@code RssysGostProvider} как {@code KeyAgreement.ECDHGOST2012}.
 */
public final class GostKeyAgreementSpi extends AbstractGostKeyAgreementSpi {

    private static final String ALGORITHM = "ECDHGOST2012";

    @Override
    protected String algorithm() {
        return ALGORITHM;
    }

    /** Сырой общий секрет: X-координата d·Qpeer в little-endian. */
    @Override
    protected byte[] derive(PrivateKeyParameters priv, PublicKeyParameters peer) {
        return KeyAgreement.computeSharedSecret(priv, peer);
    }
}
