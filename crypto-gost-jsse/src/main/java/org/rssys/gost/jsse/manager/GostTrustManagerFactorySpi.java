package org.rssys.gost.jsse.manager;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactorySpi;
import org.rssys.gost.jsse.ocsp.OcspPolicy;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.util.GostLogger;
import org.rssys.gost.util.GostLogger.Level;

/**
 * TrustManagerFactorySpi для ГОСТ-сертификатов.
 * <p>
 * Загружает все доверенные сертификаты из сертификатных записей KeyStore.
 * Записи, которые не разбираются как ГОСТ-сертификаты, пропускаются:
 * в хранилище могут лежать и не-ГОСТ корни.
 * <p>
 * Пустой набор якорей — ошибка конфигурации, а не режим trust-all.
 * <p>
 * <b>Политика отзыва при инициализации из KeyStore фиксирована</b>:
 * {@link OcspPolicy#IF_PRESENT} (проверяется только присланный сервером OCSP-staple, его
 * отсутствие не ошибка), списки CRL не используются, сетевые запросы за OCSP/CRL не выполняются.
 * Стандартный путь JSSE {@code TrustManagerFactory.init(KeyStore)} не позволяет передать
 * настройки отзыва, поэтому при каждой такой инициализации пишется предупреждение. Для
 * строгой проверки (обязательный OCSP, CRL, загрузка по сети) инициализируйте фабрику через
 * {@code init(ManagerFactoryParameters)} с {@link GostTrustManagerParameters}.
 */
public final class GostTrustManagerFactorySpi extends TrustManagerFactorySpi {

    private static final GostLogger LOG =
            GostLogger.getLogger("org.rssys.gost.jsse.manager.GostTrustManagerFactorySpi");

    private TrustAnchors trustAnchors;
    private GostTrustManagerParameters params;

    private void resetState() {
        this.trustAnchors = null;
        this.params = null;
    }

    @Override
    protected void engineInit(KeyStore ks) throws KeyStoreException {
        resetState();
        if (ks == null) {
            throw new KeyStoreException(
                    "Default trust store is not supported;"
                            + " provide a KeyStore with GOST trust anchors");
        }

        List<GostCertificate> anchors = new ArrayList<>();
        try {
            Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (!ks.isCertificateEntry(alias)) continue;
                Certificate cert = ks.getCertificate(alias);
                if (cert == null) continue;
                try {
                    anchors.add(new GostCertificate(cert.getEncoded()));
                } catch (IllegalArgumentException e) {
                    // Штатный случай: в хранилище лежит не-ГОСТ корень.
                    // DEBUG, иначе cacerts JDK даёт десятки WARNING на каждый init.
                    LOG.log(
                            Level.DEBUG,
                            "Skipping non-GOST trust store entry alias={0}, exception={1}",
                            alias,
                            e.getClass().getSimpleName());
                } catch (Exception e) {
                    // Неожиданная ошибка (кодировка, I/O) — нужна диагностика.
                    LOG.log(
                            Level.WARNING,
                            "Skipping trust store entry alias={0}, exception={1}",
                            alias,
                            e.getClass().getSimpleName());
                }
            }
        } catch (KeyStoreException e) {
            throw e;
        } catch (Exception e) {
            throw new KeyStoreException("Failed to read trust store", e);
        }

        if (anchors.isEmpty()) {
            throw new KeyStoreException("No GOST trust anchors found in KeyStore");
        }
        this.trustAnchors = TrustAnchors.ofCertificates(anchors);
        // Пользователь, инициализировавший фабрику стандартным способом, иначе не узнает, что
        // отзыв проверяется только по присланному staple: настроить его через KeyStore нельзя.
        LOG.log(
                Level.WARNING,
                "TrustManagerFactory initialized from a KeyStore: revocation policy is fixed"
                        + " (OCSP: stapled response only if present, CRL: disabled, no network"
                        + " fetchers); use GostTrustManagerParameters for strict revocation"
                        + " checking");
    }

    @Override
    protected void engineInit(ManagerFactoryParameters spec)
            throws InvalidAlgorithmParameterException {
        resetState();
        if (!(spec instanceof GostTrustManagerParameters)) {
            throw new InvalidAlgorithmParameterException(
                    "Expected GostTrustManagerParameters, got "
                            + (spec == null ? "null" : spec.getClass().getName()));
        }
        // Параметры создаются только через Builder.build(), который уже отвергает пустые якоря
        this.params = (GostTrustManagerParameters) spec;
    }

    @Override
    protected TrustManager[] engineGetTrustManagers() {
        if (params != null) {
            return new TrustManager[] {
                GostX509TrustManager.fromTrustAnchors(
                        params.getTrustAnchors(),
                        params.getOcspPolicy(),
                        params.getOcspFetcher(),
                        params.getCrlPolicy(),
                        params.getCrlFetcher(),
                        params.getMaxCrlSize(),
                        params.getMaxRevokedEntries(),
                        params.getCrlCacheMaxBytes(),
                        params.getCrlMaxAge(),
                        params.getMaxOcspAgeMs(),
                        params.getMaxThisUpdateAge())
            };
        }
        if (trustAnchors == null || trustAnchors.isEmpty()) {
            throw new IllegalStateException(
                    "TrustManagerFactory is not initialized with GOST trust anchors");
        }
        return new TrustManager[] {
            GostX509TrustManager.fromTrustAnchors(trustAnchors, OcspPolicy.IF_PRESENT, null)
        };
    }
}
