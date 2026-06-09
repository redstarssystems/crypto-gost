package org.rssys.gost.jsse.manager;
import org.rssys.gost.jsse.GostJsseConstants;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.bridge.KeyBridge;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.cert.TlsCertificate;
import org.rssys.gost.tls13.config.SniCertificateSelector;
import org.rssys.gost.tls13.config.TlsServerCredentials;
import org.rssys.gost.tls13.config.ClientCertificateSelector;
import org.rssys.gost.tls13.config.TlsClientCredentials;
import org.rssys.gost.tls13.config.OIDFilter;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import javax.security.auth.x500.X500Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * X509KeyManager для ГОСТ-ключей.
 * <p>
 * Фильтрация по keyType (256/512), выбор по hostname (SAN dNSName), SNI-селектор.
 */
public final class GostX509KeyManager extends X509ExtendedKeyManager {

    private final List<KeyEntry> entries = new CopyOnWriteArrayList<>();

    /**
     * Добавляет связку сертификат + ключ в менеджер.
     */
    public void addKeyEntry(String alias, X509Certificate[] chain, PrivateKeyParameters key) {
        entries.add(new KeyEntry(alias, chain, key));
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return filterAliases(keyType, issuers).toArray(new String[0]);
    }

    @Override
    public String chooseClientAlias(String[] keyTypes, Principal[] issuers, Socket socket) {
        return chooseFirst(keyTypes, issuers);
    }

    @Override
    public String chooseEngineClientAlias(String[] keyTypes, Principal[] issuers, SSLEngine engine) {
        return chooseFirst(keyTypes, issuers);
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return filterAliases(keyType, issuers).toArray(new String[0]);
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        List<String> matching = filterAliases(keyType, issuers);
        return matching.isEmpty() ? null : matching.get(0);
    }

    @Override
    public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
        List<String> matching = filterAliases(keyType, issuers);
        return matching.isEmpty() ? null : matching.get(0);
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        for (KeyEntry entry : entries) {
            if (entry.alias.equals(alias)) {
                return entry.chain.clone();
            }
        }
        return null;
    }

    /**
     * Конвертирует цепочку JCA-сертификатов в формат tls13-ядра
     * для передачи в SniCertificateSelector.
     *
     * @param alias алиас записи
     * @return цепочка TlsCertificate, или null если алиас не найден
     */
    public List<TlsCertificate> getCertificateChainTls(String alias) {
        for (KeyEntry entry : entries) {
            if (entry.alias.equals(alias)) {
                return CertificateBridge.toTls(entry.chain);
            }
        }
        return null;
    }

    /**
     * Возвращает PrivateKeyParameters напрямую, минуя JCA-обёртку
     * GostPrivateKeyAdapter. Нужен SniCertificateSelector для
     * построения TlsServerCredentials.
     *
     * @param alias алиас записи
     * @return ключ в формате ядра, или null если алиас не найден
     */
    public PrivateKeyParameters getPrivateKeyParams(String alias) {
        for (KeyEntry entry : entries) {
            if (entry.alias.equals(alias)) {
                return entry.key;
            }
        }
        return null;
    }

    @Override
    public PrivateKey getPrivateKey(String alias) {
        for (KeyEntry e : entries) {
            if (e.alias.equals(alias)) {
                return KeyBridge.toJca(e.key);
            }
        }
        return null;
    }

    /**
     * Ищет алиас, чей сертификат содержит SAN dNSName, совпадающий с hostname.
     * <p>
     * Только SAN dNSName (RFC 6125), без fallback на CN.
     * Exact match, без wildcard — для детерминированного поведения в тестах.
     *
     * @param hostname DNS-имя для поиска (null → первый алиас)
     * @return алиас или null
     */
    public String chooseAliasForHostname(String hostname) {
        if (hostname == null) {
            return entries.isEmpty() ? null : entries.get(0).alias;
        }
        String normalized = hostname.trim().toLowerCase();
        if (normalized.endsWith(".")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        for (KeyEntry entry : entries) {
            if (entry.chain == null || entry.chain.length == 0) continue;
            TlsCertificate tlsCert = CertificateBridge.toTls(entry.chain[0]);
            String[] sanNames = tlsCert.getSanDnsNames();
            if (sanNames == null) continue;
            for (String dnsName : sanNames) {
                if (matchHostname(normalized, dnsName.toLowerCase())) {
                    return entry.alias;
                }
            }
        }
        return null;
    }

    /**
     * Проверяет соответствие hostname DNS-имени SAN с поддержкой wildcard.
     * Алгоритм соответствует RFC 6125 и {@code TlsCertificate.verifyHostname()}.
     */
    private static boolean matchHostname(String normalized, String sanLower) {
        // Точное совпадение
        if (normalized.equals(sanLower)) return true;

        // Wildcard: должен начинаться с "*."
        if (sanLower.startsWith("*.")) {
            String suffix = sanLower.substring(2);

            // Wildcard не должен быть "*." + apex
            if (suffix.isEmpty() || suffix.indexOf('.') < 0) return false;

            // Частичный wildcard (f*.example.com) запрещён
            if (sanLower.indexOf('*', 1) >= 0) return false;

            // IDN A-label wildcard запрещён
            if (suffix.startsWith("xn--") || suffix.contains(".xn--")) return false;

            // Первая метка hostname не должна содержать точек
            int firstDot = normalized.indexOf('.');
            if (firstDot < 0) return false;

            // Оставшаяся часть hostname должна совпадать с suffix
            return normalized.substring(firstDot + 1).equals(suffix);
        }
        return false;
    }

    /**
     * Создаёт SniCertificateSelector на основе этого KeyManager.
     * Вызывается сервером при инициализации handshake.
     */
    public SniCertificateSelector asSniSelector() {
        return serverName -> {
            String alias = chooseAliasForHostname(serverName);
            if (alias == null) return null;
            List<TlsCertificate> chain = getCertificateChainTls(alias);
            PrivateKeyParameters key = getPrivateKeyParams(alias);
            if (chain == null || key == null) return null;
            return new TlsServerCredentials(chain, key, null);
        };
    }

    /**
     * Создаёт ClientCertificateSelector на основе этого KeyManager.
     * Вызывается клиентом для выбора сертификата по oid_filters
     * из CertificateRequest (RFC 8446 §4.2.5).
     * <p>
     * Перебирает все записи, отбирает первую, удовлетворяющую всем OID-фильтрам.
     * Фильтрация по acceptedCaDns (issuer DN) не реализована.
     */
    public ClientCertificateSelector asClientCertificateSelector() {
        return (acceptedCaDns, oidFilters) -> {
            if (entries.isEmpty()) return null;
            for (KeyEntry entry : entries) {
                if (entry.chain == null || entry.chain.length == 0) continue;
                List<TlsCertificate> chain = getCertificateChainTls(entry.alias);
                PrivateKeyParameters key = getPrivateKeyParams(entry.alias);
                if (chain == null || chain.isEmpty() || key == null) continue;
                TlsCertificate leaf = chain.get(0);
                // Проверка OID-фильтров
                boolean matches = true;
                for (OIDFilter filter : oidFilters) {
                    if (!leaf.matchesOidFilter(filter)) {
                        matches = false;
                        break;
                    }
                }
                if (!matches) continue;
                return new TlsClientCredentials(chain, key);
            }
            return null;
        };
    }

    /**
     * Фильтрует алиасы по keyType и issuers.
     * keyType: ECGOST3410-2012-256 или ECGOST3410-2012-512.
     * Если issuers != null и не пуст — отбирает только сертификаты,
     * выпущенные одним из перечисленных CA (сравнение issuer X500Principal).
     */
    private List<String> filterAliases(String keyType, Principal[] issuers) {
        if (keyType == null) return Collections.emptyList();
        if (!keyType.startsWith(GostJsseConstants.KEY_ALG_ECGOST_2012)) return Collections.emptyList();

        boolean want256 = keyType.contains("256");

        List<String> result = new ArrayList<>();
        for (KeyEntry entry : entries) {
            if (entry.chain == null || entry.chain.length == 0) continue;
            TlsCertificate tlsCert = CertificateBridge.toTls(entry.chain[0]);
            int hlen = tlsCert.getPublicKey().getParams().hlen;
            boolean is256 = hlen == TlsConstants.STREEBOG_256_HASH_LEN;
            if (want256 != is256) continue;
            if (issuers != null && issuers.length > 0 && !issuerMatches(entry.chain[0], issuers)) continue;
            result.add(entry.alias);
        }
        return result;
    }

    /** @return true если сертификат выпущен одним из перечисленных CA */
    private static boolean issuerMatches(X509Certificate cert, Principal[] issuers) {
        X500Principal certIssuer = cert.getIssuerX500Principal();
        for (Principal p : issuers) {
            if (certIssuer.equals(p)) return true;
        }
        return false;
    }

    private String chooseFirst(String[] keyTypes, Principal[] issuers) {
        if (keyTypes == null) return null;
        for (String kt : keyTypes) {
            List<String> aliases = filterAliases(kt, issuers);
            if (!aliases.isEmpty()) return aliases.get(0);
        }
        return null;
    }

    private static final class KeyEntry {
        final String alias;
        final X509Certificate[] chain;
        final PrivateKeyParameters key;

        KeyEntry(String alias, X509Certificate[] chain, PrivateKeyParameters key) {
            this.alias = alias;
            this.chain = chain;
            this.key = key;
        }
    }
}
