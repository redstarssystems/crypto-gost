package org.rssys.gost.jsse.manager;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.security.auth.x500.X500Principal;
import org.rssys.gost.jca.key.GostECPrivateKey;
import org.rssys.gost.jsse.GostJsseConstants;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.cert.TlsCertUtils;
import org.rssys.gost.tls13.config.ClientCertificateSelector;
import org.rssys.gost.tls13.config.OIDFilter;
import org.rssys.gost.tls13.config.SniCertificateSelector;
import org.rssys.gost.tls13.config.TlsClientCredentials;
import org.rssys.gost.tls13.config.TlsServerCredentials;

/**
 * X509KeyManager для ГОСТ-ключей.
 * <p>
 * Фильтрация по keyType (256/512), выбор по hostname (SAN dNSName), SNI-селектор.
 */
public final class GostX509KeyManager extends X509ExtendedKeyManager {

    // Длина хэша ключа, которую задаёт тип; два служебных значения не совпадают ни с одной длиной
    private static final int KEY_TYPE_UNSUPPORTED = -1;
    private static final int KEY_TYPE_ANY_SIZE = 0;

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
    public String chooseEngineClientAlias(
            String[] keyTypes, Principal[] issuers, SSLEngine engine) {
        return chooseFirst(keyTypes, issuers);
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return getClientAliases(keyType, issuers);
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        return chooseFirst(new String[] {keyType}, issuers);
    }

    @Override
    public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
        return chooseFirst(new String[] {keyType}, issuers);
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        KeyEntry entry = findEntry(alias);
        return entry != null && entry.chain != null ? entry.chain.clone() : null;
    }

    private KeyEntry findEntry(String alias) {
        for (KeyEntry entry : entries) {
            if (entry.alias.equals(alias)) {
                return entry;
            }
        }
        return null;
    }

    /**
     * Конвертирует цепочку JCA-сертификатов в формат tls13-ядра
     * для передачи в SniCertificateSelector.
     *
     * @param alias алиас записи
     * @return цепочка GostCertificate, или null если алиас не найден
     */
    public List<GostCertificate> getCertificateChainTls(String alias) {
        KeyEntry entry = findEntry(alias);
        return entry != null ? entry.tlsChain : null;
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
        KeyEntry entry = findEntry(alias);
        return entry != null ? entry.key : null;
    }

    @Override
    public PrivateKey getPrivateKey(String alias) {
        KeyEntry entry = findEntry(alias);
        return entry != null && entry.key != null ? new GostECPrivateKey(entry.key) : null;
    }

    /**
     * Ищет алиас, чей сертификат соответствует имени по правилам RFC 6125
     * ({@link GostCertificate#verifyHostname}).
     * <p>
     * Только SAN (dNSName и iPAddress), без fallback на CN. Допустим wildcard {@code *.example.com}
     * (одна метка слева), IDN сравнивается в A-label. Нормализация имени (регистр, пробелы,
     * завершающая точка) та же, что при проверке сертификата сервера, поэтому выбор сертификата
     * по SNI и его последующая проверка клиентом согласованы.
     *
     * @param hostname имя для поиска (null -> первый алиас)
     * @return алиас или null
     */
    public String chooseAliasForHostname(String hostname) {
        if (hostname == null) {
            return entries.isEmpty() ? null : entries.get(0).alias;
        }
        for (KeyEntry entry : entries) {
            List<GostCertificate> chain = entry.tlsChain;
            if (chain != null && !chain.isEmpty() && chain.get(0).verifyHostname(hostname)) {
                return entry.alias;
            }
        }
        return null;
    }

    /**
     * Создаёт SniCertificateSelector на основе этого KeyManager.
     * Вызывается сервером при инициализации handshake.
     */
    public SniCertificateSelector asSniSelector() {
        return serverName -> {
            String alias = chooseAliasForHostname(serverName);
            if (alias == null) return null;
            List<GostCertificate> chain = getCertificateChainTls(alias);
            PrivateKeyParameters key = getPrivateKeyParams(alias);
            if (chain == null || key == null) return null;
            return new TlsServerCredentials(chain, key, null);
        };
    }

    /**
     * Создаёт ClientCertificateSelector на основе этого KeyManager.
     * Вызывается клиентом на каждый CertificateRequest и выбирает сертификат по запросу сервера.
     * <p>
     * Запись отбирается, если одновременно:
     * <ul>
     *   <li>лист удовлетворяет всем OID-фильтрам (RFC 8446 §4.2.5);</li>
     *   <li>при непустом списке certificate_authorities издатель какого-либо сертификата цепочки
     *       входит в него (§4.2.4). Пустой список означает «CA не указаны», по нему не
     *       фильтруем. Фильтр жёсткий: иначе клиент отправил бы сертификат, который сервер
     *       заведомо не примет;</li>
     *   <li>схема ключа листа входит в signature_algorithms сервера (§4.4.3).</li>
     * </ul>
     * Среди подошедших предпочитается запись, подписи цепочки которой тоже входят в
     * signature_algorithms_cert (§4.2.3); иначе берётся первая подошедшая. Если не подошла ни
     * одна, возвращается {@code null}, то есть клиент отправит пустой Certificate (§4.4.2.3).
     */
    public ClientCertificateSelector asClientCertificateSelector() {
        return request -> {
            boolean filterByAuthorities = !request.caDns().isEmpty();
            // DN разбираются один раз на запрос; ни один не разобрался - совпадений нет, а
            // не «CA не указаны»: фильтр жёсткий
            List<X500Principal> authorities = parseAuthorities(request.caDns());
            int[] leafSchemes = request.signatureSchemes();
            int[] chainSchemes = request.certificateSignatureSchemes();
            TlsClientCredentials firstFit = null;
            for (KeyEntry entry : entries) {
                List<GostCertificate> chain = entry.tlsChain;
                if (chain == null || chain.isEmpty() || entry.key == null) continue;
                if (!matchesOidFilters(chain.get(0), request.oidFilters())) continue;
                if (filterByAuthorities && !issuedByAny(entry.chain, authorities)) continue;
                if (!leafSchemeOffered(chain, leafSchemes)) continue;
                TlsClientCredentials credentials = new TlsClientCredentials(chain, entry.key);
                if (chainSchemesOffered(chain, chainSchemes)) {
                    return credentials;
                }
                if (firstFit == null) firstFit = credentials;
            }
            return firstFit;
        };
    }

    private static boolean matchesOidFilters(GostCertificate leaf, List<OIDFilter> filters) {
        for (OIDFilter filter : filters) {
            if (!TlsCertUtils.matchesOidFilter(leaf, filter)) return false;
        }
        return true;
    }

    /**
     * Разбирает DN удостоверяющих центров в канонические X500Principal (как в issuerMatches).
     * DN приходят от сервера: с неверной DER-структурой он пропускается как не совпавший, а не
     * превращается в исключение селектора (то есть в internal_error по вине пира).
     */
    private static List<X500Principal> parseAuthorities(List<byte[]> caDns) {
        List<X500Principal> result = new ArrayList<>(caDns.size());
        for (byte[] dn : caDns) {
            try {
                result.add(new X500Principal(dn));
            } catch (IllegalArgumentException e) {
                // непарсируемый DN не может совпасть с издателем
            }
        }
        return result;
    }

    private static boolean issuedByAny(X509Certificate[] chain, List<X500Principal> authorities) {
        for (X509Certificate certificate : chain) {
            if (authorities.contains(certificate.getIssuerX500Principal())) return true;
        }
        return false;
    }

    /**
     * Все подписи цепочки предложены сервером. Незнакомая кривая в цепочке не превращается в
     * исключение селектора: запись просто не предпочитается, но остаётся кандидатом.
     */
    private static boolean chainSchemesOffered(List<GostCertificate> chain, int[] offered) {
        try {
            return TlsCertUtils.unofferedChainSchemes(chain, offered).isEmpty();
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /** Схема ключа листа входит в список сервера; кривая, которую не знаем, - не входит. */
    private static boolean leafSchemeOffered(List<GostCertificate> chain, int[] offered) {
        try {
            return TlsCertUtils.isSchemeOffered(offered, TlsCertUtils.leafSignatureScheme(chain));
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * Фильтрует алиасы по keyType и issuers.
     * keyType: {@code ECGOST3410-2012-256}, {@code ECGOST3410-2012-512} либо общий
     * {@code ECGOST3410-2012} (подходит ключ любого размера). Прочие типы не подходят.
     * Если issuers != null и не пуст — отбирает только сертификаты,
     * выпущенные одним из перечисленных CA (сравнение issuer X500Principal).
     */
    private List<String> filterAliases(String keyType, Principal[] issuers) {
        int wantedHashLen = hashLenOfKeyType(keyType);
        if (wantedHashLen == KEY_TYPE_UNSUPPORTED) return Collections.emptyList();

        List<String> result = new ArrayList<>();
        for (KeyEntry entry : entries) {
            if (entry.chain == null || entry.chain.length == 0) continue;
            if (wantedHashLen != KEY_TYPE_ANY_SIZE && wantedHashLen != entry.hlen) continue;
            if (issuers != null && issuers.length > 0 && !issuerMatches(entry.chain[0], issuers))
                continue;
            result.add(entry.alias);
        }
        return result;
    }

    private static int hashLenOfKeyType(String keyType) {
        if (GostJsseConstants.KEY_ALG_ECGOST_2012.equals(keyType)) return KEY_TYPE_ANY_SIZE;
        if (GostJsseConstants.KEY_TYPE_ECGOST_256.equals(keyType)) {
            return TlsConstants.STREEBOG_256_HASH_LEN;
        }
        if (GostJsseConstants.KEY_TYPE_ECGOST_512.equals(keyType)) {
            return TlsConstants.STREEBOG_512_HASH_LEN;
        }
        return KEY_TYPE_UNSUPPORTED;
    }

    /** @return true если сертификат выпущен одним из перечисленных CA */
    private static boolean issuerMatches(X509Certificate cert, Principal[] issuers) {
        X500Principal certIssuer = cert.getIssuerX500Principal();
        for (Principal p : issuers) {
            if (certIssuer.equals(p)) return true;
        }
        return false;
    }

    /** Первый подходящий алиас по списку типов ключей в порядке предпочтения; иначе null. */
    private String chooseFirst(String[] keyTypes, Principal[] issuers) {
        if (keyTypes == null) return null;
        for (String keyType : keyTypes) {
            List<String> aliases = filterAliases(keyType, issuers);
            if (!aliases.isEmpty()) return aliases.get(0);
        }
        return null;
    }

    private static final class KeyEntry {
        final String alias;
        final X509Certificate[] chain;
        final PrivateKeyParameters key;

        /** Длина хэша ключа листа; -1, если цепочки нет. */
        final int hlen;

        /** Цепочка в формате ядра; собирается один раз, неизменяема. {@code null}, если цепочки нет. */
        final List<GostCertificate> tlsChain;

        KeyEntry(String alias, X509Certificate[] chain, PrivateKeyParameters key) {
            this.alias = alias;
            // Копия: цепочка разбирается один раз (hlen, tlsChain), и изменение входного массива
            // вызывающим кодом рассинхронизировало бы запись
            this.chain = chain != null ? chain.clone() : null;
            this.key = key;
            if (this.chain != null && this.chain.length > 0) {
                this.tlsChain = List.copyOf(CertificateBridge.toGost(this.chain));
                this.hlen = tlsChain.get(0).getPublicKey().getParams().hlen;
            } else {
                this.tlsChain = null;
                this.hlen = -1;
            }
        }
    }
}
