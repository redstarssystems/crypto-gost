package org.rssys.gost.tls13;

import org.rssys.gost.signature.ECParameters;

import java.math.BigInteger;

/**
 * Представляет cipher suite TLS 1.3 для ГОСТ-криптографии
 * по RFC 9367: Кузнечик-MGM-Streebog-256.
 * Два варианта: Loop (L) и Seal (S) — отличаются TLSTREE-масками C1/C2/C3 и SNMAX.
 * Оба варианта выполняют per-record ре-кейинг через TLSTREE.
 *
 * <p>Cipher suite определяет AEAD (Kuznyechik-MGM), KDF
 * (HKDF-Streebog-256), хэш (Streebog-256) и константы TLSTREE.
 *
 * <p>По RFC 9367 §4.2 каждый cipher suite имеет свои константы
 * C1/C2/C3 для TLSTREE и SNMAX для ограничения числа записей.
 */
public final class TlsCiphersuite {

    // SNMAX = 2^64-1 (unsigned); хранится как signed -1, сравнивается через Long.compareUnsigned
    private static final long SNMAX_KUZNYECHIK_MGM_L = 0xFFFFFFFFFFFFFFFFL;

    // ========================================================================
    // Предопределённые cipher suite (RFC 9367 §3.1.2)
    // ========================================================================

    public static final TlsCiphersuite TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L = new TlsCiphersuite(
            TlsConstants.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L,
            TlsConstants.STREEBOG_256_HASH_LEN,
            TlsConstants.KUZNYECHIK_KEY_SIZE,
            TlsConstants.MGM_IV_SIZE,
            TlsConstants.MGM_TAG_SIZE,
            SNMAX_KUZNYECHIK_MGM_L,
            0xF800000000000000L,
            0xFFFFFFF000000000L,
            0xFFFFFFFFFFFFE000L,
            BigInteger.ONE);

    public static final TlsCiphersuite TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S = new TlsCiphersuite(
            TlsConstants.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S,
            TlsConstants.STREEBOG_256_HASH_LEN,
            TlsConstants.KUZNYECHIK_KEY_SIZE,
            TlsConstants.MGM_IV_SIZE,
            TlsConstants.MGM_TAG_SIZE,
            0x3FFFFFFFFFFL,
            0xFFFFFFFFE0000000L,
            0xFFFFFFFFFFFF0000L,
            0xFFFFFFFFFFFFFFF8L,
            BigInteger.ONE);

    // ========================================================================
    // Поля
    // ========================================================================

    private final int id;
    private final int hashLen;
    private final int keyLen;
    private final int ivLen;
    private final int tagLen;
    private final long snmax;
    private final long c1;
    private final long c2;
    private final long c3;
    private final BigInteger cofactor;

    private TlsCiphersuite(int id, int hashLen, int keyLen,
                           int ivLen, int tagLen,
                           long snmax, long c1, long c2, long c3,
                           BigInteger cofactor) {
        this.id = id;
        this.hashLen = hashLen;
        this.keyLen = keyLen;
        this.ivLen = ivLen;
        this.tagLen = tagLen;
        this.snmax = snmax;
        this.c1 = c1;
        this.c2 = c2;
        this.c3 = c3;
        this.cofactor = cofactor;
    }

    // ========================================================================
    // Геттеры
    // ========================================================================

    public int getId() { return id; }
    public int getHashLen() { return hashLen; }
    public int getKeyLen() { return keyLen; }
    public int getIvLen() { return ivLen; }
    public int getTagLen() { return tagLen; }
    public long getSnmax() { return snmax; }
    public long getC1() { return c1; }
    public long getC2() { return c2; }
    public long getC3() { return c3; }
    /** @return кофактор кривой (h=1 для всех ГОСТ Р 34.10-2012) */
    public BigInteger getCofactor() { return cofactor; }

    // ========================================================================
    // Поиск по ID
    // ========================================================================

    /**
     * Находит cipher suite по ID (RFC 9367).
     *
     * @param id идентификатор cipher suite (например, 0xC103 или 0xC105)
     * @return экземпляр TlsCiphersuite или null если не найден
     */
    public static TlsCiphersuite byId(int id) {
        if (id == TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L.id) {
            return TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        }
        if (id == TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S.id) {
            return TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S;
        }
        return null;
    }

    /**
     * @return массив всех определённых cipher suite (L и S)
     */
    public static TlsCiphersuite[] values() {
        return new TlsCiphersuite[]{
                TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L,
                TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S
        };
    }

    // ========================================================================
    // Отображение ECParameters ↔ NamedGroup
    // ========================================================================

    /**
     * Отображает ECParameters на идентификатор именованной группы.
     * Сравнение по значению порядка кривой (n.equals), а не по ссылке.
     *
     * @param params параметры эллиптической кривой
     * @return идентификатор именованной группы
     */
    public static int paramsToNamedGroup(ECParameters params) {
        if (params.n.equals(ECParameters.tc26a256().n))   return TlsConstants.GRP_GC256A;
        if (params.n.equals(ECParameters.cryptoProA().n))  return TlsConstants.GRP_GC256B;
        if (params.n.equals(ECParameters.cryptoProB().n))  return TlsConstants.GRP_GC256C;
        if (params.n.equals(ECParameters.cryptoProC().n))  return TlsConstants.GRP_GC256D;
        if (params.n.equals(ECParameters.tc26a512().n))   return TlsConstants.GRP_GC512A;
        if (params.n.equals(ECParameters.tc26b512().n))   return TlsConstants.GRP_GC512B;
        if (params.n.equals(ECParameters.tc26c512().n))   return TlsConstants.GRP_GC512C;
        throw new IllegalArgumentException("Unknown ECParameters");
    }

    /**
     * Отображает именованную группу на ECParameters.
     *
     * @param namedGroup идентификатор именованной группы
     * @return параметры эллиптической кривой
     */
    public static ECParameters namedGroupToParams(int namedGroup) {
        switch (namedGroup) {
            case TlsConstants.GRP_GC256A: return ECParameters.tc26a256();
            case TlsConstants.GRP_GC256B: return ECParameters.cryptoProA();
            case TlsConstants.GRP_GC256C: return ECParameters.cryptoProB();
            case TlsConstants.GRP_GC256D: return ECParameters.cryptoProC();
            case TlsConstants.GRP_GC512A: return ECParameters.tc26a512();
            case TlsConstants.GRP_GC512B: return ECParameters.tc26b512();
            case TlsConstants.GRP_GC512C: return ECParameters.tc26c512();
            default:
                throw new IllegalArgumentException("Unknown named group: 0x" + Integer.toHexString(namedGroup));
        }
    }

    /**
     * Отображает именованную группу на схему подписи (RFC 9367 §5.2).
     *
     * @param namedGroup идентификатор именованной группы
     * @return идентификатор схемы подписи
     */
    public static int namedGroupToSignatureScheme(int namedGroup) {
        switch (namedGroup) {
            case TlsConstants.GRP_GC256A: return TlsConstants.SIG_GOST_TC26_A_256;
            case TlsConstants.GRP_GC256B: return TlsConstants.SIG_GOST_CRYPTOPRO_A;
            case TlsConstants.GRP_GC256C: return TlsConstants.SIG_GOST_CRYPTOPRO_B;
            case TlsConstants.GRP_GC256D: return TlsConstants.SIG_GOST_CRYPTOPRO_C;
            case TlsConstants.GRP_GC512A: return TlsConstants.SIG_GOST_TC26_512_A;
            case TlsConstants.GRP_GC512B: return TlsConstants.SIG_GOST_TC26_512_B;
            case TlsConstants.GRP_GC512C: return TlsConstants.SIG_GOST_TC26_512_C;
            default:
                throw new IllegalArgumentException("Unknown named group: 0x" + Integer.toHexString(namedGroup));
        }
    }

}
