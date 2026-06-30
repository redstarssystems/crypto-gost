package org.rssys.gost.jca.spec;

import java.util.Collections;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.Map;
import org.rssys.gost.signature.ECParameters;

/**
 * Справочник параметров эллиптических кривых ГОСТ Р 34.10-2012.
 * <p>
 * Сопоставляет короткие мнемонические имена и строки OID с объектами
 * {@link ECParameters}. Используется всеми SPI-классами провайдера для
 * разрешения кривой по имени, переданному через {@link java.security.spec.ECGenParameterSpec}.
 * <p>
 */
public final class GostCurves {

    public static final String OID_TC26_A_256 = "1.2.643.7.1.2.1.1.1";
    public static final String OID_TC26_B_256 = "1.2.643.7.1.2.1.1.2";
    public static final String OID_TC26_C_256 = "1.2.643.7.1.2.1.1.3";
    public static final String OID_TC26_D_256 = "1.2.643.7.1.2.1.1.4";
    public static final String OID_TC26_A_512 = "1.2.643.7.1.2.1.2.1";
    public static final String OID_TC26_B_512 = "1.2.643.7.1.2.1.2.2";
    public static final String OID_TC26_C_512 = "1.2.643.7.1.2.1.2.3";
    public static final String OID_CRYPTOPRO_A = "1.2.643.2.2.35.1";
    public static final String OID_CRYPTOPRO_B = "1.2.643.2.2.35.2";
    public static final String OID_CRYPTOPRO_XCHA = "1.2.643.2.2.36.0";
    public static final String OID_CRYPTOPRO_XCHB = "1.2.643.2.2.38.0";
    public static final String OID_CRYPTOPRO_C = "1.2.643.2.2.35.3";

    public static final String OID_SIGN_256 = "1.2.643.7.1.1.1.1";
    public static final String OID_SIGN_512 = "1.2.643.7.1.1.1.2";

    /** Неизменяемый реестр: имя или OID-строка -> параметры кривой. */
    private static final Map<String, ECParameters> REGISTRY;

    /** Канонический OID для каждого синглтона ECParameters (IdentityHashMap, сравнение по ссылке). */
    private static final Map<ECParameters, String> CANONICAL_OID;

    static {
        HashMap<String, ECParameters> map = new HashMap<>();
        IdentityHashMap<ECParameters, String> oid = new IdentityHashMap<>();

        ECParameters tc26a256 = ECParameters.tc26a256();
        map.put("tc26-gost-A-256", tc26a256);
        map.put(OID_TC26_A_256, tc26a256);
        oid.put(tc26a256, OID_TC26_A_256);

        ECParameters tc26a512 = ECParameters.tc26a512();
        map.put("tc26-gost-A-512", tc26a512);
        map.put(OID_TC26_A_512, tc26a512);
        oid.put(tc26a512, OID_TC26_A_512);

        ECParameters tc26b512 = ECParameters.tc26b512();
        map.put("tc26-gost-B-512", tc26b512);
        map.put(OID_TC26_B_512, tc26b512);
        oid.put(tc26b512, OID_TC26_B_512);

        ECParameters tc26c512 = ECParameters.tc26c512();
        map.put("tc26-gost-C-512", tc26c512);
        map.put(OID_TC26_C_512, tc26c512);
        oid.put(tc26c512, OID_TC26_C_512);

        ECParameters cpa = ECParameters.cryptoProA();
        map.put("cryptopro-A", cpa);
        map.put(OID_CRYPTOPRO_A, cpa);
        oid.put(cpa, OID_CRYPTOPRO_A);

        ECParameters cpb = ECParameters.cryptoProB();
        map.put("cryptopro-B", cpb);
        map.put(OID_CRYPTOPRO_B, cpb);
        oid.put(cpb, OID_CRYPTOPRO_B);

        ECParameters cpc = ECParameters.cryptoProC();
        map.put("cryptopro-C", cpc);
        map.put(OID_CRYPTOPRO_C, cpc);
        oid.put(cpc, OID_CRYPTOPRO_C);

        // XchA/XchB (RFC 4357) — те же кривые, что CryptoPro A/B, но OID для key exchange.
        // ФНС выпускает сертификаты с XchA. XchB зарегистрирован для симметрии.
        map.put(OID_CRYPTOPRO_XCHA, cpa);
        map.put(OID_CRYPTOPRO_XCHB, cpb);

        // TC26 256-bit ParamSet B/C/D — те же кривые, что CryptoPro A/B/C (RFC 7836, назначение OID
        // в TC26).
        // Эти алиасы регистрируются только в REGISTRY для byName()-lookup.
        // В CANONICAL_OID НЕ добавляются — oidOf() всегда вернёт исходный CryptoPro OID.
        map.put(OID_TC26_B_256, cpa);
        map.put(OID_TC26_C_256, cpb);
        map.put(OID_TC26_D_256, cpc);

        REGISTRY = Collections.unmodifiableMap(map);
        CANONICAL_OID = Collections.unmodifiableMap(oid);
    }

    private GostCurves() {}

    /**
     * Возвращает параметры кривой по короткому имени или строке OID.
     * <p>
     * Поиск регистронезависим для имён, OID передаются как есть.
     *
     * @param nameOrOid короткое имя (например, {@code "cryptopro-A"}) или OID
     * @return параметры кривой
     * @throws IllegalArgumentException если имя/OID не найдены в реестре
     */
    public static ECParameters byName(String nameOrOid) {
        if (nameOrOid == null) {
            throw new IllegalArgumentException("Curve name must not be null");
        }
        // Ищем как есть (OID), затем в нижнем регистре (имя)
        ECParameters params = REGISTRY.get(nameOrOid);
        if (params == null) {
            params = REGISTRY.get(nameOrOid.toLowerCase());
        }
        if (params == null) {
            throw new IllegalArgumentException("Unknown GOST curve: " + nameOrOid);
        }
        return params;
    }

    /**
     * Возвращает канонический OID кривой по её параметрам.
     * Используется при DER-кодировании открытого/закрытого ключа.
     * <p>
     * Гарантируется, что для CryptoPro-A/B/C возвращается CryptoPro OID,
     * а не TC26-алиас.
     *
     * @param params параметры кривой
     * @return строка OID
     * @throws IllegalArgumentException если параметры не соответствуют ни одной известной кривой
     */
    public static String oidOf(ECParameters params) {
        if (params == null) {
            throw new IllegalArgumentException("ECParameters must not be null");
        }
        String oid = CANONICAL_OID.get(params);
        if (oid == null) {
            throw new IllegalArgumentException("Unknown ECParameters: cannot determine OID");
        }
        return oid;
    }

    /**
     * Проверяет, является ли строка поддерживаемым именем или OID кривой.
     *
     * @param nameOrOid имя или OID
     * @return {@code true} если кривая поддерживается
     */
    public static boolean isSupported(String nameOrOid) {
        if (nameOrOid == null) return false;
        return REGISTRY.containsKey(nameOrOid) || REGISTRY.containsKey(nameOrOid.toLowerCase());
    }
}
