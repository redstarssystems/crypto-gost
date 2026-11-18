package org.rssys.gost.jca.spec;

import java.util.Collections;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.Locale;
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
    public static final String OID_CRYPTOPRO_XCHB = "1.2.643.2.2.36.1";
    public static final String OID_CRYPTOPRO_C = "1.2.643.2.2.35.3";

    public static final String OID_SIGN_256 = "1.2.643.7.1.1.1.1";
    public static final String OID_SIGN_512 = "1.2.643.7.1.1.1.2";

    /** Неизменяемый реестр: имя (в нижнем регистре) или OID-строка -> параметры кривой. */
    private static final Map<String, ECParameters> REGISTRY;

    /** Канонический OID для каждого синглтона ECParameters (IdentityHashMap, сравнение по ссылке). */
    private static final Map<ECParameters, String> CANONICAL_OID;

    static {
        HashMap<String, ECParameters> map = new HashMap<>();
        IdentityHashMap<ECParameters, String> oid = new IdentityHashMap<>();

        ECParameters tc26a256 = ECParameters.tc26a256();
        map.put("tc26-gost-a-256", tc26a256);
        map.put(OID_TC26_A_256, tc26a256);
        oid.put(tc26a256, OID_TC26_A_256);

        ECParameters tc26a512 = ECParameters.tc26a512();
        map.put("tc26-gost-a-512", tc26a512);
        map.put(OID_TC26_A_512, tc26a512);
        oid.put(tc26a512, OID_TC26_A_512);

        ECParameters tc26b512 = ECParameters.tc26b512();
        map.put("tc26-gost-b-512", tc26b512);
        map.put(OID_TC26_B_512, tc26b512);
        oid.put(tc26b512, OID_TC26_B_512);

        ECParameters tc26c512 = ECParameters.tc26c512();
        map.put("tc26-gost-c-512", tc26c512);
        map.put(OID_TC26_C_512, tc26c512);
        oid.put(tc26c512, OID_TC26_C_512);

        ECParameters cpa = ECParameters.cryptoProA();
        map.put("cryptopro-a", cpa);
        map.put(OID_CRYPTOPRO_A, cpa);
        oid.put(cpa, OID_CRYPTOPRO_A);

        ECParameters cpb = ECParameters.cryptoProB();
        map.put("cryptopro-b", cpb);
        map.put(OID_CRYPTOPRO_B, cpb);
        oid.put(cpb, OID_CRYPTOPRO_B);

        ECParameters cpc = ECParameters.cryptoProC();
        map.put("cryptopro-c", cpc);
        map.put(OID_CRYPTOPRO_C, cpc);
        oid.put(cpc, OID_CRYPTOPRO_C);

        // XchA/XchB (RFC 4357 §11.4) — OID для key exchange: XchA задаёт те же параметры, что
        // CryptoPro A, XchB — те же, что CryptoPro C (не B). ФНС выпускает сертификаты с XchA.
        map.put(OID_CRYPTOPRO_XCHA, cpa);
        map.put(OID_CRYPTOPRO_XCHB, cpc);

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

    /**
     * Правило присутствия {@code digestParamSet} в {@code GostR3410-2012-PublicKeyParameters}
     * (RFC 9215 §4.2). Зависит от OID набора параметров в том виде, как он записан в SPKI:
     * XchA и TC26-B-256 описывают одну кривую, но правила для них противоположны.
     */
    public enum DigestParamSetPolicy {
        /** Обязателен и равен Стрибог-256 (наборы CryptoPro A/B/C, XchA, XchB). */
        REQUIRED,
        /** Обязан отсутствовать (наборы TC26 B/C/D-256). */
        FORBIDDEN,
        /** Допустимы оба варианта; при наличии равен Стрибогу нужного размера (TC26 A-256, 512 A/B/C). */
        OPTIONAL
    }

    /** OID набора параметров -> правило {@code digestParamSet}; ключ — строка OID, не имя. */
    private static final Map<String, DigestParamSetPolicy> DIGEST_POLICY;

    static {
        HashMap<String, DigestParamSetPolicy> policy = new HashMap<>();
        for (String oid :
                new String[] {
                    OID_CRYPTOPRO_A,
                    OID_CRYPTOPRO_B,
                    OID_CRYPTOPRO_C,
                    OID_CRYPTOPRO_XCHA,
                    OID_CRYPTOPRO_XCHB
                }) {
            policy.put(oid, DigestParamSetPolicy.REQUIRED);
        }
        for (String oid : new String[] {OID_TC26_B_256, OID_TC26_C_256, OID_TC26_D_256}) {
            policy.put(oid, DigestParamSetPolicy.FORBIDDEN);
        }
        for (String oid :
                new String[] {OID_TC26_A_256, OID_TC26_A_512, OID_TC26_B_512, OID_TC26_C_512}) {
            policy.put(oid, DigestParamSetPolicy.OPTIONAL);
        }
        DIGEST_POLICY = Collections.unmodifiableMap(policy);
    }

    private GostCurves() {}

    /**
     * Возвращает правило присутствия {@code digestParamSet} для набора параметров по его OID.
     * <p>
     * Правило нельзя вывести из {@link ECParameters}: {@link #byName(String)} сводит XchA,
     * CryptoPro-A и TC26-B-256 к одному объекту, поэтому вызывать нужно с исходной строкой OID
     * из SPKI.
     *
     * @param curveOid OID набора параметров из {@code publicKeyParamSet}
     * @return правило для этого OID
     * @throws IllegalArgumentException если OID не из реестра
     */
    public static DigestParamSetPolicy digestPolicyOf(String curveOid) {
        DigestParamSetPolicy policy = curveOid == null ? null : DIGEST_POLICY.get(curveOid);
        if (policy == null) {
            throw new IllegalArgumentException("Unknown GOST curve OID: " + curveOid);
        }
        return policy;
    }

    /**
     * Возвращает параметры кривой по короткому имени или строке OID.
     * <p>
     * Запрос приводится к нижнему регистру ({@code Locale.ROOT}), поэтому имена находятся в любом
     * регистре; для OID (цифры и точки) приведение ничего не меняет.
     *
     * @param nameOrOid короткое имя (например, {@code "cryptopro-A"}) или OID
     * @return параметры кривой
     * @throws IllegalArgumentException если имя/OID не найдены в реестре
     */
    public static ECParameters byName(String nameOrOid) {
        if (nameOrOid == null) {
            throw new IllegalArgumentException("Curve name must not be null");
        }
        // Ключи реестра: OID (цифры и точки) и имена в нижнем регистре; приведение регистра
        // OID не меняет. Locale.ROOT: иначе в турецкой локали «I» стало бы «ı».
        ECParameters params = REGISTRY.get(nameOrOid.toLowerCase(Locale.ROOT));
        if (params == null) {
            throw new IllegalArgumentException("Unknown GOST curve: " + nameOrOid);
        }
        return params;
    }

    /**
     * Возвращает канонический OID кривой.
     * Используется при DER-кодировании открытого/закрытого ключа.
     * <p>
     * OID есть только у зарегистрированных экземпляров: полученных из фабрик
     * {@code ECParameters.*()} и {@link #byName(String)} (разбор DER идёт через реестр, поэтому
     * возвращает тот же экземпляр). Сравнение идёт по ссылке, а не по значению: созданная вручную
     * копия, равная зарегистрированной кривой по {@code ECParameters.equals}, OID не получает и в
     * DER не кодируется (вычисления с ней работают). Так сделано сознательно, см.
     * {@code ECParameters.equals}.
     * <p>
     * Гарантируется, что для CryptoPro-A/B/C возвращается CryptoPro OID, а не TC26-алиас.
     * Алиасы TC26 B/C/D-256, XchA и XchB канонизируются в CryptoPro OID: XchA даёт
     * {@link #OID_CRYPTOPRO_A}, XchB - {@link #OID_CRYPTOPRO_C}. Ключ, разобранный с OID XchB,
     * при повторном кодировании получает OID CryptoPro-C (параметры те же).
     *
     * @param params параметры кривой
     * @return строка OID
     * @throws IllegalArgumentException если {@code params == null} или экземпляр не
     *     зарегистрирован (в том числе копия зарегистрированной кривой по значению)
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
        return REGISTRY.containsKey(nameOrOid.toLowerCase(Locale.ROOT));
    }
}
