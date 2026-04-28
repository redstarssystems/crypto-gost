package org.rssys.gost.jca.spec;

import org.rssys.gost.signature.ECParameters;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Справочник параметров эллиптических кривых ГОСТ Р 34.10-2012.
 * <p>
 * Сопоставляет короткие мнемонические имена и строки OID с объектами
 * {@link ECParameters}. Используется всеми SPI-классами провайдера для
 * разрешения кривой по имени, переданному через {@link java.security.spec.ECGenParameterSpec}.
 * <p>
 */
public final class GostCurves {

    public static final String OID_TC26_A_256 = "1.2.643.7.1.2.1.2.1";
    public static final String OID_TC26_A_512 = "1.2.643.7.1.2.1.1.1";
    public static final String OID_TC26_B_512 = "1.2.643.7.1.2.1.1.2";
    public static final String OID_TC26_C_512 = "1.2.643.7.1.2.1.1.3";
    public static final String OID_CRYPTOPRO_A = "1.2.643.2.2.35.1";
    public static final String OID_CRYPTOPRO_B = "1.2.643.2.2.35.2";
    public static final String OID_CRYPTOPRO_C = "1.2.643.2.2.35.3";


    public static final String OID_SIGN_256 = "1.2.643.7.1.1.1.1";
    public static final String OID_SIGN_512 = "1.2.643.7.1.1.1.2";

    /** Неизменяемый реестр: имя или OID-строка → параметры кривой. */
    private static final Map<String, ECParameters> REGISTRY;

    static {
        Map<String, ECParameters> map = new HashMap<>();


        ECParameters tc26a256 = ECParameters.tc26a256();
        map.put("tc26-gost-A-256",  tc26a256);
        map.put(OID_TC26_A_256,     tc26a256);


        ECParameters tc26a512 = ECParameters.tc26a512();
        map.put("tc26-gost-A-512",  tc26a512);
        map.put(OID_TC26_A_512,     tc26a512);

        ECParameters tc26b512 = ECParameters.tc26b512();
        map.put("tc26-gost-B-512",  tc26b512);
        map.put(OID_TC26_B_512,     tc26b512);

        ECParameters tc26c512 = ECParameters.tc26c512();
        map.put("tc26-gost-C-512",  tc26c512);
        map.put(OID_TC26_C_512,     tc26c512);

        ECParameters cpa = ECParameters.cryptoProA();
        map.put("cryptopro-A",      cpa);
        map.put(OID_CRYPTOPRO_A,    cpa);

        ECParameters cpb = ECParameters.cryptoProB();
        map.put("cryptopro-B",      cpb);
        map.put(OID_CRYPTOPRO_B,    cpb);

        ECParameters cpc = ECParameters.cryptoProC();
        map.put("cryptopro-C",      cpc);
        map.put(OID_CRYPTOPRO_C,    cpc);

        REGISTRY = Collections.unmodifiableMap(map);
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
     * Возвращает OID кривой по её параметрам.
     * Используется при DER-кодировании открытого/закрытого ключа.
     *
     * @param params параметры кривой
     * @return строка OID
     * @throws IllegalArgumentException если параметры не соответствуют ни одной известной кривой
     */
    public static String oidOf(ECParameters params) {
        if (params == null) {
            throw new IllegalArgumentException("ECParameters must not be null");
        }
        // Сравниваем по модулю p как быстрый дискриминатор
        for (Map.Entry<String, ECParameters> entry : REGISTRY.entrySet()) {
            String key = entry.getKey();
            // Пропускаем имена — берём только OID-строки (содержат точку)
            if (key.contains(".") && entry.getValue().p.equals(params.p)
                    && entry.getValue().n.equals(params.n)
                    && entry.getValue().gx.equals(params.gx)) {
                return key;
            }
        }
        throw new IllegalArgumentException("Unknown ECParameters: cannot determine OID");
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
