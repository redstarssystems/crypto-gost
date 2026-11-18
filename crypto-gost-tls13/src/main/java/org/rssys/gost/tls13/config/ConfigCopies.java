package org.rssys.gost.tls13.config;

import java.util.ArrayList;
import java.util.List;
import org.rssys.gost.tls13.TlsUtils;

/**
 * Защитное копирование данных, которые приложение передаёт в конфигурации.
 * <p>
 * Конфигурация живёт дольше вызова сеттера и читается из других потоков, поэтому она хранит
 * неизменяемые копии. Проверка выполняется над той же копией, которая затем сохраняется: иначе
 * вызывающий успел бы изменить исходный список между проверкой и копированием.
 */
final class ConfigCopies {

    private ConfigCopies() {}

    /**
     * Неизменяемая копия списка без {@code null}-элементов.
     *
     * @param source исходный список или {@code null}
     * @param name   имя параметра для сообщения об ошибке
     * @return неизменяемая копия, или {@code null}, если {@code source == null}
     * @throws IllegalArgumentException если в списке есть {@code null}-элемент
     */
    static <T> List<T> immutableCopy(List<T> source, String name) {
        if (source == null) {
            return null;
        }
        // Копия обычным списком допускает null: ошибку даёт наша проверка, а не List.copyOf
        List<T> snapshot = new ArrayList<>(source);
        for (T element : snapshot) {
            if (element == null) {
                throw new IllegalArgumentException(name + " must not contain null elements");
            }
        }
        return List.copyOf(snapshot);
    }

    /**
     * Неизменяемая копия списка протоколов ALPN, проверенная {@link TlsUtils#validateAlpnProtocols}.
     *
     * @param protocols исходный список протоколов
     * @return неизменяемая копия
     * @throws IllegalArgumentException если список не проходит проверку
     */
    static List<String> validatedAlpnCopy(List<String> protocols) {
        if (protocols == null) {
            throw new IllegalArgumentException("ALPN protocol list must not be null or empty");
        }
        List<String> snapshot = new ArrayList<>(protocols);
        TlsUtils.validateAlpnProtocols(snapshot);
        return List.copyOf(snapshot);
    }

    /**
     * Копия OCSP-ответа, проверенная {@link TlsUtils#validateOcspResponse}.
     *
     * @param ocspResponse OCSPResponse DER или {@code null}
     * @return копия или {@code null}
     * @throws IllegalArgumentException если массив пуст или слишком длинный
     */
    static byte[] validatedOcspCopy(byte[] ocspResponse) {
        // Сначала копия, потом проверка копии: проверка исходного массива оставила бы окно, в
        // котором вызывающий изменил бы его до копирования. Лишняя аллокация под отвергаемый
        // массив (не больше предела OCSP-ответа) дешевле этого окна
        byte[] copy = ocspResponse == null ? null : ocspResponse.clone();
        TlsUtils.validateOcspResponse(copy);
        return copy;
    }

    /** Копия массива для геттера: наружу не уходит изменяемое внутреннее состояние. */
    static byte[] copyOrNull(byte[] value) {
        return value == null ? null : value.clone();
    }
}
