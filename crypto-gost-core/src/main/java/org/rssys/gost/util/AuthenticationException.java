package org.rssys.gost.util;

/**
 * Исключение, бросаемое при нарушении целостности данных в процессе
 * аутентифицированного расшифрования.
 *
 * <p>Возникает когда CMAC-тег, вычисленный при расшифровании, не совпадает
 * с тегом из пакета. Это означает одно из:
 * <ul>
 *   <li>Данные были изменены (активная атака)</li>
 *   <li>Использован неверный ключ</li>
 *   <li>Пакет повреждён при передаче</li>
 *   <li>Поток был усечён (truncation attack)</li>
 * </ul>
 *
 * <p>Является checked exception: вызывающий код обязан явно обработать
 * нарушение целостности.
 */
public class AuthenticationException extends Exception {

    public AuthenticationException(String message) {
        super(message);
    }

    public AuthenticationException(String message, Throwable cause) {
        super(message, cause);
    }
}
