package org.rssys.gost.pkix;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Сигнализирует, что возвращаемое значение метода не должно игнорироваться.
 * Игнорирование возврата может привести к пропуску ошибок верификации —
 * сертификат/CSR будут считаться валидными без проверки.
 *
 * <p>Применяется к методам верификации, возвращающим {@code boolean},
 * а также к статическим фабрикам и методам с побочным эффектом, чей
 * возврат критичен для корректности вызывающего кода.</p>
 *
 * <p>Статические анализаторы (Error Prone, SpotBugs) могут использовать
 * эту аннотацию для предупреждений на уровне компиляции.</p>
 */
@Retention(RetentionPolicy.CLASS)
@Target({ElementType.METHOD, ElementType.CONSTRUCTOR})
public @interface CheckReturnValue {}
