package org.rssys.gost.jsse;

import javax.net.ssl.SSLContext;

/**
 * Dev/тестовые утилиты {@link GostSsl} — <b>НЕ для production</b>.
 * <p>
 * Содержит упрощённые контексты для разработки, тестирования
 * и изолированных сетей. При code-review импорт этого класса
 * сразу сигнализирует о dev-намерении.
 */
public final class GostSslDev {

    private GostSslDev() {}

    /**
     * Клиентский SSLContext без проверки сертификата сервера.
     * <p>
     * Клиент доверяет любому серверу: подлинность сервера не проверяется.
     * <b>Только для разработки и изолированных сетей.</b>
     * Для production используйте {@link GostSsl#clientContext(byte[])}.
     */
    public static SSLContext trustAllClientContextInsecure() {
        return GostSsl.builder().trustAll().buildClientContext();
    }

    /**
     * Клиентский SSLContext без проверки сертификата сервера
     * И без проверки hostname (RFC 6125).
     * <p>
     * Отключает ОБА уровня: chain validation (CA) и hostname verification.
     * Подлинность и имя сервера не проверяются — только для разработки и изолированных сетей.
     * Для production используйте {@link GostSsl#clientContext(byte[])}.
     */
    public static SSLContext trustAllNoHostnameCheckInsecure() {
        return GostSsl.builder().trustAll().withoutHostnameVerification().buildClientContext();
    }
}
