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
     * Клиент доверяет любому серверу — создаёт MITM-уязвимость.
     * <b>Только для разработки и изолированных сетей.</b>
     * Для production используйте {@link GostSsl#clientContext(byte[])}.
     */
    public static SSLContext trustAllClientContextInsecure() {
        return GostSsl.buildContext(null, null, null, null,
                null, false, -1, true, false);
    }
}
