package org.rssys.gost.crossval.util;

import java.util.Map;

/**
 * Проверка доступа к графической (X) сессии.
 *
 * <p>Установка и удаление корня в {@code uRoot} требует соединения с X-сервером (окно
 * подтверждения), но не ответа оператора. Без {@code DISPLAY} и {@code XAUTHORITY} {@code certmgr}
 * отвечает {@code 0x80090020}. Раньше это путали с «нужен диалог у оператора», когда запуск шёл
 * через ssh.
 */
public final class XSession {

    /** Код ошибки КриптоПро, который {@code certmgr} даёт без доступа к X-серверу. */
    public static final String NO_X_ERROR_CODE = "0x80090020";

    private XSession() {}

    /**
     * Убеждается, что заданы оба параметра доступа к X-серверу.
     *
     * @param environment переменные окружения процесса
     * @throws IllegalStateException если нет {@code DISPLAY} или {@code XAUTHORITY}
     */
    public static void require(Map<String, String> environment) {
        if (isBlank(environment.get("DISPLAY")) || isBlank(environment.get("XAUTHORITY"))) {
            throw new IllegalStateException(noAccessMessage());
        }
    }

    /** @return сообщение об отсутствии доступа к X-сессии (общее для проверки и кода 0x80090020) */
    public static String noAccessMessage() {
        return "No access to the X session: set DISPLAY and XAUTHORITY (run from the graphical"
                + " session, not from plain ssh); certmgr needs it to change uRoot";
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
