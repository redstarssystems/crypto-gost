package org.rssys.gost.jsse.engine;

import java.util.concurrent.atomic.AtomicReference;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

/**
 * Учёт ошибок двух потоков рукопожатия через {@link InMemoryTlsTransport}: «первая записанная
 * ошибка выигрывает».
 *
 * <p>Упавшая сторона обязана закрыть свой транспорт, иначе вторая ждёт запись до таймаута
 * транспорта (10 с). Закрытие, в свою очередь, роняет вторую сторону ошибкой «Transport
 * closed», которая не является причиной отказа. Поэтому ошибка записывается строго ДО
 * закрытия транспорта: так сторона, убитая закрытием, первой быть не может, а выбор причины не
 * зависит ни от текстов сообщений, ни от порядка, в котором тест проверяет стороны. Контракт
 * обеспечивает единственный метод {@link #recordAndClose}: записать и закрыть нужно им, а не
 * по отдельности.
 */
final class HandshakeFailures {

    static final String SIDE_CLIENT = "Клиент";
    static final String SIDE_SERVER = "Сервер";

    private record Failure(String side, Throwable cause) {}

    private final AtomicReference<Failure> first = new AtomicReference<>();
    private final AtomicReference<Throwable> second = new AtomicReference<>();

    /**
     * Записывает ошибку стороны и только потом закрывает её транспорт.
     *
     * <p>Проигравший поток не трогает исключение победителя: его ошибка складывается в отдельное
     * поле и присоединяется в {@link #throwIfFailed()} главным потоком.
     *
     * @param side      {@link #SIDE_CLIENT} или {@link #SIDE_SERVER}
     * @param error     ошибка рукопожатия этой стороны
     * @param transport транспорт этой стороны; закрытие будит ждущего пира
     */
    void recordAndClose(String side, Throwable error, InMemoryTlsTransport transport) {
        if (!first.compareAndSet(null, new Failure(side, error))) {
            second.compareAndSet(null, error);
        }
        transport.close();
    }

    /**
     * Бросает {@code RuntimeException("<сторона> завершился с ошибкой", причина)} по первой
     * записанной ошибке; вторая ошибка присоединяется как подавленная. Вызывается главным
     * потоком после {@code join}: он гарантирует порядок «сначала запись, потом чтение».
     */
    void throwIfFailed() {
        Failure failure = first.get();
        if (failure == null) {
            return;
        }
        Throwable other = second.get();
        // самоподавление запрещено: addSuppressed(this) бросает IllegalArgumentException
        if (other != null && other != failure.cause()) {
            failure.cause().addSuppressed(other);
        }
        throw new RuntimeException(failure.side() + " завершился с ошибкой", failure.cause());
    }
}
