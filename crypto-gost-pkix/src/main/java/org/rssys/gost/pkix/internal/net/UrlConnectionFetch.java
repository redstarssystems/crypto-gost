package org.rssys.gost.pkix.internal.net;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.URLConnection;
import java.time.Duration;
import org.rssys.gost.pkix.internal.net.FetchOutcome.Failure;
import org.rssys.gost.pkix.util.BodyTooLargeException;
import org.rssys.gost.pkix.util.BoundedBodyReader;
import org.rssys.gost.pkix.util.Deadline;
import org.rssys.gost.pkix.util.DeadlineExceededException;
import org.rssys.gost.pkix.util.DeadlineWatchdog;
import org.rssys.gost.util.GostLogger;
import org.rssys.gost.util.GostLogger.Level;
import org.rssys.gost.util.SafeText;

/**
 * Загрузка по HTTP на {@link HttpURLConnection} (Android-совместимый вариант) с одним общим
 * сроком на весь запрос.
 *
 * <p>Сторож {@link DeadlineWatchdog} защищает только соединение и заголовки и закрывается до
 * чтения тела: {@code disconnect()} во время чтения тела блокируется, пока читатель не дочитает
 * поток. Срок тела проверяется между чтениями ({@link BoundedBodyReader}); перерасход не больше
 * одного чтения, которое ограничено {@code readTimeout = max(1 мс, срок/4)}. Соединение
 * закрывается из читающего потока. Внутренний тип, не часть публичного API библиотеки.
 */
public final class UrlConnectionFetch {

    private static final GostLogger LOG =
            GostLogger.getLogger("org.rssys.gost.pkix.internal.net.UrlConnectionFetch");

    private static final int READ_TIMEOUT_DIVISOR = 4;
    private static final int ERROR_READ_BUFFER = 512;

    private UrlConnectionFetch() {}

    /**
     * Выполняет запрос.
     *
     * @return {@link FetchOutcome#success тело} ответа 200, {@link FetchOutcome#unchanged 304}
     *         на условный запрос либо {@link FetchOutcome#failure отказ}: ответ не 200, недопустимое перенаправление или адрес, слишком много
     *         перенаправлений, неожиданный тип содержимого
     * @throws DeadlineExceededException если общий срок вышел до получения заголовков ответа или
     *                                  при чтении тела ответа 200. Если срок вышел или поток
     *                                  оборвался посреди тела ответа не 200, возвращается отказ
     *                                  {@link FetchOutcome.Failure#NON_200} с кодом статуса и
     *                                  прочитанной частью тела
     * @throws BodyTooLargeException     если ответ больше предела
     * @throws IOException               при прочей сетевой ошибке
     */
    public static FetchOutcome execute(FetchRequest request) throws IOException {
        Deadline deadline = Deadline.after(request.timeout());
        URI current = request.uri();
        String validator = HttpValidators.acceptLastModified(request.ifModifiedSince());
        for (int attempt = 0; attempt < RedirectPolicy.MAX_REQUESTS; attempt++) {
            boolean viaRedirect = attempt > 0;
            // Условный запрос только на исходном адресе: после перенаправления валидатор мог бы
            // сработать на другом ресурсе
            boolean conditional = !viaRedirect && validator != null;
            // Исходный адрес и каждый переход проверяются одинаково, до обращения к сети
            Failure blocked =
                    RedirectPolicy.checkTarget(
                            current, request.allowedSchemes(), request.blockedTarget());
            if (blocked != null) {
                LOG.log(
                        Level.DEBUG,
                        "Fetch skipped: address not allowed: {0}",
                        SafeText.uri(current));
                return FetchOutcome.failure(blocked, 0, current, viaRedirect);
            }
            if (deadline.isExpired()) {
                throw new DeadlineExceededException("Deadline exceeded before the request");
            }
            HttpURLConnection conn = null;
            try {
                URLConnection raw = current.toURL().openConnection();
                if (!(raw instanceof HttpURLConnection http)) {
                    return FetchOutcome.failure(Failure.DISALLOWED_SCHEME, 0, current, viaRedirect);
                }
                conn = http;
                int remainingMillis = deadline.remainingMillisAtLeastOne();
                conn.setConnectTimeout(remainingMillis);
                // Таймаут чтения не меняется между чтениями, поэтому берём его долей срока:
                // остановившийся сервер обрывается за срок/4, а не ждёт весь срок
                int readTimeout =
                        (int)
                                Math.max(
                                        1L,
                                        Math.min(
                                                remainingMillis,
                                                request.timeout().toMillis()
                                                        / READ_TIMEOUT_DIVISOR));
                conn.setReadTimeout(readTimeout);
                conn.setRequestMethod(request.method());
                conn.setInstanceFollowRedirects(false);
                conn.setUseCaches(false);
                request.headers().forEach(conn::setRequestProperty);
                if (conditional) {
                    // Строкой как есть: дата сервера, а не наши часы; If-None-Match не посылается
                    conn.setRequestProperty("If-Modified-Since", validator);
                }
                if (request.body() != null) {
                    conn.setDoOutput(true);
                    conn.setRequestProperty("Content-Type", request.contentType());
                }

                int status;
                try (DeadlineWatchdog watchdog =
                        new DeadlineWatchdog(conn, Duration.ofMillis(remainingMillis))) {
                    conn.connect();
                    if (request.body() != null) {
                        try (OutputStream os = conn.getOutputStream()) {
                            os.write(request.body());
                        }
                    }
                    status = conn.getResponseCode();
                    // После срабатывания сторожа getResponseCode() может вернуть 200 с неполными
                    // заголовками: принимать такой ответ нельзя
                    if (watchdog.hasFired()) {
                        throw new DeadlineExceededException("Deadline exceeded in the headers");
                    }
                }
                // Сторож закрыт. Он срабатывает не раньше срока, поэтому истёкший срок здесь
                // покрывает и гонку на границе
                if (deadline.isExpired()) {
                    throw new DeadlineExceededException("Deadline exceeded after the headers");
                }

                if (status == 304 && conditional) {
                    // Ответ на наш условный запрос: тела нет; Last-Modified ответа 304 не читается
                    return FetchOutcome.unchanged();
                }
                if (RedirectPolicy.isRedirect(request.method(), status)) {
                    RedirectPolicy.Redirect redirect =
                            RedirectPolicy.next(
                                    current,
                                    conn.getHeaderField("Location"),
                                    request.allowedSchemes());
                    if (redirect.target() == null) {
                        LOG.log(
                                Level.DEBUG,
                                "Fetch failed: redirect (HTTP {0}) is not allowed from {1}",
                                status,
                                SafeText.uri(current));
                        // Отказ относится к самому переходу, поэтому viaRedirect истинен и на
                        // первом запросе: так «плохой переход» отличается от «плохого адреса»
                        return FetchOutcome.failure(
                                redirect.failure(),
                                status,
                                redirect.rejected() != null ? redirect.rejected() : current,
                                true);
                    }
                    current = redirect.target();
                    continue;
                }
                if (status != 200) {
                    LOG.log(
                            Level.DEBUG,
                            "Fetch failed: HTTP {0} for {1}",
                            status,
                            SafeText.uri(current));
                    byte[] errorBody = readErrorBody(conn, request.errorBodyLimit(), deadline);
                    return FetchOutcome.failure(
                            Failure.NON_200, status, current, viaRedirect, null, errorBody);
                }

                // Тип сверяется до чтения тела: ответ чужого типа не нужно ни читать, ни копить
                String contentType = conn.getContentType();
                if (request.expectedMediaType() != null
                        && !MediaTypes.matches(contentType, request.expectedMediaType())) {
                    LOG.log(
                            Level.DEBUG,
                            "Fetch failed: unexpected Content-Type for {0}: {1}",
                            SafeText.uri(current),
                            SafeText.printableAscii(contentType));
                    return FetchOutcome.failure(
                            Failure.UNEXPECTED_CONTENT_TYPE,
                            status,
                            current,
                            viaRedirect,
                            contentType,
                            null);
                }

                // Заранее заявленный размер больше предела: тело не читаем
                long declared = conn.getContentLengthLong();
                if (declared > request.maxResponseSize()) {
                    throw new BodyTooLargeException(request.maxResponseSize(), declared);
                }
                try (InputStream in = conn.getInputStream()) {
                    // Валидатор запоминается, только если ответ пришёл без перенаправлений
                    String lastModified = viaRedirect ? null : conn.getHeaderField("Last-Modified");
                    return FetchOutcome.success(
                            BoundedBodyReader.readAll(in, request.maxResponseSize(), deadline),
                            lastModified);
                }
            } catch (IllegalArgumentException e) {
                // Адрес или Location прошли разбор URI, но негодны для соединения (порт вне
                // диапазона и т. п.): для вызывающего это сетевая ошибка
                throw new IOException("Malformed URL or redirect: " + SafeText.uri(current), e);
            } catch (SocketTimeoutException e) {
                // Общий срок мог ещё не выйти: сервер замолчал дольше таймаута чтения (или не
                // уложился в соединение). Тип тот же, а диагностика различает причину
                throw new DeadlineExceededException(
                        "Server stalled longer than the read/connect timeout: "
                                + SafeText.uri(current),
                        e);
            } catch (InterruptedIOException e) {
                Thread.currentThread().interrupt();
                throw new IOException("Fetch interrupted", e);
            } catch (DeadlineExceededException | BodyTooLargeException e) {
                throw e;
            } catch (IOException e) {
                // Обрыв сторожем выглядит как обычная ошибка чтения: причину различаем по сроку
                if (deadline.isExpired()) {
                    throw new DeadlineExceededException(
                            "Deadline exceeded: " + SafeText.uri(current), e);
                }
                throw e;
            } finally {
                if (conn != null) {
                    conn.disconnect();
                }
            }
        }
        LOG.log(
                Level.DEBUG,
                "Fetch failed: too many redirects for {0}",
                SafeText.uri(request.uri()));
        return FetchOutcome.failure(Failure.TOO_MANY_REDIRECTS, 0, request.uri(), false);
    }

    /**
     * Читает не больше {@code limit} байт тела ошибки по принципу «сколько успели». Тело нужно
     * только для диагностики, а код статуса уже известен: срок, таймаут чтения, обрыв или
     * прерывание останавливают чтение и возвращают прочитанное, исход остаётся «ответ не 200».
     */
    private static byte[] readErrorBody(HttpURLConnection conn, int limit, Deadline deadline) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        if (limit == 0) {
            return out.toByteArray();
        }
        try (InputStream in = conn.getErrorStream()) {
            if (in == null) {
                return out.toByteArray();
            }
            byte[] buf = new byte[Math.min(limit, ERROR_READ_BUFFER)];
            while (out.size() < limit && !deadline.isExpired()) {
                int n = in.read(buf, 0, Math.min(buf.length, limit - out.size()));
                if (n < 0) {
                    break;
                }
                out.write(buf, 0, n);
                if (Thread.interrupted()) {
                    // Флаг возвращается вызывающему: чтение прекращено, а не проглочено
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        } catch (IOException e) {
            // Таймаут чтения, обрыв, сбой закрытия: вернуть то, что успели прочитать
        }
        return out.toByteArray();
    }
}
