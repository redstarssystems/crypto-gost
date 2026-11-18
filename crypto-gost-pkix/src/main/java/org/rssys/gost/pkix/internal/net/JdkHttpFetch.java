package org.rssys.gost.pkix.internal.net;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.rssys.gost.pkix.internal.net.FetchOutcome.Failure;
import org.rssys.gost.pkix.util.BodyTooLargeException;
import org.rssys.gost.pkix.util.Deadline;
import org.rssys.gost.pkix.util.DeadlineExceededException;
import org.rssys.gost.util.GostLogger;
import org.rssys.gost.util.GostLogger.Level;
import org.rssys.gost.util.SafeText;

/**
 * Загрузка по HTTP на {@link HttpClient} (JVM) с одним общим сроком на весь запрос.
 *
 * <p>{@code HttpRequest.timeout} покрывает только ожидание заголовков, поэтому запрос идёт
 * асинхронно, а вызывающий поток ждёт результат не дольше остатка общего срока
 * ({@code get(остаток)}); по истечении запрос отменяется ({@code cancel(true)}), и соединение
 * закрывается. Тело собирает собственный подписчик: он сверяет заявленный размер до чтения,
 * останавливает приём при превышении предела и не копит тело ответа не-200. Перенаправления
 * выполняются вручную ({@code Redirect.NEVER}): SSRF и схема проверяются на каждом переходе,
 * срок общий. Внутренний тип, не часть публичного API библиотеки.
 */
public final class JdkHttpFetch implements FetchTransport {

    private static final GostLogger LOG =
            GostLogger.getLogger("org.rssys.gost.pkix.internal.net.JdkHttpFetch");

    private final HttpClient client;

    /** Создаёт загрузчик с собственным клиентом без автоматических перенаправлений. */
    public JdkHttpFetch() {
        this(HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build());
    }

    /**
     * @param client клиент; перенаправления он должен выполнять не сам ({@code Redirect.NEVER})
     * @throws IllegalArgumentException если клиент сам следует перенаправлениям: он обошёл бы
     *                                  проверку SSRF и схемы на переходах и общий срок
     */
    public JdkHttpFetch(HttpClient client) {
        if (client.followRedirects() != HttpClient.Redirect.NEVER) {
            throw new IllegalArgumentException(
                    "HttpClient must not follow redirects itself (Redirect.NEVER required)");
        }
        this.client = client;
    }

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
    @Override
    public FetchOutcome execute(FetchRequest request) throws IOException {
        Deadline deadline = Deadline.after(request.timeout());
        URI current = request.uri();
        String validator = HttpValidators.acceptLastModified(request.ifModifiedSince());
        for (int attempt = 0; attempt < RedirectPolicy.MAX_REQUESTS; attempt++) {
            boolean viaRedirect = attempt > 0;
            // Условный запрос только на исходном адресе: после перенаправления валидатор мог бы
            // сработать на другом ресурсе
            boolean conditional = !viaRedirect && validator != null;
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
            // Остаток срока на каждом переходе; нулевой остаток - ошибка срока без нового запроса
            if (deadline.isExpired()) {
                throw new DeadlineExceededException("Deadline exceeded before the request");
            }
            HttpRequest httpRequest =
                    buildRequest(request, current, deadline, conditional ? validator : null);

            ErrorBodyCapture errorCapture = new ErrorBodyCapture();
            CompletableFuture<HttpResponse<byte[]>> future;
            try {
                future =
                        client.sendAsync(
                                httpRequest, info -> handlerFor(info, request, errorCapture));
            } catch (IllegalArgumentException | SecurityException e) {
                throw new IOException("Malformed URL or request: " + SafeText.uri(current), e);
            }
            HttpResponse<byte[]> response;
            try {
                response = await(future, deadline);
            } catch (IOException e) {
                // Срок или обрыв посреди тела отказа не отменяют код статуса; для остальных
                // фаз (соединение, заголовки, тело 200) partial отсутствует, и ошибка выходит
                FetchOutcome partial = errorCapture.outcome(current, viaRedirect);
                if (partial == null) {
                    throw e;
                }
                return partial;
            }

            int status = response.statusCode();
            if (status == 304 && conditional) {
                // Ответ на наш условный запрос: тела нет; Last-Modified ответа 304 не читается
                return FetchOutcome.unchanged();
            }
            if (status == 200) {
                String contentType = response.headers().firstValue("Content-Type").orElse(null);
                if (!typeAccepted(request, contentType)) {
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
                // Валидатор запоминается, только если ответ пришёл без перенаправлений
                return FetchOutcome.success(
                        response.body(),
                        viaRedirect
                                ? null
                                : response.headers().firstValue("Last-Modified").orElse(null));
            }
            if (RedirectPolicy.isRedirect(request.method(), status)) {
                RedirectPolicy.Redirect redirect =
                        RedirectPolicy.next(
                                current,
                                response.headers().firstValue("Location").orElse(null),
                                request.allowedSchemes());
                if (redirect.target() == null) {
                    LOG.log(
                            Level.DEBUG,
                            "Fetch failed: redirect (HTTP {0}) is not allowed from {1}",
                            status,
                            SafeText.uri(current));
                    // Отказ относится к самому перенаправлению (его адресу или заголовку), поэтому
                    // viaRedirect истинен и на первом запросе: вызывающий различает «плохой
                    // исходный
                    // адрес» и «плохой переход»
                    return FetchOutcome.failure(
                            redirect.failure(),
                            status,
                            redirect.rejected() != null ? redirect.rejected() : current,
                            true);
                }
                current = redirect.target();
                continue;
            }
            LOG.log(Level.DEBUG, "Fetch failed: HTTP {0} for {1}", status, SafeText.uri(current));
            return FetchOutcome.failure(
                    Failure.NON_200, status, current, viaRedirect, null, response.body());
        }
        LOG.log(
                Level.DEBUG,
                "Fetch failed: too many redirects for {0}",
                SafeText.uri(request.uri()));
        return FetchOutcome.failure(Failure.TOO_MANY_REDIRECTS, 0, request.uri(), false);
    }

    private static boolean typeAccepted(FetchRequest request, String contentType) {
        return request.expectedMediaType() == null
                || MediaTypes.matches(contentType, request.expectedMediaType());
    }

    private static HttpRequest buildRequest(
            FetchRequest request, URI uri, Deadline deadline, String ifModifiedSince)
            throws IOException {
        try {
            // Резервный предел на фазу заголовков; общий срок обеспечивает get(остаток)
            Duration headerTimeout =
                    Duration.ofNanos(Math.max(1_000_000L, deadline.remainingNanos()));
            HttpRequest.Builder builder = HttpRequest.newBuilder().uri(uri).timeout(headerTimeout);
            request.headers().forEach(builder::header);
            if (ifModifiedSince != null) {
                // Строкой как есть: дата сервера, а не наши часы; If-None-Match не посылается
                builder.header("If-Modified-Since", ifModifiedSince);
            }
            if ("POST".equals(request.method())) {
                // ofByteArray повторяем: тело отправляется заново после 307 и 308
                builder.header("Content-Type", request.contentType())
                        .POST(HttpRequest.BodyPublishers.ofByteArray(request.body()));
            } else {
                builder.GET();
            }
            return builder.build();
        } catch (IllegalArgumentException e) {
            throw new IOException("Malformed URL or request: " + SafeText.uri(uri), e);
        }
    }

    private static <T> T await(CompletableFuture<T> future, Deadline deadline) throws IOException {
        try {
            return future.get(deadline.remainingNanos(), TimeUnit.NANOSECONDS);
        } catch (TimeoutException e) {
            // Отмена закрывает соединение, фонового чтения не остаётся
            future.cancel(true);
            throw new DeadlineExceededException("Deadline exceeded", e);
        } catch (InterruptedException e) {
            future.cancel(true);
            Thread.currentThread().interrupt();
            throw new IOException("Fetch interrupted", e);
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof BodyTooLargeException tooLarge) {
                throw tooLarge;
            }
            if (cause instanceof HttpTimeoutException) {
                throw new DeadlineExceededException("Timed out waiting for the response", cause);
            }
            if (cause instanceof IOException io) {
                throw io;
            }
            // Разбор недоверенных заголовков в HttpClient может бросить непроверяемое исключение
            throw new IOException("Malformed or failed HTTP exchange", cause);
        } catch (CancellationException e) {
            throw new IOException("Fetch cancelled", e);
        }
    }

    /**
     * Запоминает статус и накопленное тело ответа не 200: если срок вышел или поток оборвался
     * посреди тела ошибки, код статуса всё равно известен, и теряться ему нельзя.
     */
    private static final class ErrorBodyCapture {
        private volatile int status;
        private volatile TruncatingSubscriber subscriber;

        void record(int status, TruncatingSubscriber subscriber) {
            this.status = status;
            this.subscriber = subscriber;
        }

        /** Исход «не 200» с прочитанной частью тела или {@code null}, если статус не принят. */
        FetchOutcome outcome(URI uri, boolean viaRedirect) {
            TruncatingSubscriber captured = subscriber;
            if (captured == null) {
                return null;
            }
            return FetchOutcome.failure(
                    Failure.NON_200, status, uri, viaRedirect, null, captured.snapshot());
        }
    }

    private static HttpResponse.BodySubscriber<byte[]> handlerFor(
            HttpResponse.ResponseInfo info, FetchRequest request, ErrorBodyCapture errorCapture) {
        int status = info.statusCode();
        if (status == 304) {
            // Ответ без тела: ничего не читаем и не копим
            return new CancellingSubscriber(null);
        }
        if (status != 200) {
            // Тело нужно только для усечённого текста отказа: у перенаправления и при нулевом
            // пределе оно не читается, чтобы не тратить память и время на чужой ответ
            if (request.errorBodyLimit() == 0
                    || RedirectPolicy.isRedirect(request.method(), status)) {
                return new CancellingSubscriber(null);
            }
            TruncatingSubscriber subscriber = new TruncatingSubscriber(request.errorBodyLimit());
            errorCapture.record(status, subscriber);
            return subscriber;
        }
        // Тип сверяется до чтения тела: ответ чужого типа не нужно ни читать, ни копить
        String contentType = info.headers().firstValue("Content-Type").orElse(null);
        if (!typeAccepted(request, contentType)) {
            return new CancellingSubscriber(null);
        }
        long declared = declaredLength(info);
        if (declared > request.maxResponseSize()) {
            return new CancellingSubscriber(
                    new BodyTooLargeException(request.maxResponseSize(), declared));
        }
        return new CollectingSubscriber(request.maxResponseSize());
    }

    private static long declaredLength(HttpResponse.ResponseInfo info) {
        try {
            return info.headers().firstValueAsLong("Content-Length").orElse(-1L);
        } catch (NumberFormatException e) {
            // Нечисловой заголовок значит «неизвестно»: размер считается при приёме
            return -1L;
        }
    }

    /** Отменяет приём тела сразу; результат - {@code null} или заданная ошибка. */
    private static final class CancellingSubscriber implements HttpResponse.BodySubscriber<byte[]> {
        private final CompletableFuture<byte[]> result = new CompletableFuture<>();
        private final IOException failure;

        CancellingSubscriber(IOException failure) {
            this.failure = failure;
        }

        @Override
        public CompletionStage<byte[]> getBody() {
            return result;
        }

        @Override
        public void onSubscribe(Flow.Subscription subscription) {
            subscription.cancel();
            if (failure != null) {
                result.completeExceptionally(failure);
            } else {
                result.complete(null);
            }
        }

        @Override
        public void onNext(List<ByteBuffer> item) {}

        @Override
        public void onError(Throwable throwable) {
            result.completeExceptionally(throwable);
        }

        @Override
        public void onComplete() {
            result.complete(null);
        }
    }

    /**
     * Собирает не больше заданного числа байт тела ошибки и останавливает приём: превышение
     * предела не ошибка, а усечение.
     */
    private static final class TruncatingSubscriber implements HttpResponse.BodySubscriber<byte[]> {
        private final CompletableFuture<byte[]> result = new CompletableFuture<>();
        // Пишется только из потока HttpClient (onNext вызываются последовательно)
        private final ByteArrayOutputStream out = new ByteArrayOutputStream();
        // Копия для чтения из потока вызывающего: безопасная публикация через volatile, а не через
        // внутреннюю синхронизацию ByteArrayOutputStream, которую его контракт не обещает.
        // Копия дешёвая: тело ошибки не больше нескольких сотен байт
        private volatile byte[] collected = new byte[0];
        private final int limit;
        private Flow.Subscription subscription;

        TruncatingSubscriber(int limit) {
            this.limit = limit;
        }

        @Override
        public CompletionStage<byte[]> getBody() {
            return result;
        }

        @Override
        public void onSubscribe(Flow.Subscription subscription) {
            this.subscription = subscription;
            subscription.request(Long.MAX_VALUE);
        }

        /**
         * Прочитанная к этому моменту часть тела. Вызывается из потока вызывающего, пока поток
         * {@code HttpClient} ещё может принимать данные: возвращается последняя опубликованная
         * копия, поэтому чтение безопасно без блокировок.
         */
        byte[] snapshot() {
            return collected;
        }

        @Override
        public void onNext(List<ByteBuffer> items) {
            if (result.isDone()) {
                return;
            }
            for (ByteBuffer buffer : items) {
                int n = Math.min(buffer.remaining(), limit - out.size());
                byte[] chunk = new byte[n];
                buffer.get(chunk);
                out.write(chunk, 0, n);
                collected = out.toByteArray();
                if (collected.length >= limit) {
                    // Остальное тело не нужно: закрываем приём, а не дочитываем чужой ответ
                    subscription.cancel();
                    result.complete(collected);
                    return;
                }
            }
        }

        @Override
        public void onError(Throwable throwable) {
            result.completeExceptionally(throwable);
        }

        @Override
        public void onComplete() {
            result.complete(collected);
        }
    }

    /** Собирает тело, останавливая приём при превышении предела. */
    private static final class CollectingSubscriber implements HttpResponse.BodySubscriber<byte[]> {
        private final CompletableFuture<byte[]> result = new CompletableFuture<>();
        private final ByteArrayOutputStream out = new ByteArrayOutputStream();
        private final int maxBytes;
        private int total;
        private Flow.Subscription subscription;

        CollectingSubscriber(int maxBytes) {
            this.maxBytes = maxBytes;
        }

        @Override
        public CompletionStage<byte[]> getBody() {
            return result;
        }

        @Override
        public void onSubscribe(Flow.Subscription subscription) {
            this.subscription = subscription;
            subscription.request(Long.MAX_VALUE);
        }

        @Override
        public void onNext(List<ByteBuffer> items) {
            if (result.isDone()) {
                return;
            }
            for (ByteBuffer buffer : items) {
                int n = buffer.remaining();
                if (total > maxBytes - n) {
                    subscription.cancel();
                    result.completeExceptionally(
                            new BodyTooLargeException(
                                    maxBytes, BodyTooLargeException.UNKNOWN_SIZE));
                    return;
                }
                total += n;
                byte[] chunk = new byte[n];
                buffer.get(chunk);
                out.write(chunk, 0, n);
            }
        }

        @Override
        public void onError(Throwable throwable) {
            result.completeExceptionally(throwable);
        }

        @Override
        public void onComplete() {
            result.complete(out.toByteArray());
        }
    }
}
