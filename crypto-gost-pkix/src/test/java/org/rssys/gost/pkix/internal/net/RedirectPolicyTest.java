package org.rssys.gost.pkix.internal.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.util.Set;
import java.util.function.Predicate;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.internal.net.FetchOutcome.Failure;

@DisplayName("RedirectPolicy: статусы по методу, схема, понижение https")
class RedirectPolicyTest {

    private static final Set<String> HTTP_ONLY = Set.of("http");
    private static final Set<String> HTTP_AND_HTTPS = Set.of("http", "https");

    @Test
    @DisplayName("GET следует 301, 302, 303, 307, 308; POST только 307 и 308")
    void statusesByMethod() {
        for (int status : new int[] {301, 302, 303, 307, 308}) {
            assertTrue(RedirectPolicy.isRedirect("GET", status), "GET " + status);
        }
        assertTrue(RedirectPolicy.isRedirect("POST", 307));
        assertTrue(RedirectPolicy.isRedirect("POST", 308));
        for (int status : new int[] {301, 302, 303}) {
            assertFalse(RedirectPolicy.isRedirect("POST", status), "POST " + status);
        }
        assertFalse(RedirectPolicy.isRedirect("GET", 200));
        assertFalse(RedirectPolicy.isRedirect("GET", 304));
    }

    @Test
    @DisplayName("Относительный Location разрешается от текущего адреса")
    void relativeLocation() {
        RedirectPolicy.Redirect next =
                RedirectPolicy.next(URI.create("http://a.example/x/y"), "/z", HTTP_ONLY);

        assertEquals(URI.create("http://a.example/z"), next.target());
        assertNull(next.failure());
    }

    @Test
    @DisplayName("Отсутствующий и пустой Location - MISSING_LOCATION, битый - BAD_LOCATION")
    void missingAndBadLocation() {
        URI cur = URI.create("http://a.example/");

        assertEquals(Failure.MISSING_LOCATION, failureOf(cur, null, HTTP_AND_HTTPS));
        assertEquals(Failure.MISSING_LOCATION, failureOf(cur, "", HTTP_AND_HTTPS));
        assertEquals(Failure.BAD_LOCATION, failureOf(cur, "http://[bad", HTTP_AND_HTTPS));
    }

    @Test
    @DisplayName("Чужие схемы (file:, ftp:) - DISALLOWED_SCHEME")
    void foreignSchemes() {
        URI cur = URI.create("http://a.example/");

        assertEquals(
                Failure.DISALLOWED_SCHEME, failureOf(cur, "file:///etc/hostname", HTTP_AND_HTTPS));
        assertEquals(
                Failure.DISALLOWED_SCHEME, failureOf(cur, "ftp://a.example/x", HTTP_AND_HTTPS));
    }

    @Test
    @DisplayName("Схема должна быть из допустимых: для OCSP https недопустим, для CRL допустим")
    void schemeMustBeAllowed() {
        URI cur = URI.create("http://a.example/");

        assertEquals(Failure.DISALLOWED_SCHEME, failureOf(cur, "https://a.example/x", HTTP_ONLY));
        assertEquals(
                URI.create("https://a.example/x"),
                RedirectPolicy.next(cur, "https://a.example/x", HTTP_AND_HTTPS).target(),
                "повышение http до https для CRL безвредно: ответ проверяется по подписи");
    }

    @Test
    @DisplayName("Понижение https до http запрещено и называется отдельной причиной")
    void downgradeIsForbidden() {
        assertEquals(
                Failure.DOWNGRADE,
                failureOf(URI.create("https://a.example/"), "http://a.example/x", HTTP_AND_HTTPS));
    }

    @Test
    @DisplayName("Адрес вне допустимых схем отвергается даже без SSRF-блокировки")
    void targetSchemeIsChecked() {
        Predicate<URI> nothingBlocked = uri -> false;

        assertEquals(
                Failure.DISALLOWED_SCHEME,
                RedirectPolicy.checkTarget(URI.create("file:///x"), HTTP_ONLY, nothingBlocked));
        assertNull(
                RedirectPolicy.checkTarget(
                        URI.create("http://127.0.0.1/"), HTTP_ONLY, nothingBlocked));
    }

    @Test
    @DisplayName("Заблокированный предикатом адрес - BLOCKED_TARGET; loopback блокирует SsrfGuard")
    void blockedTarget() {
        assertEquals(
                Failure.BLOCKED_TARGET,
                RedirectPolicy.checkTarget(
                        URI.create("http://127.0.0.1/"),
                        HTTP_ONLY,
                        FetchRequest.BLOCK_PRIVATE_ADDRESSES),
                "loopback блокируется SSRF-защитой");
        assertEquals(
                Failure.BLOCKED_TARGET,
                RedirectPolicy.checkTarget(
                        URI.create("http://a.example/secret"),
                        HTTP_ONLY,
                        uri -> uri.getPath().startsWith("/secret")));
    }

    private static Failure failureOf(URI current, String location, Set<String> schemes) {
        RedirectPolicy.Redirect redirect = RedirectPolicy.next(current, location, schemes);
        assertNull(redirect.target(), "при отказе адреса быть не должно");
        return redirect.failure();
    }
}
