package org.rssys.gost.jsse;

import static org.junit.jupiter.api.Assertions.*;

import java.security.KeyManagementException;
import java.security.Security;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;

/**
 * Тесты регистрации RssysGostJsseProvider.
 * Проверяют корректность регистрации провайдера, создание SSL-контекстов,
 * фабрик ключей и доверенных сертификатов.
 */
@DisplayName("Тесты RssysGostJsseProvider")
class RssysGostJsseProviderTest {

    @Test
    @DisplayName("Проверка регистрации провайдера и его сервисов")
    void testProviderRegistration() {
        RssysGostJsseProvider provider = new RssysGostJsseProvider();
        assertEquals("RssysGostJsse", provider.getName());
        assertEquals("1.0", provider.getVersionStr());

        // без этих сервисов TLS 1.3 через провайдер не работает
        assertNotNull(provider.get("SSLContext.TLSv1.3"));
        assertNotNull(provider.get("SSLContext.GOST-TLSv1.3"));
        assertNotNull(provider.get("KeyManagerFactory.GostX509"));
        assertNotNull(provider.get("TrustManagerFactory.GostX509"));

        // алиасы PKIX и TLS ведут на SunJCE —fallback запрещён
        assertNull(provider.get("SSLContext.TLS"));
        assertNull(provider.get("KeyManagerFactory.PKIX"));
        assertNull(provider.get("TrustManagerFactory.PKIX"));
    }

    @Test
    @DisplayName("Создание SSL-контекста через провайдер")
    void testSSLContextCreation() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        try {
            SSLContext ctx =
                    SSLContext.getInstance(
                            GostJsseConstants.PROTOCOL_TLS_1_3, GostJsseConstants.PROVIDER_NAME);
            assertEquals(
                    GostJsseConstants.PROVIDER_NAME,
                    ctx.getProvider().getName(),
                    "контекст должен принадлежать ГОСТ-провайдеру, а не JDK");
            assertEquals(GostJsseConstants.PROTOCOL_TLS_1_3, ctx.getProtocol());
            ctx.init(null, null, null);
            assertEquals(
                    "GostSSLEngine",
                    ctx.createSSLEngine().getClass().getSimpleName(),
                    "движок должен быть ГОСТ-реализацией");
        } finally {
            Security.removeProvider(GostJsseConstants.PROVIDER_NAME);
        }
    }

    @Test
    @DisplayName("Сторонний TrustManager отвергается с KeyManagementException")
    void testForeignTrustManagerRejected() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        try {
            SSLContext ctx =
                    SSLContext.getInstance(
                            GostJsseConstants.PROTOCOL_TLS_1_3, GostJsseConstants.PROVIDER_NAME);
            TrustManager foreign = new TrustManager() {};
            assertThrows(
                    KeyManagementException.class,
                    () -> ctx.init(null, new TrustManager[] {foreign}, null),
                    "сторонний TrustManager не должен заменяться trust-all");
        } finally {
            Security.removeProvider(GostJsseConstants.PROVIDER_NAME);
        }
    }

    @Test
    @DisplayName("Два разных GostX509TrustManager отвергаются: якоря второго не теряются молча")
    void testTwoDistinctGostTrustManagersRejected() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        try {
            SSLContext ctx =
                    SSLContext.getInstance(
                            GostJsseConstants.PROTOCOL_TLS_1_3, GostJsseConstants.PROVIDER_NAME);
            TrustManager first = GostX509TrustManager.insecureTrustAll();
            TrustManager second = GostX509TrustManager.insecureTrustAll();
            assertThrows(
                    KeyManagementException.class,
                    () -> ctx.init(null, new TrustManager[] {first, second}, null),
                    "два разных экземпляра не должны приводить к выбору первого");
        } finally {
            Security.removeProvider(GostJsseConstants.PROVIDER_NAME);
        }
    }

    @Test
    @DisplayName("Один и тот же GostX509TrustManager дважды допустим")
    void testSameGostTrustManagerTwiceAccepted() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        try {
            SSLContext ctx =
                    SSLContext.getInstance(
                            GostJsseConstants.PROTOCOL_TLS_1_3, GostJsseConstants.PROVIDER_NAME);
            TrustManager tm = GostX509TrustManager.insecureTrustAll();
            ctx.init(null, new TrustManager[] {tm, tm}, null);
            assertNotNull(ctx.createSSLEngine(), "контекст с одним экземпляром должен работать");
        } finally {
            Security.removeProvider(GostJsseConstants.PROVIDER_NAME);
        }
    }

    @Test
    @DisplayName("GostX509TrustManager вместе со сторонним отвергается")
    void testGostWithForeignTrustManagerRejected() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        try {
            SSLContext ctx =
                    SSLContext.getInstance(
                            GostJsseConstants.PROTOCOL_TLS_1_3, GostJsseConstants.PROVIDER_NAME);
            TrustManager gost = GostX509TrustManager.insecureTrustAll();
            TrustManager foreign = new TrustManager() {};
            assertThrows(
                    KeyManagementException.class,
                    () -> ctx.init(null, new TrustManager[] {gost, foreign}, null),
                    "сторонний менеджер в массиве должен отвергаться");
        } finally {
            Security.removeProvider(GostJsseConstants.PROVIDER_NAME);
        }
    }

    @Test
    @DisplayName("null-элемент массива TrustManager отвергается")
    void testNullTrustManagerElementRejected() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        try {
            SSLContext ctx =
                    SSLContext.getInstance(
                            GostJsseConstants.PROTOCOL_TLS_1_3, GostJsseConstants.PROVIDER_NAME);
            assertThrows(
                    KeyManagementException.class,
                    () -> ctx.init(null, new TrustManager[] {null}, null),
                    "null-элемент не должен приводить к trust-all");
        } finally {
            Security.removeProvider(GostJsseConstants.PROVIDER_NAME);
        }
    }

    @Test
    @DisplayName("Сторонний KeyManager отвергается с KeyManagementException")
    void testForeignKeyManagerRejected() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        try {
            SSLContext ctx =
                    SSLContext.getInstance(
                            GostJsseConstants.PROTOCOL_TLS_1_3, GostJsseConstants.PROVIDER_NAME);
            KeyManager foreign = new KeyManager() {};
            assertThrows(
                    KeyManagementException.class,
                    () -> ctx.init(new KeyManager[] {foreign}, null, null),
                    "сторонний KeyManager не должен молча заменяться пустым");
        } finally {
            Security.removeProvider(GostJsseConstants.PROVIDER_NAME);
        }
    }

    @Test
    @DisplayName("null-элемент массива KeyManager отвергается")
    void testNullKeyManagerElementRejected() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        try {
            SSLContext ctx =
                    SSLContext.getInstance(
                            GostJsseConstants.PROTOCOL_TLS_1_3, GostJsseConstants.PROVIDER_NAME);
            assertThrows(
                    KeyManagementException.class,
                    () -> ctx.init(new KeyManager[] {null}, null, null),
                    "null-элемент не должен приводить к пустому менеджеру");
        } finally {
            Security.removeProvider(GostJsseConstants.PROVIDER_NAME);
        }
    }

    @Test
    @DisplayName("Два разных GostX509KeyManager отвергаются: ключи второго не теряются молча")
    void testTwoDistinctGostKeyManagersRejected() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        try {
            SSLContext ctx =
                    SSLContext.getInstance(
                            GostJsseConstants.PROTOCOL_TLS_1_3, GostJsseConstants.PROVIDER_NAME);
            KeyManager first = new GostX509KeyManager();
            KeyManager second = new GostX509KeyManager();
            assertThrows(
                    KeyManagementException.class,
                    () -> ctx.init(new KeyManager[] {first, second}, null, null),
                    "два разных экземпляра не должны приводить к выбору первого");
        } finally {
            Security.removeProvider(GostJsseConstants.PROVIDER_NAME);
        }
    }

    @Test
    @DisplayName("KeyManager: один и тот же экземпляр дважды, null и пустой массив допустимы")
    void testKeyManagerAcceptedForms() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        try {
            KeyManager gost = new GostX509KeyManager();
            for (KeyManager[] accepted : new KeyManager[][] {{gost, gost}, {gost}, {}, null}) {
                SSLContext ctx =
                        SSLContext.getInstance(
                                GostJsseConstants.PROTOCOL_TLS_1_3,
                                GostJsseConstants.PROVIDER_NAME);
                assertDoesNotThrow(
                        () -> ctx.init(accepted, null, null),
                        "клиент без mTLS и повтор одного менеджера допустимы");
            }
        } finally {
            Security.removeProvider(GostJsseConstants.PROVIDER_NAME);
        }
    }

    @Test
    @DisplayName("Создание SSL-контекста с именем GOST-TLSv1.3")
    void testGostTls13Name() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        try {
            SSLContext ctx =
                    SSLContext.getInstance("GOST-TLSv1.3", GostJsseConstants.PROVIDER_NAME);
            assertNotNull(ctx, "SSLContext для GOST-TLSv1.3 не должен быть null");
        } finally {
            Security.removeProvider(GostJsseConstants.PROVIDER_NAME);
        }
    }

    @Test
    @DisplayName("Создание KeyManagerFactory через провайдер")
    void testKeyManagerFactory() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        try {
            KeyManagerFactory kmf =
                    KeyManagerFactory.getInstance("GostX509", GostJsseConstants.PROVIDER_NAME);
            assertNotNull(kmf, "KeyManagerFactory не должен быть null");
        } finally {
            Security.removeProvider(GostJsseConstants.PROVIDER_NAME);
        }
    }

    @Test
    @DisplayName("Создание TrustManagerFactory через провайдер")
    void testTrustManagerFactory() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        try {
            TrustManagerFactory tmf =
                    TrustManagerFactory.getInstance("GostX509", GostJsseConstants.PROVIDER_NAME);
            assertNotNull(tmf, "TrustManagerFactory не должен быть null");
        } finally {
            Security.removeProvider(GostJsseConstants.PROVIDER_NAME);
        }
    }
}
