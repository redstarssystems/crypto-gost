package org.rssys.gost.jsse;


import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import java.security.Provider;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.*;

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

        // WHY: без этих сервисов TLS 1.3 через провайдер не работает
        assertNotNull(provider.get("SSLContext.TLSv1.3"));
        assertNotNull(provider.get("SSLContext.GOST-TLSv1.3"));
        assertNotNull(provider.get("KeyManagerFactory.GostX509"));
        assertNotNull(provider.get("TrustManagerFactory.GostX509"));

        // WHY: алиасы PKIX и TLS ведут на SunJCE —fallback запрещён
        assertNull(provider.get("SSLContext.TLS"));
        assertNull(provider.get("KeyManagerFactory.PKIX"));
        assertNull(provider.get("TrustManagerFactory.PKIX"));
    }

    @Test
    @DisplayName("Создание SSL-контекста через провайдер")
    void testSSLContextCreation() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        try {
            SSLContext ctx = SSLContext.getInstance(GostJsseConstants.PROTOCOL_TLS_1_3, GostJsseConstants.PROVIDER_NAME);
            assertNotNull(ctx, "SSLContext не должен быть null");
            ctx.init(null, null, null);
            assertNotNull(ctx.createSSLEngine(), "SSLEngine не должен быть null");
        } finally {
            Security.removeProvider(GostJsseConstants.PROVIDER_NAME);
        }
    }

    @Test
    @DisplayName("Создание SSL-контекста с именем GOST-TLSv1.3")
    void testGostTls13Name() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        try {
            SSLContext ctx = SSLContext.getInstance("GOST-TLSv1.3", GostJsseConstants.PROVIDER_NAME);
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
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("GostX509", GostJsseConstants.PROVIDER_NAME);
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
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("GostX509", GostJsseConstants.PROVIDER_NAME);
            assertNotNull(tmf, "TrustManagerFactory не должен быть null");
        } finally {
            Security.removeProvider(GostJsseConstants.PROVIDER_NAME);
        }
    }
}
