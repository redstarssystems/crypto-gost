package org.rssys.gost;

import java.security.Security;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.rssys.gost.jca.RssysGostProvider;

/**
 * Регистрация провайдера {@link RssysGostProvider} для JCA-тестов. Подключается к классу
 * аннотацией {@code @ExtendWith(JcaTestSupport.class)}; из кода вызывается как
 * {@link #ensureProvider()}.
 *
 * <p>Провайдер регистрируется один раз на JVM: повторная регистрация другим тестовым классом
 * ничего не делает.
 */
public final class JcaTestSupport implements BeforeAllCallback {

    /** Регистрирует провайдер, если он ещё не зарегистрирован. */
    public static void ensureProvider() {
        if (Security.getProvider(RssysGostProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new RssysGostProvider());
        }
    }

    @Override
    public void beforeAll(ExtensionContext context) {
        ensureProvider();
    }
}
