package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.signature.ECParameters;

@DisplayName("PKCS#12: кодирование пароля в UTF-8, непарный суррогат отвергается")
class GostPkcs12PasswordEncodingTest {

    private static final int TEST_ITER = 100;

    private static byte[] build(PkixCertTestHelper.CertBundle bundle, char[] password) {
        return GostPkcs12Builder.create()
                .key(bundle.priv)
                .certificate(bundle.cert)
                .password(password)
                .iterations(TEST_ITER)
                .build();
    }

    @Test
    @DisplayName("пароль с символом вне BMP: build -> load возвращает ключ")
    void passwordOutsideBmpRoundtrips() throws Exception {
        PkixCertTestHelper.CertBundle bundle =
                PkixCertTestHelper.createCertWithKey(ECParameters.tc26a256());
        char[] password = "p😀п".toCharArray();

        byte[] pfx = build(bundle, password);

        assertNotNull(GostPkcs12Loader.load(pfx, password, true, 50).getPrivateKey(), "ключ");
    }

    @Test
    @DisplayName("PFX, собранный с паролем «ab?», не открывается паролем с непарным суррогатом")
    void unpairedSurrogateIsNotReplacedByQuestionMark() throws Exception {
        PkixCertTestHelper.CertBundle bundle =
                PkixCertTestHelper.createCertWithKey(ECParameters.tc26a256());
        byte[] pfx = build(bundle, "ab?".toCharArray());

        // Раньше Charset.encode молча заменял непарный суррогат на «?», и этот пароль подходил
        assertThrows(
                IllegalArgumentException.class,
                () -> GostPkcs12Loader.load(pfx, "ab\uD800".toCharArray(), true, 50),
                "непарный суррогат не должен давать ключ от пароля «ab?»");
        assertNotNull(
                GostPkcs12Loader.load(pfx, "ab?".toCharArray(), true, 50).getPrivateKey(),
                "настоящий пароль по-прежнему подходит");
    }

    @Test
    @DisplayName("сборка PFX с паролем, содержащим непарный суррогат, отвергается")
    void builderRejectsUnpairedSurrogate() throws Exception {
        PkixCertTestHelper.CertBundle bundle =
                PkixCertTestHelper.createCertWithKey(ECParameters.tc26a256());

        assertThrows(
                IllegalArgumentException.class,
                () -> build(bundle, "ab\uDC00".toCharArray()),
                "пароль, который нельзя закодировать в UTF-8, не должен давать контейнер");
    }
}
