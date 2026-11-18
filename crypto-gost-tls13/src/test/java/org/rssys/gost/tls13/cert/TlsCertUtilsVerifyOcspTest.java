package org.rssys.gost.tls13.cert;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsException;

@DisplayName("TlsCertUtils.verifyOcspResponse: срок действия приложенного ответа")
class TlsCertUtilsVerifyOcspTest {

    @Test
    @DisplayName("nextUpdate просрочен -> TlsException")
    void expiredNextUpdateGivesTlsException() throws Exception {
        PkixCertTestHelper.CertBundle bundle =
                PkixCertTestHelper.createCertWithKey(ECParameters.tc26a256());
        byte[] ocsp =
                PkixCertTestHelper.buildOcspResponse(
                        bundle.cert.getSerialNumber(),
                        bundle.priv,
                        bundle.cert.getPublicKey(),
                        bundle.subjectDn,
                        "20200101120000Z");
        bundle.cert.setOcspResponse(ocsp);
        assertThrows(
                TlsException.class,
                () -> TlsCertUtils.verifyOcspResponse(bundle.cert, bundle.cert),
                "Просроченный ответ должен давать TlsException");
    }

    @Test
    @DisplayName("нет nextUpdate -> проходит")
    void noNextUpdateIsAccepted() throws Exception {
        PkixCertTestHelper.CertBundle bundle =
                PkixCertTestHelper.createCertWithKey(ECParameters.tc26a256());
        byte[] ocsp =
                PkixCertTestHelper.buildOcspResponse(
                        bundle.cert.getSerialNumber(),
                        bundle.priv,
                        bundle.cert.getPublicKey(),
                        bundle.subjectDn,
                        null);
        bundle.cert.setOcspResponse(ocsp);
        assertDoesNotThrow(
                () -> TlsCertUtils.verifyOcspResponse(bundle.cert, bundle.cert),
                "Ответ без nextUpdate должен проходить проверку срока");
    }
}
