package org.rssys.gost.tls13.cert;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;

@DisplayName("TlsCertUtils: схема подписи и именованная группа ключа сертификата")
class TlsCertUtilsSignatureSchemeTest {

    @Test
    @DisplayName("hasSignatureScheme: точное совпадение для TC26-A-256")
    void hasSignatureSchemeExact256() {
        PkixCertTestHelper.CertBundle bundle =
                PkixCertTestHelper.createCertWithKey(ECParameters.tc26a256());
        assertTrue(
                TlsCertUtils.hasSignatureScheme(
                        bundle.cert.getPublicKey(), TlsConstants.SIG_GOST_TC26_A_256));
    }

    @Test
    @DisplayName("hasSignatureScheme без флага: 0x0709 для CryptoPro-A отвергается")
    void hasSignatureSchemeRejectsMismatch() {
        PkixCertTestHelper.CertBundle bundle =
                PkixCertTestHelper.createCertWithKey(ECParameters.cryptoProA());
        assertFalse(
                TlsCertUtils.hasSignatureScheme(
                        bundle.cert.getPublicKey(), TlsConstants.SIG_GOST_TC26_A_256));
    }

    @Test
    @DisplayName("hasSignatureScheme с флагом: 0x0709 для CryptoPro-A принимается")
    void hasSignatureSchemeInterop256() {
        PkixCertTestHelper.CertBundle bundle =
                PkixCertTestHelper.createCertWithKey(ECParameters.cryptoProA());
        assertTrue(
                TlsCertUtils.hasSignatureScheme(
                        bundle.cert.getPublicKey(), TlsConstants.SIG_GOST_TC26_A_256, true));
    }

    @Test
    @DisplayName("hasSignatureScheme без флага: 0x070D для 512-bit ParamSet B отвергается")
    void hasSignatureSchemeRejectsMismatch512() {
        PkixCertTestHelper.CertBundle bundle =
                PkixCertTestHelper.createCertWithKey(ECParameters.tc26b512());
        assertFalse(
                TlsCertUtils.hasSignatureScheme(
                        bundle.cert.getPublicKey(), TlsConstants.SIG_GOST_TC26_512_A));
    }

    @Test
    @DisplayName("hasSignatureScheme с флагом: 0x070D для 512-bit ParamSet B принимается")
    void hasSignatureSchemeInterop512() {
        PkixCertTestHelper.CertBundle bundle =
                PkixCertTestHelper.createCertWithKey(ECParameters.tc26b512());
        assertTrue(
                TlsCertUtils.hasSignatureScheme(
                        bundle.cert.getPublicKey(), TlsConstants.SIG_GOST_TC26_512_A, true));
    }

    @Test
    @DisplayName("hasSignatureScheme с флагом: точное совпадение не ломается")
    void hasSignatureSchemeInteropExactStillWorks() {
        PkixCertTestHelper.CertBundle bundle =
                PkixCertTestHelper.createCertWithKey(ECParameters.tc26a256());
        assertTrue(
                TlsCertUtils.hasSignatureScheme(
                        bundle.cert.getPublicKey(), TlsConstants.SIG_GOST_TC26_A_256, true));
    }

    @Test
    @DisplayName("hasSignatureScheme без флага: точное совпадение для 512-bit")
    void hasSignatureSchemeExact512() {
        PkixCertTestHelper.CertBundle bundle =
                PkixCertTestHelper.createCertWithKey(ECParameters.tc26a512());
        assertTrue(
                TlsCertUtils.hasSignatureScheme(
                        bundle.cert.getPublicKey(), TlsConstants.SIG_GOST_TC26_512_A));
    }

    @Test
    @DisplayName("getNamedGroup: tc26a256 = GRP_GC256A")
    void namedGroupOfTc26a256() {
        GostCertificate cert = PkixCertTestHelper.createCertWithKey(ECParameters.tc26a256()).cert;
        assertEquals(
                TlsConstants.GRP_GC256A,
                TlsCertUtils.getNamedGroup(cert.getPublicKey()),
                "Кривая tc26a256 должна давать группу GRP_GC256A (0x0022)");
    }

    // ========================================================================
    // interopAcceptGostBaseSigScheme: серверная роль
    // ========================================================================

    @Test
    @DisplayName(
            "verifyCertificateVerify с isServer=true, флаг=false: 0x0709 для GC256B отвергается")
    void serverVerifyRejectsWrongSchemeWithoutFlag() {
        GostCertificate cert = PkixCertTestHelper.createCertWithKey(ECParameters.cryptoProA()).cert;
        byte[] cvBody = new byte[4];
        cvBody[0] = (byte) 0x07;
        cvBody[1] = (byte) 0x09; // SIG_GOST_TC26_A_256 (базовая, не для GC256B)
        cvBody[2] = 0x00;
        cvBody[3] = 0x01; // sigLen=1 (минимально, до проверки схемы не доходит)

        TlsException e =
                assertThrows(
                        TlsException.class,
                        () ->
                                TlsCertificateValidator.verifyCertificateVerify(
                                        cvBody, cert, new byte[32], true, false));
        assertTrue(
                e.getMessage().contains("does not match signature scheme"),
                "Без флага: ошибка о несоответствии схемы");
    }

    @Test
    @DisplayName(
            "verifyCertificateVerify с isServer=true, флаг=true: 0x0709 для GC256B принимается (обход)")
    void serverVerifyAcceptsWrongSchemeWithFlag() {
        GostCertificate cert = PkixCertTestHelper.createCertWithKey(ECParameters.cryptoProA()).cert;
        byte[] cvBody = new byte[4];
        cvBody[0] = (byte) 0x07;
        cvBody[1] = (byte) 0x09; // SIG_GOST_TC26_A_256 (базовая, не для GC256B)
        cvBody[2] = 0x00;
        cvBody[3] = 0x01; // sigLen=1

        TlsException e =
                assertThrows(
                        TlsException.class,
                        () ->
                                TlsCertificateValidator.verifyCertificateVerify(
                                        cvBody, cert, new byte[32], true, true));
        assertFalse(
                e.getMessage().contains("does not match signature scheme"),
                "С флагом: ошибка ДОЛЖНА быть от сигнатуры, а не от схемы");
    }
}
