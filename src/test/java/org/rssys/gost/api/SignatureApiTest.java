package org.rssys.gost.api;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.Digest;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.ECPoint;
import org.rssys.gost.signature.PublicKeyParameters;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Signature API Tests")
class SignatureApiTest {

    private static final byte[] MSG = "тестовое сообщение для ГОСТ подписи".getBytes(StandardCharsets.UTF_8);

    // -----------------------------------------------------------------------
    // Roundtrip — CryptoPro-A (256 бит)
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("cryptoProA: sign/verify roundtrip")
    void testRoundtripCryptoProA() {
        KeyPair pair = KeyGenerator.generateKeyPair(ECParameters.cryptoProA());
        try {
            byte[] sig = Signature.sign(MSG, pair.getPrivate());
            assertTrue(Signature.verify(MSG, sig, pair.getPublic()),
                "Подпись должна верифицироваться");
        } finally {
            pair.getPrivate().destroy();
        }
    }

    @Test
    @DisplayName("cryptoProA: длина подписи 64 байта")
    void testSignatureLengthCryptoProA() {
        KeyPair pair = KeyGenerator.generateKeyPair(ECParameters.cryptoProA());
        try {
            byte[] sig = Signature.sign(MSG, pair.getPrivate());
            assertEquals(64, sig.length, "Подпись для 256-битной кривой = 64 байта");
        } finally {
            pair.getPrivate().destroy();
        }
    }

    // -----------------------------------------------------------------------
    // Roundtrip — tc26a256
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("tc26a256: sign/verify roundtrip")
    void testRoundtripTc26a256() {
        KeyPair pair = KeyGenerator.generateKeyPair(ECParameters.tc26a256());
        try {
            byte[] sig = Signature.sign(MSG, pair.getPrivate());
            assertTrue(Signature.verify(MSG, sig, pair.getPublic()));
        } finally {
            pair.getPrivate().destroy();
        }
    }

    // -----------------------------------------------------------------------
    // Roundtrip — tc26a512 (512 бит)
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("tc26a512: sign/verify roundtrip")
    void testRoundtripTc26a512() {
        KeyPair pair = KeyGenerator.generateKeyPair(ECParameters.tc26a512());
        try {
            byte[] sig = Signature.sign(MSG, pair.getPrivate());
            assertTrue(Signature.verify(MSG, sig, pair.getPublic()),
                "Подпись должна верифицироваться для 512-бит кривой");
        } finally {
            pair.getPrivate().destroy();
        }
    }

    @Test
    @DisplayName("tc26a512: длина подписи 128 байт")
    void testSignatureLengthTc26a512() {
        KeyPair pair = KeyGenerator.generateKeyPair(ECParameters.tc26a512());
        try {
            byte[] sig = Signature.sign(MSG, pair.getPrivate());
            assertEquals(128, sig.length, "Подпись для 512-битной кривой = 128 байт");
        } finally {
            pair.getPrivate().destroy();
        }
    }

    // -----------------------------------------------------------------------
    // Детерминированность подписи (RFC 6979)
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("sign: детерминированность — одни данные + один ключ → одна подпись")
    void testSignDeterministic() {
        KeyPair pair = KeyGenerator.generateKeyPair(ECParameters.cryptoProA());
        try {
            byte[] sig1 = Signature.sign(MSG, pair.getPrivate());
            byte[] sig2 = Signature.sign(MSG, pair.getPrivate());
            assertArrayEquals(sig1, sig2, "RFC 6979: подпись должна быть детерминированной");
        } finally {
            pair.getPrivate().destroy();
        }
    }

    // -----------------------------------------------------------------------
    // Негативные тесты
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("verify: подменённые данные → false")
    void testVerifyTamperedData() {
        KeyPair pair = KeyGenerator.generateKeyPair(ECParameters.cryptoProA());
        try {
            byte[] sig = Signature.sign(MSG, pair.getPrivate());
            byte[] tampered = MSG.clone();
            tampered[0] ^= 0x01;
            assertFalse(Signature.verify(tampered, sig, pair.getPublic()),
                "Подменённые данные должны отвергаться");
        } finally {
            pair.getPrivate().destroy();
        }
    }

    @Test
    @DisplayName("verify: подменённая подпись → false")
    void testVerifyTamperedSignature() {
        KeyPair pair = KeyGenerator.generateKeyPair(ECParameters.cryptoProA());
        try {
            byte[] sig = Signature.sign(MSG, pair.getPrivate());
            byte[] tampered = sig.clone();
            tampered[0] ^= 0x01;
            assertFalse(Signature.verify(MSG, tampered, pair.getPublic()),
                "Подменённая подпись должна отвергаться");
        } finally {
            pair.getPrivate().destroy();
        }
    }

    @Test
    @DisplayName("verify: чужой открытый ключ → false")
    void testVerifyWrongKey() {
        ECParameters params = ECParameters.cryptoProA();
        KeyPair pair1 = KeyGenerator.generateKeyPair(params);
        KeyPair pair2 = KeyGenerator.generateKeyPair(params);
        try {
            byte[] sig = Signature.sign(MSG, pair1.getPrivate());
            assertFalse(Signature.verify(MSG, sig, pair2.getPublic()),
                "Чужой ключ должен отвергать подпись");
        } finally {
            pair1.getPrivate().destroy();
            pair2.getPrivate().destroy();
        }
    }

    // -----------------------------------------------------------------------
    // derivePublicKey
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("derivePublicKey: совпадает с Q из generateKeyPair")
    void testDerivePublicKey() {
        ECParameters params = ECParameters.cryptoProA();
        KeyPair pair = KeyGenerator.generateKeyPair(params);
        try {
            PublicKeyParameters derived = Signature.derivePublicKey(pair.getPrivate());
            ECPoint q1 = pair.getPublic().getQ().normalize();
            ECPoint q2 = derived.getQ().normalize();
            assertEquals(q1.getX(), q2.getX(), "Qx должен совпадать");
            assertEquals(q1.getY(), q2.getY(), "Qy должен совпадать");
        } finally {
            pair.getPrivate().destroy();
        }
    }

    @Test
    @DisplayName("derivePublicKey: полученный ключ можно использовать для верификации")
    void testDerivePublicKeyCanVerify() {
        KeyPair pair = KeyGenerator.generateKeyPair(ECParameters.cryptoProA());
        try {
            byte[] sig = Signature.sign(MSG, pair.getPrivate());
            PublicKeyParameters derived = Signature.derivePublicKey(pair.getPrivate());
            assertTrue(Signature.verify(MSG, sig, derived),
                "Производный открытый ключ должен верифицировать подпись");
        } finally {
            pair.getPrivate().destroy();
        }
    }

    // -----------------------------------------------------------------------
    // Несколько кривых
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Все кривые: roundtrip sign/verify")
    void testAllCurves() {
        ECParameters[] curves = {
            ECParameters.tc26a256(),
            ECParameters.tc26a512(),
            ECParameters.tc26b512(),
            ECParameters.tc26c512(),
            ECParameters.cryptoProA(),
            ECParameters.cryptoProB(),
            ECParameters.cryptoProC()
        };

        for (ECParameters params : curves) {
            KeyPair pair = KeyGenerator.generateKeyPair(params);
            try {
                byte[] sig = Signature.sign(MSG, pair.getPrivate());
                assertTrue(Signature.verify(MSG, sig, pair.getPublic()),
                    "Roundtrip должен проходить для кривой: " +
                    params.p.toString(16).substring(0, 8) + "...");
            } finally {
                pair.getPrivate().destroy();
            }
        }
    }

    // -----------------------------------------------------------------------
    // signHash / verifyHash — подпись готового хэша
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("signHash/verifyHash: roundtrip с готовым хэшем (cryptoProA)")
    void testSignHashRoundtrip() {
        KeyPair pair = KeyGenerator.generateKeyPair(ECParameters.cryptoProA());
        try {
            byte[] hash = Digest.digest256(MSG);

            byte[] sig = Signature.signHash(hash, pair.getPrivate());
            assertEquals(64, sig.length, "Подпись для 256-битной кривой = 64 байта");
            assertTrue(Signature.verifyHash(hash, sig, pair.getPublic()),
                "verifyHash должен верифицировать подпись готового хэша");
        } finally {
            pair.getPrivate().destroy();
        }
    }

    @Test
    @DisplayName("signHash результат совпадает с sign для тех же данных")
    void testSignHashConsistentWithSign() {
        KeyPair pair = KeyGenerator.generateKeyPair(ECParameters.cryptoProA());
        try {
            byte[] hash = Digest.digest256(MSG);

            byte[] sigFromData = Signature.sign(MSG, pair.getPrivate());
            byte[] sigFromHash = Signature.signHash(hash, pair.getPrivate());

            assertArrayEquals(sigFromData, sigFromHash,
                "signHash(digest256(data)) должен давать ту же подпись что и sign(data)");
        } finally {
            pair.getPrivate().destroy();
        }
    }

    @Test
    @DisplayName("sign + verifyHash: кросс-совместимость (sign → verifyHash)")
    void testSignThenVerifyHash() {
        KeyPair pair = KeyGenerator.generateKeyPair(ECParameters.cryptoProA());
        try {
            byte[] sig  = Signature.sign(MSG, pair.getPrivate());
            byte[] hash = Digest.digest256(MSG);

            assertTrue(Signature.verifyHash(hash, sig, pair.getPublic()),
                "verifyHash должен принимать подпись, созданную через sign");
        } finally {
            pair.getPrivate().destroy();
        }
    }

    @Test
    @DisplayName("signHash + verify: кросс-совместимость (signHash → verify)")
    void testSignHashThenVerify() {
        KeyPair pair = KeyGenerator.generateKeyPair(ECParameters.cryptoProA());
        try {
            byte[] hash = Digest.digest256(MSG);
            byte[] sig  = Signature.signHash(hash, pair.getPrivate());

            assertTrue(Signature.verify(MSG, sig, pair.getPublic()),
                "verify должен принимать подпись, созданную через signHash");
        } finally {
            pair.getPrivate().destroy();
        }
    }

    @Test
    @DisplayName("signHash: неверная длина хэша → IllegalArgumentException")
    void testSignHashWrongLength() {
        KeyPair pair = KeyGenerator.generateKeyPair(ECParameters.cryptoProA());
        try {
            byte[] wrongHash = new byte[16]; // ожидается 32
            assertThrows(IllegalArgumentException.class,
                () -> Signature.signHash(wrongHash, pair.getPrivate()),
                "Хэш неверной длины должен вызывать IllegalArgumentException");
        } finally {
            pair.getPrivate().destroy();
        }
    }

    @Test
    @DisplayName("verifyHash: подменённый хэш → false")
    void testVerifyHashTamperedHash() {
        KeyPair pair = KeyGenerator.generateKeyPair(ECParameters.cryptoProA());
        try {
            byte[] hash    = Digest.digest256(MSG);
            byte[] sig     = Signature.signHash(hash, pair.getPrivate());
            byte[] tampered = hash.clone();
            tampered[0] ^= 0x01;

            assertFalse(Signature.verifyHash(tampered, sig, pair.getPublic()),
                "Подменённый хэш должен отвергаться");
        } finally {
            pair.getPrivate().destroy();
        }
    }

    @Test
    @DisplayName("signHash/verifyHash: roundtrip для 512-битной кривой (tc26a512)")
    void testSignHashRoundtrip512() {
        KeyPair pair = KeyGenerator.generateKeyPair(ECParameters.tc26a512());
        try {
            byte[] hash = Digest.digest512(MSG);

            byte[] sig = Signature.signHash(hash, pair.getPrivate());
            assertEquals(128, sig.length, "Подпись для 512-битной кривой = 128 байт");
            assertTrue(Signature.verifyHash(hash, sig, pair.getPublic()),
                "verifyHash должен верифицировать подпись для 512-бит кривой");
        } finally {
            pair.getPrivate().destroy();
        }
    }
}
