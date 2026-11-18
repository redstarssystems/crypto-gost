package org.rssys.gost.signature;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.math.BigInteger;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.rssys.gost.api.Signature;

/**
 * Внешние эталоны {@code d -> Q} для всех 7 зарегистрированных кривых.
 * <p>
 * Сравнение {@code d·G} с самим же {@code g.multiply(d)} ошибку скалярного умножения не
 * заметило бы, а после того как для зарегистрированных кривых пропущена повторная проверка
 * подгруппы, неверное {@code Q} никто больше не поймает. Поэтому пары {@code (d, Q)} получены
 * независимой реализацией: OpenSSL 3.5.7 с gost-engine, {@code genpkey} и
 * {@code pkey -text}; для TC26-A-256 это paramset {@code TCA}. Ключи одноразовые, тестовые.
 */
@DisplayName("derivePublicKey: эталонные пары d -> Q от независимой реализации")
class DerivePublicKeyReferenceTest {

    static Stream<Arguments> vectors() {
        return Stream.of(
                Arguments.of(
                        "TC26-A-256",
                        ECParameters.tc26a256(),
                        "03990BA0A0C5FE9169759EAB93B715DFE4E355F707FD3A2977213DB5EA472241",
                        "F4B46F3592AF88528C3AE6164A6A1A9316B710D39E432F219EEB130AC8526EE9",
                        "23392C997E29815A4BF56702F6425F0C23704FA2DDE3BBE37AA0D13A6BB0BA84"),
                Arguments.of(
                        "CryptoPro-A",
                        ECParameters.cryptoProA(),
                        "BB809015C1956BDCAC3E05BA97A573B98E2FB1C09A82EE79044C78C23912AE41",
                        "92C8AC51BBBDC6E1ED020CD934F87F46CDE5910AB3189DDBCE9C958EDFC7B45E",
                        "55073B55E541E4092C9AE19DF5FF9E13F7E6EFDA93FD1AA6E628D370E42958E3"),
                Arguments.of(
                        "CryptoPro-B",
                        ECParameters.cryptoProB(),
                        "051A570334C4F2C3FD7F954359E6949131D2563FD7179D4F150E5817869A8E63",
                        "4D05AFF43C372FD44AFAE7FECD90C4C19AAEB2264972E4EB66B3087BDCB9BD33",
                        "05FE64800EF10C98E336B87A8AFC3E97A08DD69C9C348ACD7B4D8EF08DFAC334"),
                Arguments.of(
                        "CryptoPro-C",
                        ECParameters.cryptoProC(),
                        "8D93604D785B82791EDC38DDE97ECD1AE93709AB578929AF2EC8C81D5E2A3E90",
                        "7CF9414E929B1943697AB210AC6BC9B7E8B7FC292CA7B4B7FF9EE19BBE062CE9",
                        "4664BA72A38767F68535E667969FEBC0DD04C63862A0CE7FB8B86AB101156AF7"),
                Arguments.of(
                        "TC26-A-512",
                        ECParameters.tc26a512(),
                        "C22490795E5CE321D19DFC7A03B388F8A604A0586DEF047E9946C5E1FC9DA3CC"
                                + "C518D1DCE66B8D523C5DAE2D18418AD59CAE6109F5C11E350D5DF5204598991A",
                        "E235F99890C6A067E800400393B97810A3A9442670FE043EC3DBB9A7EF3F7B52"
                                + "FB515E7FC086EC188A5FEAB5F8693337224AE9177DFED8722B4CD3726F474979",
                        "5460276578D4D6496D2991FCB58D7E30497287E33DAC9AEBF1C5A6986D6A1D4D"
                                + "39F8CEF862BD9D90A7FAFE24B1016D5ED127FA9BF5CC3BE0395F1465B01CF976"),
                Arguments.of(
                        "TC26-B-512",
                        ECParameters.tc26b512(),
                        "339F9F182B3F6725E5F600F57DBF08DBCC307664EE279DF42D0D4F04244C4B0B"
                                + "40A6BEAC465241C8B2859753F8835C2F70E09CECFE90F9FCCDDBFFA6298CEFFF",
                        "2AF95856CFD8F58386133B6745D174FD454D691863100AF8001F22142039CBCD"
                                + "F897CF90964FF78F9FB0046AD6476D62B45586B036BAB448B9148A886FD552AD",
                        "103DB8508977A0558555BAB4909E544378903E5A829375844446E97E9CC0D690"
                                + "02A9544B18D9B7CF6E329D70B4D86255A3540CC0B2B2E378BFB2DF53A9C617FE"),
                Arguments.of(
                        "TC26-C-512",
                        ECParameters.tc26c512(),
                        "07D27B10A55B4EC288455CB08308FEAEE0A4315A28B01DCC7D1874E378AD1119"
                                + "DDD1F52AB98BBC518C81D4234DC12B2A008E097CA4BD0ADF1F939CDBDB64F50A",
                        "38F10BD1A1F04C2220C33A16F661CC62D07E98BADC0017C6CF2A1DEA8D57FFF9"
                                + "92E2EC89CC5D901D7FD9DAB1F32A9C40BBF8F59F9EE5ABA00A82A3684D9739C5",
                        "92A9055003275A9BEDBAD1F5C9F83CEE928D2D9D1BBEE858A6ADD99EA0C483A3"
                                + "1E78B3A70C65E27CFFDA76935ECCF80BC7DA2D48DD08A2C5380A7FA587F372AE"));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    @DisplayName("Q = d·G совпадает с открытым ключом, выданным OpenSSL")
    void derivedKeyMatchesReference(
            String name, ECParameters params, String dHex, String xHex, String yHex) {
        PrivateKeyParameters priv = new PrivateKeyParameters(new BigInteger(dHex, 16), params);
        ECPoint viaMethod = priv.derivePublicKey().getQ();
        ECPoint viaSignature = Signature.derivePublicKey(priv).getQ();
        BigInteger x = new BigInteger(xHex, 16);
        BigInteger y = new BigInteger(yHex, 16);
        assertEquals(x, viaMethod.getX(), "x открытого ключа, выведенного из d");
        assertEquals(y, viaMethod.getY(), "y открытого ключа, выведенного из d");
        assertEquals(x, viaSignature.getX(), "x через Signature.derivePublicKey");
        assertEquals(y, viaSignature.getY(), "y через Signature.derivePublicKey");
    }
}
