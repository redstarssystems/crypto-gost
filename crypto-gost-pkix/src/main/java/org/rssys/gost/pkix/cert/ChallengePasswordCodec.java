package org.rssys.gost.pkix.cert;

import static org.rssys.gost.pkix.cert.GostDerParser.TAG_BMP_STRING;
import static org.rssys.gost.pkix.cert.GostDerParser.TAG_T61_STRING;
import static org.rssys.gost.pkix.cert.GostDerParser.TAG_UNIVERSAL_STRING;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.CoderResult;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.rssys.gost.util.DerCodec;

/**
 * Кодек значения атрибута {@code challengePassword} (RFC 2985 §5.4.1, тип {@code DirectoryString}).
 *
 * <p>Единое место правил для записи (сборщик CSR) и чтения (разборщик CSR), чтобы они не
 * разъехались. Пароль нигде не превращается в {@link String}: копию строки затереть нельзя.
 * Сообщения исключений не содержат ни пароля, ни его фрагментов.</p>
 *
 * <p><b>Правила, общие для записи и чтения:</b></p>
 * <ul>
 *   <li>от 1 до 255 знаков (code points) после декодирования
 *       ({@code pkcs-9-ub-challengePassword});</li>
 *   <li>не более 255 байт в содержимом закодированного значения (RFC 7030 §3.5);</li>
 *   <li>никаких управляющих знаков ({@link Character#CONTROL}: C0, U+007F, C1): у них нет
 *       законного применения в пароле, NUL обрезает значение у пиров на C-строках, а U+009B
 *       терминалы читают как начало управляющей последовательности. Проверка идёт по code point,
 *       до выбора типа строки, чтобы суррогатная пара не читалась как два знака;</li>
 *   <li>одиночный суррогат недопустим.</li>
 * </ul>
 *
 * <p><b>Разные политики записи и чтения алфавита PrintableString.</b> При записи PrintableString
 * выбирается только если все знаки входят в алфавит X.680, иначе пароль уходит в UTF8String.
 * При чтении алфавит X.680 не применяется: старые кодировщики кладут в PrintableString
 * произвольный ASCII, и отказ сломал бы приём чужих запросов.</p>
 *
 * <p>{@code TeletexString} читается как ISO-8859-1 (как OpenSSL и {@link GostDnParser}):
 * настоящий набор T.61 почти нигде не реализован.</p>
 */
final class ChallengePasswordCodec {

    /** Предел RFC 2985 ({@code ub-challengePassword}) в знаках и RFC 7030 §3.5 в байтах. */
    static final int MAX_LENGTH = 255;

    private static final int ASCII_MAX = 0x7F;
    private static final int BMP_MAX = 0xFFFF;
    private static final Charset UTF_32_BE = Charset.forName("UTF-32BE");

    private ChallengePasswordCodec() {}

    /**
     * Кодирует пароль в TLV {@code DirectoryString}: PrintableString, если все знаки входят в
     * алфавит X.680, иначе UTF8String.
     *
     * <p>Не использует {@link DerCodec#encodePrintableString(String)}: он молча подменяет
     * не-ASCII знаки на {@code ?}. Возвращённый TLV содержит пароль, затирает его вызывающий.</p>
     *
     * @param password пароль, не изменяется и не затирается
     * @return TLV значения
     * @throws IllegalArgumentException если пароль {@code null}, пуст или нарушает правила
     */
    static byte[] encode(char[] password) {
        if (password == null) {
            throw new IllegalArgumentException("challengePassword must not be null");
        }
        boolean printable = true;
        int codePoints = 0;
        for (int i = 0; i < password.length; ) {
            int cp = Character.codePointAt(password, i);
            requireAllowedCodePoint(cp);
            printable &= GostDerParser.isPrintableStringChar(cp);
            codePoints++;
            i += Character.charCount(cp);
        }
        requireLengthInCodePoints(codePoints);

        byte[] content = printable ? encodeAscii(password) : encodeUtf8(password);
        try {
            if (content.length > MAX_LENGTH) {
                throw new IllegalArgumentException(
                        "challengePassword encoding exceeds " + MAX_LENGTH + " bytes");
            }
            return DerCodec.encodeTlv(
                    printable ? DerCodec.TAG_PRINTABLE_STRING : DerCodec.TAG_UTF8_STRING, content);
        } finally {
            Arrays.fill(content, (byte) 0);
        }
    }

    /**
     * Декодирует содержимое значения {@code DirectoryString} сразу в {@code char[]}.
     *
     * @param der   DER-поток
     * @param tag   тег строки
     * @param start начало содержимого
     * @param end   конец содержимого (за последним байтом)
     * @return пароль; массив затирает вызывающий
     * @throws IllegalArgumentException если тип не входит в {@code DirectoryString}, кодировка
     *     некорректна или нарушены общие правила
     */
    static char[] decode(byte[] der, int tag, int start, int end) {
        int length = end - start;
        if (length == 0) {
            throw new IllegalArgumentException("challengePassword must not be empty");
        }
        if (length > MAX_LENGTH) {
            throw new IllegalArgumentException(
                    "challengePassword exceeds " + MAX_LENGTH + " bytes");
        }
        CharsetDecoder decoder = newDecoder(tag, length);
        // знаков не больше, чем байтов: самый «тесный» случай — однобайтовые кодировки
        CharBuffer decoded = CharBuffer.allocate(length);
        char[] result = null;
        try {
            decodeStrict(decoder, ByteBuffer.wrap(der, start, length), decoded);
            decoded.flip();
            result = new char[decoded.remaining()];
            decoded.get(result);

            int codePoints = 0;
            for (int i = 0; i < result.length; ) {
                int cp = Character.codePointAt(result, i);
                requireAllowedCodePoint(cp);
                if (tag == TAG_BMP_STRING && cp > BMP_MAX) {
                    throw new IllegalArgumentException(
                            "BMPString must not contain surrogate pairs");
                }
                codePoints++;
                i += Character.charCount(cp);
            }
            requireLengthInCodePoints(codePoints);
            char[] ok = result;
            result = null;
            return ok;
        } finally {
            Arrays.fill(decoded.array(), '\0');
            if (result != null) {
                Arrays.fill(result, '\0');
            }
        }
    }

    private static CharsetDecoder newDecoder(int tag, int length) {
        Charset charset;
        switch (tag) {
            case DerCodec.TAG_UTF8_STRING:
                charset = StandardCharsets.UTF_8;
                break;
            case DerCodec.TAG_PRINTABLE_STRING:
                // алфавит X.680 при чтении сознательно не проверяется, байт >0x7F — ошибка
                charset = StandardCharsets.US_ASCII;
                break;
            case TAG_T61_STRING:
                charset = StandardCharsets.ISO_8859_1;
                break;
            case TAG_BMP_STRING:
                if ((length & 1) != 0) {
                    throw new IllegalArgumentException("BMPString length must be even");
                }
                charset = StandardCharsets.UTF_16BE;
                break;
            case TAG_UNIVERSAL_STRING:
                if ((length & 3) != 0) {
                    throw new IllegalArgumentException(
                            "UniversalString length must be a multiple of 4");
                }
                charset = UTF_32_BE;
                break;
            default:
                throw new IllegalArgumentException(
                        "challengePassword must be a DirectoryString, got tag " + tag);
        }
        return charset.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
    }

    private static void decodeStrict(CharsetDecoder decoder, ByteBuffer in, CharBuffer out) {
        CoderResult result = decoder.decode(in, out, true);
        if (result.isUnderflow()) {
            result = decoder.flush(out);
        }
        if (!result.isUnderflow()) {
            throw new IllegalArgumentException("challengePassword has an invalid encoding");
        }
    }

    private static void requireAllowedCodePoint(int cp) {
        if (cp >= Character.MIN_SURROGATE && cp <= Character.MAX_SURROGATE) {
            throw new IllegalArgumentException("challengePassword contains an unpaired surrogate");
        }
        if (Character.getType(cp) == Character.CONTROL) {
            throw new IllegalArgumentException("challengePassword contains a control character");
        }
    }

    private static void requireLengthInCodePoints(int codePoints) {
        if (codePoints < 1 || codePoints > MAX_LENGTH) {
            throw new IllegalArgumentException(
                    "challengePassword must contain 1.." + MAX_LENGTH + " characters");
        }
    }

    /** Знаки уже проверены на принадлежность алфавиту PrintableString, то есть на ASCII. */
    private static byte[] encodeAscii(char[] password) {
        byte[] bytes = new byte[password.length];
        for (int i = 0; i < password.length; i++) {
            if (password[i] > ASCII_MAX) {
                Arrays.fill(bytes, (byte) 0);
                throw new IllegalStateException("PrintableString alphabet check was bypassed");
            }
            bytes[i] = (byte) password[i];
        }
        return bytes;
    }

    private static byte[] encodeUtf8(char[] password) {
        CharsetEncoder encoder =
                StandardCharsets.UTF_8
                        .newEncoder()
                        .onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT);
        ByteBuffer buffer;
        try {
            buffer = encoder.encode(CharBuffer.wrap(password));
        } catch (CharacterCodingException e) {
            // сообщение исключения может нести позицию знака, но не сам знак
            throw new IllegalArgumentException("challengePassword is not valid text");
        }
        try {
            byte[] bytes = new byte[buffer.remaining()];
            buffer.get(bytes);
            return bytes;
        } finally {
            Arrays.fill(buffer.array(), (byte) 0);
        }
    }
}
