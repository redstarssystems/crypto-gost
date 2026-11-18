package org.rssys.gost.api;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;
import org.rssys.gost.cipher.Kuznyechik;
import org.rssys.gost.cipher.ParametersWithIV;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.cipher.mode.Ctr;
import org.rssys.gost.mac.Cmac;
import org.rssys.gost.util.AuthenticationException;
import org.rssys.gost.util.AuthenticationIOException;
import org.rssys.gost.util.ConstantTime;
import org.rssys.gost.util.CryptoRandom;
import org.rssys.gost.util.Pack;

/**
 * API для потокового аутентифицированного шифрования
 * с разбиением на чанки; CMAC и CTR - на шифре Кузнечик (ГОСТ Р 34.12-2015).
 *
 * <h3>Зачем chunking?</h3>
 * CMAC вычисляется от шифртекста и требует знания всех данных перед
 * шифрованием. Для потока произвольного размера данные разбиваются на
 * чанки фиксированного размера. Каждый чанк имеет собственный CMAC и проверяется
 * до расшифрования. Память потребляется O(chunkSize), а не O(totalData).
 *
 * <h3>Формат потока (Encrypt-then-MAC):</h3>
 * <pre>
 * Заголовок (21 байт):
 *   version[1]      = 0x03
 *   streamNonce[16] = случайные байты (CryptoRandom, per-stream)
 *   chunkSize[4]    = размер чанка в байтах (big-endian int)
 *
 * Каждый чанк (21 + N байт):
 *   chunkLen[4]  = длина ciphertext, big-endian int: ровно chunkSize для обычного чанка,
 *                  от 0 до chunkSize для последнего
 *   flags[1]     = 0x00 обычный / 0x01 последний чанк (иные значения отвергаются)
 *   CMAC[16]     = CMAC(AAD чанка ‖ ciphertext), полный тег 128 бит;
 *                  AAD чанка = seqNo[8] ‖ flags[1] ‖ [заголовок потока, только у первого чанка]
 *   ciphertext[N]
 * </pre>
 *
 * <h3>Внешний AAD</h3>
 * Внешний AAD - контекст (имя файла, получатель, идентификатор сессии), который проверяется
 * вместе с потоком, но не шифруется, не передаётся и не затирается: секреты в AAD не класть. Его не следует путать с AAD чанка выше: тот
 * служебный и записан в самом потоке. Внешний AAD в поток не пишется и в CMAC не входит. Он входит
 * в вывод ключей потока: затравка KDF - это {@code streamNonce ‖ aad}. Поэтому формат потока от AAD
 * не зависит, а при пустом AAD поток побайтово совпадает с потоком без AAD. Читатель обязан знать
 * то же значение до {@code opening}. Неверный AAD неотличим от неверного ключа: отказ приходит
 * при чтении чанка 0. {@code null} равнозначен пустому массиву. Если AAD составлен из нескольких
 * полей, их склеивает вызывающий так, чтобы граница между полями была однозначной (например, с
 * длиной перед каждым полем). Обработка AAD добавляет два прохода HMAC-Стрибог по его байтам,
 * поэтому AAD должен быть коротким контекстом, а не данными.
 *
 * <h3>Гамма</h3>
 * Весь поток - одно сообщение в режиме CTR с нулевым IV: ключ CTR выводится из мастер-ключа и
 * случайного {@code streamNonce} и свой у каждого потока, а счётчик не сбрасывается между чанками.
 * Поэтому гамма не повторяется внутри потока при любых размерах чанков. Если {@code chunkSize}
 * не кратен 16, блок гаммы делится между соседними чанками.
 *
 * <p>Номер чанка {@code seqNo} не передаётся по проводу, а входит в AAD чанка: он защищает от
 * перестановки и дублирования чанков и служит единственной привязкой чанка к его месту в гамме.
 * Без него обмен двух чанков равной длины проходил бы проверку тега и давал бы мусор вместо
 * открытого текста. Из той же непрерывности следует, что расшифрование чанка зависит от того,
 * что все предыдущие чанки прочитаны по порядку: произвольного доступа (seek) нет, это
 * осознанное решение.
 *
 * <p>Флаг последнего чанка защищает от усечения потока:
 * если поток обрезан до финального чанка — расшифрование выбросит
 * {@link AuthenticationException}.
 *
 * <p><b>Состояние после ошибки.</b> После любой ошибки чтения (целостность, усечение или
 * {@link IOException} нижнего потока) читающий поток непригоден: повторный {@code read()} снова
 * бросает исключение, а не возвращает {@code -1}, который выглядел бы как чистый конец потока и
 * скрывал бы усечение. Поток нужно закрыть.
 *
 * <p>Мастер-ключ — ключ Кузнечика ровно 32 байта; ключ другой длины отвергается с
 * {@link IllegalArgumentException}. Из него и случайного {@code streamNonce} выводятся
 * отдельные ключи CMAC и CTR потока.
 *
 * <h3>Пределы</h3>
 * <ul>
 *   <li>Число потоков под одним мастер-ключом: не более ≈2⁴⁸. Нонс 128 бит, вероятность
 *       совпадения у q потоков ≈ q²/2¹²⁹, при 2⁴⁸ потоков ≈2⁻³³. Совпавший нонс означает
 *       одинаковые ключи и повтор всей гаммы потока целиком.</li>
 *   <li>Объём одного потока: ключи CMAC и CTR один на весь поток. Практический потолок задаёт
 *       общая оценка σ²/2¹²⁸, где σ - число блоков потока: например, 2⁴⁰ блоков по 16 байт (2⁴⁴ байт, 16 ТиБ) дают
 *       ≈2⁻⁴⁸.</li>
 *   <li>Жёсткая граница конструкции: 2⁶⁴ блоков (2⁶⁸ байт). Дальше младшая половина счётчика CTR
 *       переходит через ноль без переноса в старшую, и гамма повторяется. Она недостижима на
 *       практике и намного выше рабочего потолка.</li>
 * </ul>
 *
 * <h3>Пример использования:</h3>
 * <pre>{@code
 * SymmetricKey key = KeyGenerator.generateSymmetricKey();
 *
 * // Шифрование
 * try (OutputStream sealed = AuthenticatedStream.sealing(fileOut, key)) {
 *     sealed.write(data);
 * }
 *
 * // Расшифрование
 * try (InputStream opened = AuthenticatedStream.opening(fileIn, key)) {
 *     byte[] buf = new byte[4096];
 *     int n;
 *     while ((n = opened.read(buf)) > 0) {
 *         process(buf, 0, n);
 *     }
 * } catch (AuthenticationException | AuthenticationIOException e) {
 *     // Поток повреждён, изменён или усечён (проверяемое исключение приходит из read()
 *     // завёрнутым в AuthenticationIOException; обычная ошибка ввода-вывода - это IOException)
 * }
 *
 * // С внешним AAD: поток привязан к контексту, например к имени файла
 * byte[] aad = "report-2026.pdf".getBytes(StandardCharsets.UTF_8);
 * try (OutputStream sealed = AuthenticatedStream.sealing(fileOut, key, aad)) {
 *     sealed.write(data);
 * }
 * try (InputStream opened = AuthenticatedStream.opening(fileIn, key, aad)) { // тот же AAD
 *     opened.transferTo(target);
 * }
 * }</pre>
 *
 * <p><b>Усечение.</b> Конец потока до чанка с флагом последнего (в том числе посреди чанка или
 * заголовка) считается нарушением целостности ({@link AuthenticationException}, при чтении -
 * {@link AuthenticationIOException}), а не ошибкой ввода-вывода. Прочие {@code IOException}
 * нижнего потока передаются без изменений. Открытый текст выдаётся по мере проверки чанков, а
 * об усечении читатель узнаёт только в конце: необратимые действия над данными можно делать
 * лишь после того, как {@code read} вернул {@code -1}.
 *
 * <p><b>Ключ и AAD проверяются при первом чтении.</b> {@code opening} читает только заголовок и не
 * может отличить неверный ключ или неверный внешний AAD от верных: ошибка появляется при чтении
 * первого чанка. У пустого потока это первый {@code read()}, который иначе вернул бы {@code -1};
 * если поток не читать, проверки нет. Со стороны записи последний чанк с тегом пишут
 * {@code finish()} или {@code close()}.
 *
 * <p><b>Повтор потока целиком.</b> Перестановка и дублирование чанков внутри потока
 * обнаруживаются, но замену потока другим валидным потоком под тем же ключом и тем же AAD или
 * его повтор целиком схема не замечает. Внешний AAD (имя файла, получатель, номер сообщения)
 * привязывает поток к контексту, но повтор сам не обнаруживает: чтобы обнаружить его, вызывающий
 * кладёт в AAD номер сообщения и ведёт счётчик.
 *
 * <p><b>Данные после последнего чанка.</b> Читающий поток останавливается на чанке с флагом
 * последнего и не читает дальше: байты за ним не аутентифицируются и не проверяются. Это
 * позволяет встраивать защищённый поток в более длинный (например, в сокет, где за ним идут другие
 * данные). {@code close()} обоих потоков закрывает нижний поток, как у {@code FilterOutputStream} и
 * {@code FilterInputStream}; если нижний поток должен остаться открытым, передайте обёртку, не
 * закрывающую его.
 *
 * <p><b>Не потокобезопасен.</b> Создавайте отдельный экземпляр на каждое соединение.
 */
public final class AuthenticatedStream {

    /** Размер чанка по умолчанию: 64 КБ. */
    public static final int DEFAULT_CHUNK_SIZE = 65536;

    /** Версия формата. */
    static final byte VERSION = 0x03;

    /**
     * Размер случайного nonce потока: 128 бит. Из мастер-ключа и nonce выводятся ключи потока;
     * совпадение nonce двух потоков под одним мастер-ключом означало бы одинаковые ключи и гамму
     * CTR. У q потоков вероятность совпадения ≈ q²/2¹²⁹.
     */
    static final int NONCE_SIZE = 16;

    /** Минимальный размер чанка в байтах. */
    static final int MIN_CHUNK_SIZE = 16;

    /** Флаг: обычный чанк. */
    static final byte FLAG_NORMAL = 0x00;

    /** Флаг: последний чанк (защита от усечения потока). */
    static final byte FLAG_LAST = 0x01;

    /**
     * Максимальный размер чанка. Писатель отвергает больший размер при создании, читатель - в
     * заголовке: иначе записанный поток нельзя было бы прочитать.
     */
    static final int MAX_CHUNK_SIZE = 1_048_576; // 1 МБ

    /**
     * Смещения полей заголовка потока: версия идёт первой, чтобы читатель находил её по
     * фиксированному смещению независимо от размеров остальных полей.
     */
    private static final int VERSION_OFFSET = 0;

    private static final int NONCE_OFFSET = VERSION_OFFSET + 1;
    private static final int CHUNK_SIZE_OFFSET = NONCE_OFFSET + NONCE_SIZE;

    /** Размер заголовка потока в байтах: version(1) + nonce(16) + chunkSize(4). */
    static final int HEADER_SIZE = CHUNK_SIZE_OFFSET + 4;

    /** Смещения полей заголовка чанка: chunkLen(4), flags(1), CMAC(16). */
    private static final int CHUNK_FLAGS_OFFSET = 4;

    private static final int CHUNK_TAG_OFFSET = CHUNK_FLAGS_OFFSET + 1;

    /** Размер заголовка чанка: chunkLen(4) + flags(1) + CMAC(16). */
    static final int CHUNK_HEADER_SIZE = CHUNK_TAG_OFFSET + AuthenticatedCipher.TAG_LEN;

    /** Размер начала AAD чанка: seqNo(8) + flags(1). */
    private static final int CHUNK_AAD_PREFIX_SIZE = 9;

    /** Наибольший размер AAD чанка: seqNo(8), flags(1) и заголовок потока (только у первого). */
    private static final int MAX_CHUNK_AAD_SIZE = CHUNK_AAD_PREFIX_SIZE + HEADER_SIZE;

    /**
     * Метка для KDF: генерация per-stream ключей. Метка разделяет назначения ключей (поток, шифр
     * пакета), а не версии формата. Перенос тегов между раскладками заголовка закрыт тем, что
     * заголовок целиком входит в AAD первого чанка: он содержит и версию, и nonce, из которого
     * выводятся ключи.
     *
     * <p>Внешний AAD метку не меняет: он входит в затравку, а назначение ключей и конструкция при
     * пустом AAD прежние.
     */
    static final String KDF_LABEL_NAME = "auth-stream";

    private static final byte[] KDF_LABEL = KDF_LABEL_NAME.getBytes(StandardCharsets.US_ASCII);

    private AuthenticatedStream() {}

    // -----------------------------------------------------------------------
    // Одноключевой API
    // -----------------------------------------------------------------------

    /**
     * Создаёт шифрующий поток с аутентификацией.
     *
     * <p>Записывает заголовок потока сразу при создании. Данные разбиваются
     * на чанки по {@link #DEFAULT_CHUNK_SIZE} байт; чанк уходит при заполнении буфера, а
     * {@link SealingStream#finish()} или {@link SealingStream#close()} записывает последний чанк.
     * {@code close()} затем закрывает {@code out}, {@code finish()} оставляет его открытым.
     *
     * @param out выходной поток с зашифрованными данными
     * @param key мастер-ключ шифрования (32 байта)
     * @return шифрующий поток {@link SealingStream}
     * @throws IOException если не удалось записать заголовок
     * @throws IllegalArgumentException если длина ключа не равна 32 байтам
     */
    public static SealingStream sealing(OutputStream out, SymmetricKey key) throws IOException {
        return sealing(out, key, DEFAULT_CHUNK_SIZE, AuthenticatedCipher.NO_AAD);
    }

    /**
     * Создаёт шифрующий поток с внешним AAD и размером чанка по умолчанию.
     *
     * <p>Внешний AAD (контекст: имя файла, получатель, идентификатор сессии) в поток не пишется:
     * он входит в вывод ключей потока вместе с {@code streamNonce}. Читатель обязан передать то же
     * значение в {@link #opening(InputStream, SymmetricKey, byte[])}.
     *
     * @param out выходной поток с зашифрованными данными
     * @param key мастер-ключ шифрования (32 байта)
     * @param aad внешний AAD; {@code null} равнозначен пустому массиву
     * @return шифрующий поток {@link SealingStream}
     * @throws IOException если не удалось записать заголовок
     * @throws IllegalArgumentException если длина ключа не равна 32 байтам
     */
    public static SealingStream sealing(OutputStream out, SymmetricKey key, byte[] aad)
            throws IOException {
        return sealing(out, key, DEFAULT_CHUNK_SIZE, aad);
    }

    /**
     * Создаёт шифрующий поток с аутентификацией и заданным размером блока (chunk).
     *
     * @param out       выходной поток с зашифрованными данными
     * @param key       мастер-ключ шифрования (32 байта)
     * @param chunkSize размер чанка в байтах: от 16 до 1 048 576 (1 МиБ), рекомендуется кратно 16
     * @return шифрующий поток {@link SealingStream}
     * @throws IOException              если не удалось записать заголовок
     * @throws IllegalArgumentException если chunkSize вне диапазона [16, 1 048 576] или длина
     *     ключа не равна 32 байтам
     */
    public static SealingStream sealing(OutputStream out, SymmetricKey key, int chunkSize)
            throws IOException {
        return sealing(out, key, chunkSize, AuthenticatedCipher.NO_AAD);
    }

    /**
     * Создаёт шифрующий поток с внешним AAD и заданным размером чанка.
     *
     * @param out       выходной поток с зашифрованными данными
     * @param key       мастер-ключ шифрования (32 байта)
     * @param chunkSize размер чанка в байтах: от 16 до 1 048 576 (1 МиБ), рекомендуется кратно 16
     * @param aad       внешний AAD; {@code null} равнозначен пустому массиву
     * @return шифрующий поток {@link SealingStream}
     * @throws IOException              если не удалось записать заголовок
     * @throws IllegalArgumentException если chunkSize вне диапазона [16, 1 048 576] или длина
     *     ключа не равна 32 байтам
     */
    public static SealingStream sealing(
            OutputStream out, SymmetricKey key, int chunkSize, byte[] aad) throws IOException {
        return new SealingStream(out, key, chunkSize, aad);
    }

    /**
     * Создаёт расшифровывающий поток с проверкой аутентичности данных.
     *
     * <p>Читает и проверяет заголовок потока сразу при создании.
     * Данные каждого чанка верифицируются через CMAC перед отдачей вызывающему.
     * {@code close()} закрывает {@code in}; если конструктор бросил исключение, {@code in}
     * остаётся открытым и закрывается вызывающим.
     *
     * @param in  поток зашифрованных данных в формате AuthenticatedStream
     * @param key мастер-ключ расшифрования (32 байта) — тот же что при sealing
     * @return расшифровывающий {@link InputStream}; ошибки целостности и усечение при чтении
     *     приходят как {@link AuthenticationIOException}
     * @throws IOException                 если не удалось прочитать заголовок из-за ошибки
     *                                     ввода-вывода
     * @throws AuthenticationException если заголовок повреждён или поток оборван до его конца
     * @throws IllegalArgumentException если длина ключа не равна 32 байтам
     */
    public static InputStream opening(InputStream in, SymmetricKey key)
            throws IOException, AuthenticationException {
        return opening(in, key, AuthenticatedCipher.NO_AAD);
    }

    /**
     * Создаёт расшифровывающий поток с проверкой аутентичности данных и внешнего AAD.
     *
     * <p>AAD в потоке не передаётся, поэтому вызывающий обязан знать его до {@code opening} и
     * первого {@code read}. По той же причине {@code opening} не может проверить AAD при
     * создании: читается только заголовок, а несовпадение AAD (как и неверный ключ) выявляет CMAC
     * первого чанка. Отказ приходит при чтении чанка 0. У пустого потока он приходит при первом
     * {@code read()}, который иначе вернул бы {@code -1}; если поток не читать, проверки нет.
     *
     * @param in  поток зашифрованных данных в формате AuthenticatedStream
     * @param key мастер-ключ расшифрования (32 байта) — тот же что при sealing
     * @param aad внешний AAD — то же значение, что при sealing; {@code null} равнозначен пустому
     *     массиву
     * @return расшифровывающий {@link InputStream}; ошибки целостности и усечение при чтении
     *     приходят как {@link AuthenticationIOException}
     * @throws IOException                 если не удалось прочитать заголовок из-за ошибки
     *                                     ввода-вывода
     * @throws AuthenticationException если заголовок повреждён или поток оборван до его конца
     * @throws IllegalArgumentException если длина ключа не равна 32 байтам
     */
    public static InputStream opening(InputStream in, SymmetricKey key, byte[] aad)
            throws IOException, AuthenticationException {
        return new OpeningStream(in, key, aad);
    }

    // -----------------------------------------------------------------------
    // SealingStream — шифрующий поток
    // -----------------------------------------------------------------------

    /**
     * Шифрующий поток {@link AuthenticatedStream#sealing}. Создаётся только через {@code sealing}:
     * поток держит ключи, поэтому конструктор закрыт, а класс не наследуется.
     *
     * <p>Данные копятся в буфере чанка; полный чанк шифруется и уходит в нижний поток сразу.
     * Последний (возможно неполный или пустой) чанк с флагом последнего пишут {@link #finish()}
     * или {@link #close()}: без него читатель видит усечение потока.
     *
     * <p>{@link #flush()} выталкивает в нижний поток только уже записанные полные чанки.
     * Неполный буфер как обычный чанк не уходит: читатель требует, чтобы обычный чанк был ровно
     * {@code chunkSize} байт, и это правило защищает от неоднозначности частичного чанка.
     *
     * <p>{@link #finish()} записывает последний чанк и оставляет нижний поток открытым, например,
     * когда защищённый поток встроен в более длинный (сокет). Он не заменяет {@link #close()}:
     * нижний поток закрывает тот, кто его открыл, либо {@code close()} этого потока.
     */
    public static final class SealingStream extends OutputStream {

        private final OutputStream out;
        private final int chunkSize;

        /**
         * Внутренний буфер одного чанка: накапливает открытый текст, при отправке шифруется на
         * месте (ручное управление).
         */
        private final byte[] chunkBuf;

        /**
         * Рабочие буферы чанка, по одному на поток вместо массивов на каждый чанк: заголовок
         * чанка и AAD чанка. Это не секреты (структура потока открыта), затирать их не нужно.
         */
        private final byte[] chunkHeader = new byte[CHUNK_HEADER_SIZE];

        private final byte[] chunkAad = new byte[MAX_CHUNK_AAD_SIZE];

        private int chunkCount;

        /** Заголовок потока (version[1] + nonce[16] + chunkSize[4]), нужен для AAD чанка при seqNo=0. */
        private byte[] firstHeader;

        /**
         * CTR и CMAC потока с ключами, выведенными из мастер-ключа. Создаются один раз при записи
         * заголовка. {@code Ctr} нельзя сбрасывать и инициализировать заново после первого чанка:
         * счётчик вернулся бы к нулевому IV, и гамма повторилась бы.
         */
        private StreamCrypto crypto;

        /** Порядковый номер чанка (неявная защита от reorder/duplicate). */
        private long seqNo = 0;

        /**
         * Последний чанк записывается или уже записан. Признак ставится до записи: при сбое
         * повторный {@code finish()} и {@code close()} не пишут второй чанк с флагом последнего.
         */
        private boolean finished = false;

        /** Запись чанка закончилась ошибкой: поток непригоден, часть структуры в нижнем потоке. */
        private boolean failed = false;

        private boolean closed = false;

        private SealingStream(OutputStream out, SymmetricKey key, int chunkSize, byte[] aad)
                throws IOException {
            Objects.requireNonNull(out, "out");
            Objects.requireNonNull(key, "key");
            if (chunkSize < MIN_CHUNK_SIZE || chunkSize > MAX_CHUNK_SIZE) {
                // Верхняя граница та же, что у читателя: поток с большим чанком записался бы,
                // но не открывался бы, и данные оказались бы потеряны.
                throw new IllegalArgumentException(
                        "chunkSize must be in ["
                                + MIN_CHUNK_SIZE
                                + ", "
                                + MAX_CHUNK_SIZE
                                + "] bytes, got "
                                + chunkSize);
            }
            this.out = out;
            this.chunkSize = chunkSize;
            this.chunkBuf = new byte[chunkSize];
            this.chunkCount = 0;
            try {
                writeStreamHeader(key, aad);
            } catch (IOException | RuntimeException e) {
                // Ключи уже выведены: при сбое записи заголовка их нельзя оставлять в куче
                wipeState();
                throw e;
            }
        }

        /** Записывает заголовок потока: version[1] + streamNonce[16] + chunkSize[4]. */
        private void writeStreamHeader(SymmetricKey masterKey, byte[] aad) throws IOException {
            // Заголовок хранится целиком: он входит в AAD первого чанка (seqNo=0)
            firstHeader = new byte[HEADER_SIZE];
            firstHeader[VERSION_OFFSET] = VERSION;
            byte[] streamNonce = new byte[NONCE_SIZE];
            CryptoRandom.INSTANCE.nextBytes(streamNonce);
            System.arraycopy(streamNonce, 0, firstHeader, NONCE_OFFSET, NONCE_SIZE);
            Pack.writeInt(chunkSize, firstHeader, CHUNK_SIZE_OFFSET);

            // KDF: из мастер-ключа, streamNonce и внешнего AAD выводим ключи потока для CMAC и CTR
            this.crypto = StreamCrypto.create(masterKey, streamNonce, aad);
            out.write(firstHeader, 0, HEADER_SIZE);
        }

        @Override
        public void write(int b) throws IOException {
            checkWritable();
            chunkBuf[chunkCount++] = (byte) b;
            if (chunkCount >= chunkSize) {
                writeChunk(false);
            }
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            checkWritable();
            Objects.checkFromIndexSize(off, len, b.length);
            int remaining = len;
            int srcOff = off;
            while (remaining > 0) {
                int space = chunkSize - chunkCount;
                int toWrite = Math.min(remaining, space);
                System.arraycopy(b, srcOff, chunkBuf, chunkCount, toWrite);
                chunkCount += toWrite;
                srcOff += toWrite;
                remaining -= toWrite;
                if (chunkCount >= chunkSize) {
                    writeChunk(false);
                }
            }
        }

        /**
         * Выталкивает в нижний поток уже записанные полные чанки. Неполный буфер не уходит:
         * хвост пишут {@link #finish()} или {@link #close()}.
         *
         * @throws IOException если поток закрыт, непригоден после ошибки записи или нижний поток
         *                     отказал
         */
        @Override
        public void flush() throws IOException {
            if (closed) throw new IOException("Stream is closed");
            if (failed) throw new IOException("Stream is unusable after an earlier write error");
            out.flush();
        }

        /**
         * Записывает последний чанк, делает {@code flush()} нижнего потока и затирает буфер и
         * ключи потока. Нижний поток не закрывается. Повторный вызов ничего не делает; после
         * вызова {@code write} бросает {@link IOException}.
         *
         * @throws IOException если поток закрыт, непригоден после прежней ошибки записи или
         *                     запись последнего чанка не удалась
         */
        public void finish() throws IOException {
            if (closed) throw new IOException("Stream is closed");
            if (failed) throw new IOException("Stream is unusable after an earlier write error");
            finishInternal();
        }

        /**
         * Шифрует и записывает один чанк (Encrypt-then-MAC), не помечая поток завершённым. Сбой
         * записи делает поток непригодным: часть чанка уже в нижнем потоке, и продолжение дало бы
         * поток, который читатель отвергнет.
         */
        private void writeChunk(boolean isLast) throws IOException {
            try {
                flushChunk(isLast);
            } catch (IOException | RuntimeException e) {
                failed = true;
                finished = true;
                wipeState();
                throw e;
            }
        }

        private void finishInternal() throws IOException {
            if (finished) return;
            finished = true;
            try {
                flushChunk(true);
                out.flush();
            } catch (IOException | RuntimeException e) {
                failed = true;
                throw e;
            } finally {
                wipeState();
            }
        }

        /**
         * Шифрует и записывает один чанк (Encrypt-then-MAC).
         * @param isLast true для последнего чанка
         */
        private void flushChunk(boolean isLast) throws IOException {
            int count = chunkCount;
            chunkCount = 0;
            byte flags = isLast ? FLAG_LAST : FLAG_NORMAL;

            // AAD чанка: seqNo(8) || flags(1), для первого чанка (seqNo=0) с заголовком потока
            int chunkAadLen =
                    writeChunkAad(chunkAad, seqNo, flags, seqNo == 0 ? firstHeader : null);
            if (firstHeader != null) {
                Arrays.fill(firstHeader, (byte) 0);
                firstHeader = null;
            }

            // CTR на месте: шифртекст замещает открытый текст в буфере чанка, поэтому копии
            // открытого текста нет и затирать её не нужно (при сбое буфер затирает wipeState).
            // Счётчик продолжает гамму предыдущего чанка: повторить гамму нельзя без нового Ctr
            crypto.ctr.processBytes(chunkBuf, 0, count, chunkBuf, 0);
            seqNo++;

            // Заголовок чанка: chunkLen(4) + flags(1) + CMAC(16), одним вызовом write.
            // CMAC от AAD чанка || шифртекста (Encrypt-then-MAC) пишется сразу в заголовок.
            Pack.writeInt(count, chunkHeader, 0);
            chunkHeader[CHUNK_FLAGS_OFFSET] = flags;
            crypto.cmac.update(chunkAad, 0, chunkAadLen);
            crypto.cmac.update(chunkBuf, 0, count);
            crypto.cmac.doFinal(chunkHeader, CHUNK_TAG_OFFSET);
            out.write(chunkHeader, 0, CHUNK_HEADER_SIZE);
            out.write(chunkBuf, 0, count);
        }

        /**
         * Записывает последний чанк (если он ещё не записан) и закрывает нижний поток. Повторный
         * вызов ничего не делает.
         */
        @Override
        public void close() throws IOException {
            if (closed) return;
            closed = true;
            // Нижний поток закрывается в любом исходе, в том числе при сбое записи последнего
            // чанка: иначе дескриптор утёк бы. Ошибка закрытия при уже выброшенном исключении
            // добавляется к нему как подавленная. После finish() последний чанк не пишется.
            try (OutputStream target = out) {
                finishInternal();
            }
        }

        /** Затирает буфер чанка, заголовок и ключи потока; повторный вызов безопасен. */
        private void wipeState() {
            Arrays.fill(chunkBuf, (byte) 0);
            if (firstHeader != null) Arrays.fill(firstHeader, (byte) 0);
            if (crypto != null) crypto.destroy();
        }

        private void checkWritable() throws IOException {
            if (closed) throw new IOException("Stream is closed");
            if (failed) throw new IOException("Stream is unusable after an earlier write error");
            if (finished) throw new IOException("Stream is finished");
        }
    }

    // -----------------------------------------------------------------------
    // OpeningStream — расшифровывающий поток
    // -----------------------------------------------------------------------

    private static final class OpeningStream extends InputStream {

        private final InputStream in;
        private final int chunkSize;

        /** Заголовок потока ({@value #HEADER_SIZE} байт), прочитанный из входного потока. */
        private byte[] firstHeader;

        /**
         * CTR и CMAC потока с ключами, выведенными из мастер-ключа. Создаются один раз при чтении
         * заголовка. {@code Ctr} нельзя сбрасывать и инициализировать заново после первого чанка:
         * счётчик вернулся бы к нулевому IV, и гамма не совпала бы с гаммой писателя.
         */
        private StreamCrypto crypto;

        /**
         * Буфер текущего чанка: сюда читается шифртекст и тут же расшифровывается. Один на поток,
         * растёт до размера чанка по требованию.
         */
        private byte[] plainBuf = new byte[0];

        /** Число расшифрованных байт в plainBuf; ёмкость буфера может быть больше. */
        private int plainLen = 0;

        /** Позиция чтения в plainBuf. */
        private int plainPos = 0;

        /**
         * Рабочие буферы чанка, по одному на поток: заголовок, AAD чанка и вычисленный тег. Структура
         * потока открыта, затирается только вычисленный тег (см. {@code readNextChunk}).
         */
        private final byte[] chunkHeader = new byte[CHUNK_HEADER_SIZE];

        private final byte[] chunkAad = new byte[MAX_CHUNK_AAD_SIZE];
        private final byte[] tagBuf = new byte[AuthenticatedCipher.TAG_LEN];

        /** Буфер однобайтового {@code read()}: байт открытого текста, затирается после чтения. */
        private final byte[] oneByte = new byte[1];

        /** Порядковый номер чанка (неявная защита от reorder/duplicate). */
        private long seqNo = 0;

        private boolean lastChunkSeen = false;

        /** Поток закрыт: чтение после {@code close()} даёт {@link IOException}. */
        private boolean closed = false;

        /** Чистый конец потока: последний чанк прочитан целиком. */
        private boolean streamEnded = false;

        /**
         * Первая ошибка чтения. Пока она есть, каждый {@code read()} бросает исключение: ошибка
         * не должна превращаться в {@code -1} (конец потока) или в чтение с середины структуры.
         */
        private IOException failure;

        OpeningStream(InputStream in, SymmetricKey key, byte[] aad)
                throws IOException, AuthenticationException {
            Objects.requireNonNull(in, "in");
            Objects.requireNonNull(key, "key");
            this.in = in;
            this.chunkSize = readAndVerifyStreamHeader(key, aad);
        }

        /** Читает и проверяет заголовок потока. Возвращает chunkSize. */
        private int readAndVerifyStreamHeader(SymmetricKey masterKey, byte[] aad)
                throws IOException, AuthenticationException {
            byte[] header;
            try {
                header = new byte[HEADER_SIZE];
                readInto(header, HEADER_SIZE);
            } catch (EOFException e) {
                // Обрыв (в том числе пустой поток) - нарушение целостности, а не ошибка
                // ввода-вывода
                throw new AuthenticationException(
                        "Unexpected end of stream: stream header is incomplete");
            }
            // Заголовок входит в AAD первого чанка и тем защищён от изменения.
            if (header[VERSION_OFFSET] != VERSION) {
                throw new AuthenticationException(
                        "Unsupported format version: "
                                + (header[VERSION_OFFSET] & 0xFF)
                                + " (expected "
                                + VERSION
                                + ")");
            }
            int declaredChunkSize = Pack.readInt(header, CHUNK_SIZE_OFFSET);
            if (declaredChunkSize < MIN_CHUNK_SIZE || declaredChunkSize > MAX_CHUNK_SIZE) {
                throw new AuthenticationException(
                        "Invalid chunk size in header: " + declaredChunkSize);
            }
            this.firstHeader = header;

            // KDF: из мастер-ключа, streamNonce и внешнего AAD выводим ключи потока
            byte[] streamNonce =
                    Arrays.copyOfRange(header, NONCE_OFFSET, NONCE_OFFSET + NONCE_SIZE);
            try {
                this.crypto = StreamCrypto.create(masterKey, streamNonce, aad);
            } finally {
                Arrays.fill(streamNonce, (byte) 0);
            }

            return declaredChunkSize;
        }

        /**
         * Отказ проверки чанка с его позицией в сообщении: номер чанка с нуля и смещение его
         * открытого текста от начала данных (без заголовка потока). Все предшествующие чанки
         * полные (обычный чанк всегда ровно {@code chunkSize}, это проверяется при чтении), поэтому
         * смещение равно {@code номер * chunkSize}. Позиция не секрет: тот, кто испортил или
         * обрезал поток, знает её и так, а оператору она показывает место в многогигабайтном
         * файле.
         */
        private AuthenticationException chunkFailure(long chunkIndex, String message) {
            return new AuthenticationException(
                    message
                            + " [chunk "
                            + chunkIndex
                            + ", plaintext offset "
                            + chunkIndex * chunkSize
                            + "]");
        }

        /**
         * Читает и расшифровывает следующий чанк из потока.
         * CMAC проверяется от шифртекста ДО расшифрования (Encrypt-then-MAC).
         *
         * @return false если поток исчерпан
         */
        private boolean readNextChunk() throws IOException, AuthenticationException {
            if (lastChunkSeen) return false;

            // Номер читаемого чанка фиксируется до seqNo++: к проверке тега счётчик уже ушёл
            // вперёд, а в сообщении об отказе нужен номер чанка, который не прошёл
            final long chunkIndex = seqNo;

            // Предыдущий чанк уже выдан вызывающему и дочитан до конца; на время чтения нового
            // буфер не должен выглядеть содержащим данные
            plainLen = 0;
            plainPos = 0;

            // Читаем заголовок чанка: chunkLen(4) + flags(1) + CMAC(16)
            try {
                readInto(chunkHeader, CHUNK_HEADER_SIZE);
            } catch (EOFException e) {
                // Поток завершился без флага последнего чанка — усечение! Другие IOException
                // (обрыв сети, закрытый файл) - не признак усечения и передаются как есть.
                throw chunkFailure(
                        chunkIndex,
                        "Unexpected end of stream: last chunk not found (truncated stream?)");
            }

            int chunkLen = Pack.readInt(chunkHeader, 0);
            byte flags = chunkHeader[CHUNK_FLAGS_OFFSET];

            // Каноническая форма: писатель выдаёт только флаги 0x00 и 0x01, обычный чанк всегда
            // полный (chunkSize), последний - от 0 до chunkSize. Иное принималось бы молча
            // (пустой обычный чанк читался как конец потока без проверки на усечение), поэтому
            // отвергаем до чтения шифртекста.
            if (flags != FLAG_NORMAL && flags != FLAG_LAST) {
                throw chunkFailure(chunkIndex, "Invalid chunk flags: " + (flags & 0xFF));
            }
            if (chunkLen < 0 || chunkLen > chunkSize) {
                throw chunkFailure(chunkIndex, "Invalid chunk length: " + chunkLen);
            }
            if (flags == FLAG_NORMAL && chunkLen != chunkSize) {
                throw chunkFailure(
                        chunkIndex,
                        "Invalid chunk length for a non-final chunk: "
                                + chunkLen
                                + " (expected "
                                + chunkSize
                                + ")");
            }

            // Шифртекст читается прямо в буфер открытого текста и расшифровывается на месте:
            // один буфер на поток вместо двух массивов на каждый чанк. Буфер растёт до размера
            // чанка по требованию, чтобы короткий поток не занимал chunkSize байт (до 1 МиБ).
            if (plainBuf.length < chunkLen) {
                Arrays.fill(plainBuf, (byte) 0);
                plainBuf = new byte[chunkLen];
            }
            try {
                readInto(plainBuf, chunkLen);
            } catch (EOFException e) {
                throw chunkFailure(
                        chunkIndex,
                        "Unexpected end of stream: chunk is incomplete (truncated stream?)");
            }

            // Буфер мог держать более длинный предыдущий чанк (бывает только перед последним):
            // его хвост уже выдан вызывающему и не должен лежать в буфере
            Arrays.fill(plainBuf, chunkLen, plainBuf.length, (byte) 0);

            // Проверяем CMAC от AAD чанка(seqNo || flags || [заголовок потока]) || шифртекста ДО
            // расшифрования
            int chunkAadLen =
                    writeChunkAad(chunkAad, seqNo, flags, seqNo == 0 ? firstHeader : null);
            crypto.cmac.update(chunkAad, 0, chunkAadLen);
            crypto.cmac.update(plainBuf, 0, chunkLen);
            crypto.cmac.doFinal(tagBuf, 0);
            seqNo++;

            boolean valid;
            try {
                valid =
                        ConstantTime.equals(
                                tagBuf,
                                0,
                                chunkHeader,
                                CHUNK_TAG_OFFSET,
                                AuthenticatedCipher.TAG_LEN);
            } finally {
                // Вычисленный тег затирается, принятый из потока (и сам шифртекст) не секрет:
                // для повреждённого чанка вычисленный тег это действительный CMAC под ключом
                // потока для данных, выбранных не пользователем
                Arrays.fill(tagBuf, (byte) 0);
            }

            if (!valid) {
                throw chunkFailure(
                        chunkIndex,
                        "Chunk integrity violation: CMAC mismatch. "
                                + "Stream is corrupted, was modified, "
                                + "or the key or associated data does not match.");
            }

            // Только после успешной верификации — расшифрование на месте. Гамма продолжает
            // предыдущий чанк: чанки обрабатываются строго по порядку, а при неверном теге
            // счётчик не двигается и поток всё равно непригоден
            crypto.ctr.processBytes(plainBuf, 0, chunkLen, plainBuf, 0);
            plainLen = chunkLen;

            // После успешной верификации первого чанка заголовок больше не нужен
            if (firstHeader != null) {
                Arrays.fill(firstHeader, (byte) 0);
                firstHeader = null;
            }

            if (flags == FLAG_LAST) {
                lastChunkSeen = true;
                // Последний чанк проверен и расшифрован: ключи больше не нужны. Читатель
                // встроенного потока (сокет) его не закрывает, и ключи не должны ждать close().
                destroyKeys();
            }

            return true;
        }

        @Override
        public int read() throws IOException {
            int n = read(oneByte, 0, 1);
            int result = (n < 0) ? -1 : (oneByte[0] & 0xFF);
            oneByte[0] = 0;
            return result;
        }

        @Override
        public int read(byte[] buf, int off, int len) throws IOException {
            // Контракт InputStream: границы проверяются всегда, при len == 0 возвращается 0
            // независимо от состояния (в том числе после ошибки и после конца потока).
            Objects.checkFromIndexSize(off, len, buf.length);
            if (len == 0) return 0;
            if (closed) throw new IOException("Stream is closed");
            if (failure != null) {
                throw repeatFailure();
            }
            if (streamEnded) return -1;

            // Заполняем буфер из расшифрованных чанков
            int totalRead = 0;
            while (totalRead < len) {
                // Если текущий чанк исчерпан — читаем следующий
                if (plainPos >= plainLen) {
                    boolean hasMore;
                    try {
                        hasMore = readNextChunk();
                    } catch (AuthenticationException e) {
                        failure =
                                new AuthenticationIOException(
                                        "Authentication error: " + e.getMessage(), e);
                        discardPlaintext();
                        destroyKeys();
                        throw failure;
                    } catch (IOException e) {
                        // Сбой нижнего потока: структура чанка прочитана частично, продолжать
                        // с середины нельзя
                        failure = e;
                        discardPlaintext();
                        destroyKeys();
                        throw e;
                    }
                    if (!hasMore || plainLen == 0) {
                        streamEnded = true;
                        // Прежний чанк дочитан до конца: затираем его открытый текст
                        discardPlaintext();
                        break;
                    }
                }

                int available = plainLen - plainPos;
                int toCopy = Math.min(available, len - totalRead);
                System.arraycopy(plainBuf, plainPos, buf, off + totalRead, toCopy);
                plainPos += toCopy;
                totalRead += toCopy;
            }

            return (totalRead == 0 && streamEnded) ? -1 : totalRead;
        }

        private void discardPlaintext() {
            Arrays.fill(plainBuf, (byte) 0);
            plainBuf = new byte[0];
            plainLen = 0;
            plainPos = 0;
        }

        /** Новое исключение с тем же типом и причиной, чтобы не бросать один объект повторно. */
        private IOException repeatFailure() {
            if (failure instanceof AuthenticationIOException
                    && failure.getCause() instanceof AuthenticationException cause) {
                return new AuthenticationIOException(failure.getMessage(), cause);
            }
            return new IOException("Stream is unusable after an earlier read error", failure);
        }

        @Override
        public void close() throws IOException {
            if (closed) return;
            closed = true;
            // Мастер-ключ принадлежит вызывающему — не уничтожаем его.
            // Per-stream ключи — наши, уничтожаем.
            try (InputStream source = in) {
                Arrays.fill(plainBuf, (byte) 0);
                destroyKeys();
            }
        }

        /** Затирает заголовок и ключи потока; повторный вызов безопасен. */
        private void destroyKeys() {
            if (firstHeader != null) Arrays.fill(firstHeader, (byte) 0);
            if (crypto != null) crypto.destroy();
        }

        // -----------------------------------------------------------------------
        // Вспомогательные методы чтения
        // -----------------------------------------------------------------------

        /**
         * Читает ровно {@code n} байт в начало {@code buf}. Конец потока даёт
         * {@link EOFException}: вызывающий отличает его от прочих ошибок ввода-вывода и трактует
         * как усечение.
         */
        private void readInto(byte[] buf, int n) throws IOException {
            int read = 0;
            while (read < n) {
                int r = in.read(buf, read, n - read);
                if (r < 0)
                    throw new EOFException(
                            "Unexpected end of stream: expected " + n + " bytes, read " + read);
                read += r;
            }
        }
    }

    // -----------------------------------------------------------------------
    // Утилиты
    // -----------------------------------------------------------------------

    /**
     * CTR и CMAC одного потока. Ключи, выведенные из мастер-ключа, нужны только для {@code init}:
     * Кузнечик разворачивает их в раундовые ключи и копию ключа затирает, поэтому выведенные
     * {@link SymmetricKey} уничтожаются сразу. Один {@code Ctr} и один {@code Cmac} живут весь поток
     * вместо пары новых объектов на каждый чанк. {@code Cmac.doFinal} сам сбрасывает состояние и
     * сохраняет ключ, а {@code Ctr} продолжает гамму между чанками.
     */
    private static final class StreamCrypto {

        final Ctr ctr;
        final Cmac cmac;

        private StreamCrypto(Ctr ctr, Cmac cmac) {
            this.ctr = ctr;
            this.cmac = cmac;
        }

        /**
         * Выводит ключи из мастер-ключа и затравки {@code streamNonce ‖ aad} и создаёт CTR с
         * нулевым IV и CMAC.
         */
        static StreamCrypto create(SymmetricKey masterKey, byte[] streamNonce, byte[] aad) {
            // Затравку собираем до создания объектов шифра, чтобы сбой выделения памяти не
            // оставлял полусозданное состояние
            byte[] seed = AuthenticatedCipher.seedWithAad(streamNonce, 0, NONCE_SIZE, aad);
            SymmetricKey[] keys = new SymmetricKey[2];
            Ctr ctr = new Ctr(new Kuznyechik());
            Cmac cmac = new Cmac(new Kuznyechik());
            try {
                AuthenticatedCipher.deriveKeyPair(masterKey, KDF_LABEL, seed, keys);
                cmac.init(keys[0]);
                // IV из нулей: ключ CTR свой у потока, а чанки не сбрасывают счётчик
                ctr.init(true, new ParametersWithIV(keys[1], new byte[AuthenticatedCipher.IV_LEN]));
                return new StreamCrypto(ctr, cmac);
            } catch (RuntimeException e) {
                ctr.destroy();
                cmac.destroy();
                throw e;
            } finally {
                for (SymmetricKey derived : keys) {
                    if (derived != null) derived.destroy();
                }
            }
        }

        /** Затирает раундовые ключи и рабочее состояние; повторный вызов безопасен. */
        void destroy() {
            ctr.destroy();
            cmac.destroy();
        }
    }

    /**
     * Записывает AAD чанка для CMAC в {@code dst} и возвращает его длину: {@code seqNo(8) ‖ flags(1)} и
     * для первого чанка ({@code firstHeader != null}) заголовок потока. Номер чанка идёт первым,
     * поэтому AAD первого чанка и остальных различаются уже в первых 8 байтах и не могут
     * совпасть при разном разбиении байтов на AAD чанка и шифртекст.
     */
    private static int writeChunkAad(byte[] dst, long seqNo, byte flags, byte[] firstHeader) {
        Pack.writeLong(seqNo, dst, 0);
        dst[8] = flags;
        if (firstHeader == null) {
            return CHUNK_AAD_PREFIX_SIZE;
        }
        System.arraycopy(firstHeader, 0, dst, CHUNK_AAD_PREFIX_SIZE, HEADER_SIZE);
        return CHUNK_AAD_PREFIX_SIZE + HEADER_SIZE;
    }
}
