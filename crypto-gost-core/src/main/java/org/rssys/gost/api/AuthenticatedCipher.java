package org.rssys.gost.api;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;
import org.rssys.gost.cipher.Kuznyechik;
import org.rssys.gost.cipher.ParametersWithIV;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.cipher.mode.Ctr;
import org.rssys.gost.kdf.KdfTreeGostR3411_2012_256;
import org.rssys.gost.mac.Cmac;
import org.rssys.gost.util.AuthenticationException;
import org.rssys.gost.util.ConstantTime;
import org.rssys.gost.util.CryptoRandom;

/**
 * API для аутентифицированного шифрования по ГОСТ Р 34.13-2015
 *
 * <p>Реализует схему Encrypt-then-MAC (EtM): сначала шифрование Кузнечиком
 * в режиме CTR, затем имитовставка CMAC от версии, соли и шифртекста. Верификация
 * выполняется до расшифрования — неверный тег не даёт oracle на plaintext.
 *
 * <p>Композиция собственная, не стандартизована: примитивы (CTR, CMAC, KDF_TREE)
 * стандартные, а их сочетание, формат пакета и метка KDF определены в этой библиотеке
 * и не имеют внешнего эталона. Для обмена со сторонними системами используйте
 * стандартизованные форматы (CMS, PBES2).
 *
 * <h3>Ключи сообщения:</h3>
 * Для каждого сообщения из мастер-ключа и затравки через KDF_TREE
 * (Р 50.1.113-2016) выводятся два независимых ключа: для CMAC и для CTR. Затравка - случайная
 * соль (16 байт), а при непустом внешнем AAD - соль вместе с AAD ({@code соль ‖ aad}). Соль
 * генерируется внутри {@link #seal} и снаружи не задаётся: уникальность ключей
 * сообщения не должна зависеть от вызывающего. Ключ CTR уникален для сообщения,
 * поэтому счётчик стартует с фиксированного нулевого IV.
 *
 * <h3>Формат пакета:</h3>
 * <pre>
 *   [версия (1 байт)] [соль (16 байт)] [CMAC (16 байт)] [шифртекст (N байт)]
 * </pre>
 * Тег считается от {@code версия ‖ соль ‖ шифртекст}. Внешний AAD в пакет не пишется и в тег
 * не входит: он участвует только в выводе ключей, поэтому формат пакета от AAD не зависит.
 * Overhead: 33 байта на сообщение. Пакеты прежних версий (без байта версии) не принимаются.
 *
 * <h3>Внешний AAD:</h3>
 * AAD - контекст (имя файла, получатель, идентификатор сессии), который проверяется вместе с
 * пакетом, но не шифруется, не передаётся и не затирается: секреты в AAD не класть. Получатель обязан знать то же значение. Неверный AAD
 * неотличим от неверного ключа и даёт тот же {@link AuthenticationException}. {@code null}
 * равнозначен пустому массиву: пустой и отсутствующий AAD дают один и тот же пакет. Если AAD
 * составлен из нескольких полей, их склеивает вызывающий, так, чтобы граница между полями была
 * однозначной (например, с длиной перед каждым полем). Обработка AAD добавляет два прохода
 * HMAC-Стрибог по его байтам, поэтому AAD должен быть коротким контекстом, а не данными.
 *
 * <p>Для обмена со сторонними реализациями ГОСТ и там, где нужен стандарт (RFC 9058), используйте
 * {@link MgmCipher}. {@code AuthenticatedCipher} подходит, когда важны свежие ключи CMAC и CTR на
 * каждое сообщение и одна конструкция с {@link AuthenticatedStream} для файлов и сообщений;
 * формат внутренний, для обмена не предназначен.
 *
 * <h3>Предел по числу сообщений:</h3>
 * Ключи двух сообщений совпадут только при совпадении 128-битной соли. Вероятность
 * коллизии среди q сообщений на одном мастер-ключе ≈ q²/2¹²⁹: безопасно не более
 * ≈2⁴⁸ сообщений на ключ (вероятность ≈2⁻³³), около 50% достигается к ≈2⁶⁴. Ключ
 * следует использовать только для этого API.
 *
 * <h3>Чего API не обеспечивает:</h3>
 * Состояния нет, поэтому API не защищает от повтора пакета, переупорядочивания и замены пакета
 * другим валидным пакетом под тем же ключом и тем же AAD. Внешний AAD привязывает пакет к
 * контексту, но сам по себе повтор не обнаруживает: чтобы обнаружить его, вызывающий кладёт в AAD
 * номер сообщения и ведёт счётчик. Для потоков используйте {@link AuthenticatedStream}.
 *
 * <h3>Пример использования:</h3>
 * <pre>{@code
 * SymmetricKey key = KeyGenerator.generateSymmetricKey();
 * byte[] aad = "invoice-2026-0417".getBytes(StandardCharsets.UTF_8);
 *
 * byte[] packet = AuthenticatedCipher.seal(plaintext, key, aad);
 * byte[] opened = AuthenticatedCipher.open(packet, key, aad); // тот же AAD
 * }</pre>
 *
 * <p>Все методы потокобезопасны.
 */
public final class AuthenticatedCipher {

    /**
     * Длина IV для режима CTR по ГОСТ Р 34.13-2015 §4.4 (n/2 = 8 байт). Оба API берут нулевой IV
     * такой длины: ключ CTR у каждого сообщения и у каждого потока свой. Поэтому здесь общий
     * только размер, а массив с нулями каждый создаёт себе сам: общий изменяемый массив мог бы
     * испортить любой класс пакета.
     */
    static final int IV_LEN = 8;

    /**
     * Длина полного CMAC-тега в пакете (128 бит = размер блока Кузнечика).
     */
    static final int TAG_LEN = CmacApi.CMAC_TAG_SIZE;

    /** Версия формата пакета. */
    static final byte VERSION = 0x01;

    /** Длина поля версии в пакете. */
    static final int VERSION_LEN = 1;

    /** Длина случайной соли сообщения: 128 бит, из неё выводятся оба ключа. */
    static final int SALT_LEN = 16;

    /** Длина ключа Кузнечика (256 бит) в байтах. */
    private static final int KEY_LEN = Kuznyechik.KEY_SIZE;

    /** Размер заголовка, который аутентифицируется: версия и соль. */
    private static final int HEADER_LEN = VERSION_LEN + SALT_LEN;

    /**
     * Минимальная длина пакета: версия + соль + тег (сообщение с пустым открытым текстом).
     */
    static final int MIN_PACKET_LEN = HEADER_LEN + TAG_LEN;

    /** Метка KDF_TREE: отличается от меток {@link AuthenticatedStream} и PBES2/CMS. */
    static final String KDF_LABEL_NAME = "auth-cipher-v1";

    private static final byte[] KDF_LABEL = KDF_LABEL_NAME.getBytes(StandardCharsets.US_ASCII);

    /**
     * Нулевой IV счётчика. Безопасен только потому, что ключ CTR выводится из уникальной
     * для сообщения соли: второе сообщение с тем же ключом и тем же IV повторило бы гамму.
     */
    private static final byte[] ZERO_IV = new byte[IV_LEN];

    /**
     * Пустой внешний AAD для коротких форм обоих API ({@code AuthenticatedCipher} и
     * {@link AuthenticatedStream}). Общий массив безопасен, потому что он нулевой длины: изменить
     * или затереть в нём нечего. Только для чтения, наружу не отдаётся.
     */
    static final byte[] NO_AAD = new byte[0];

    private AuthenticatedCipher() {}

    /**
     * Шифрует данные с аутентификацией (Encrypt-then-MAC) без внешнего AAD.
     * Равнозначно {@link #seal(byte[], SymmetricKey, byte[])} с пустым AAD.
     *
     * @param plaintext открытые данные
     * @param key       мастер-ключ Кузнечика (32 байта), выделенный для этого API
     * @return пакет вида {@code [версия(1)] [соль(16)] [CMAC(16)] [шифртекст(N)]}
     * @throws NullPointerException если {@code plaintext} или {@code key} равны {@code null}
     * @throws IllegalArgumentException если длина мастер-ключа не равна 32 байтам
     */
    public static byte[] seal(byte[] plaintext, SymmetricKey key) {
        return seal(plaintext, key, NO_AAD);
    }

    /**
     * Шифрует данные с аутентификацией (Encrypt-then-MAC) и привязывает пакет к внешнему AAD.
     *
     * <p>Порядок: вывод ключей из случайной соли и AAD, CTR-шифрование, затем CMAC от
     * {@code версия ‖ соль ‖ шифртекст}. Соль генерируется при каждом вызове. AAD в пакет не
     * пишется: при {@link #open(byte[], SymmetricKey, byte[])} нужно передать то же значение.
     *
     * @param plaintext открытые данные
     * @param key       мастер-ключ Кузнечика (32 байта), выделенный для этого API
     * @param aad       внешний AAD (контекст): не хранится в пакете, не шифруется; {@code null}
     *                  равнозначен пустому массиву
     * @return пакет вида {@code [версия(1)] [соль(16)] [CMAC(16)] [шифртекст(N)]}
     * @throws NullPointerException если {@code plaintext} или {@code key} равны {@code null}
     * @throws IllegalArgumentException если длина мастер-ключа не равна 32 байтам
     */
    public static byte[] seal(byte[] plaintext, SymmetricKey key, byte[] aad) {
        Objects.requireNonNull(plaintext, "plaintext");
        Objects.requireNonNull(key, "key");
        byte[] salt = new byte[SALT_LEN];
        CryptoRandom.INSTANCE.nextBytes(salt);

        byte[] packet = new byte[MIN_PACKET_LEN + plaintext.length];
        packet[0] = VERSION;
        System.arraycopy(salt, 0, packet, VERSION_LEN, SALT_LEN);

        SymmetricKey[] keys = new SymmetricKey[2];
        deriveKeyPair(key, KDF_LABEL, seedWithAad(salt, 0, SALT_LEN, aad), keys);
        SymmetricKey cmacKey = keys[0];
        SymmetricKey ctrKey = keys[1];
        try {
            // Шифртекст и тег пишутся сразу на свои места в пакете: промежуточных массивов нет, а
            // затирать нечего, шифртекст и тег не секрет
            ctrEncrypt(plaintext, 0, plaintext.length, packet, MIN_PACKET_LEN, ctrKey, ZERO_IV);
            computeCmac(
                    packet,
                    HEADER_LEN,
                    packet,
                    MIN_PACKET_LEN,
                    plaintext.length,
                    cmacKey,
                    packet,
                    HEADER_LEN);
            return packet;
        } finally {
            cmacKey.destroy();
            ctrKey.destroy();
        }
    }

    /**
     * Расшифровывает пакет без внешнего AAD и проверяет целостность.
     * Равнозначно {@link #open(byte[], SymmetricKey, byte[])} с пустым AAD.
     *
     * @param encryptedData пакет вида {@code [версия(1)] [соль(16)] [CMAC(16)] [шифртекст(N)]}
     * @param key           мастер-ключ Кузнечика (32 байта) — тот же что при {@link #seal}
     * @return открытые данные
     * @throws AuthenticationException если пакет короткий, версия не поддерживается или
     *                                 CMAC не совпал (данные повреждены или изменены)
     * @throws NullPointerException если {@code encryptedData} или {@code key} равны {@code null}
     * @throws IllegalArgumentException если длина мастер-ключа не равна 32 байтам
     */
    public static byte[] open(byte[] encryptedData, SymmetricKey key)
            throws AuthenticationException {
        return open(encryptedData, key, NO_AAD);
    }

    /**
     * Расшифровывает пакет и проверяет целостность вместе с внешним AAD.
     *
     * <p>Версия и CMAC от версии, соли и шифртекста проверяются до расшифрования —
     * неверный тег не даёт oracle на plaintext.
     *
     * @param encryptedData пакет вида {@code [версия(1)] [соль(16)] [CMAC(16)] [шифртекст(N)]}
     * @param key           мастер-ключ Кузнечика (32 байта) — тот же что при {@link #seal}
     * @param aad           внешний AAD: то же значение, что при шифровании (в пакете его нет);
     *                      {@code null} равнозначен пустому массиву
     * @return открытые данные
     * @throws AuthenticationException если пакет короткий, версия не поддерживается или
     *                                 CMAC не совпал (данные повреждены или изменены, ключ или
     *                                 AAD не те)
     * @throws NullPointerException если {@code encryptedData} или {@code key} равны {@code null}
     * @throws IllegalArgumentException если длина мастер-ключа не равна 32 байтам
     */
    public static byte[] open(byte[] encryptedData, SymmetricKey key, byte[] aad)
            throws AuthenticationException {
        Objects.requireNonNull(encryptedData, "encryptedData");
        Objects.requireNonNull(key, "key");
        if (encryptedData.length < MIN_PACKET_LEN) {
            throw new AuthenticationException(
                    "Packet too short: expected at least "
                            + MIN_PACKET_LEN
                            + " bytes, got "
                            + encryptedData.length);
        }
        // Неизвестную версию не пытаемся разбирать: старый формат не принимается, откатов нет.
        if (encryptedData[0] != VERSION) {
            throw new AuthenticationException("Unsupported packet format version");
        }

        // Затравка нужна KDF отдельным массивом: соль копируется из пакета сразу в неё, вместе с
        // AAD; шифртекст и тег читаются прямо из пакета
        byte[] seed = seedWithAad(encryptedData, VERSION_LEN, SALT_LEN, aad);
        int ciphertextLen = encryptedData.length - MIN_PACKET_LEN;

        SymmetricKey[] keys = new SymmetricKey[2];
        deriveKeyPair(key, KDF_LABEL, seed, keys);
        SymmetricKey cmacKey = keys[0];
        SymmetricKey ctrKey = keys[1];
        byte[] expected = new byte[TAG_LEN];
        try {
            // CMAC(версия ‖ соль ‖ шифртекст) — верификация ДО расшифрования
            computeCmac(
                    encryptedData,
                    HEADER_LEN,
                    encryptedData,
                    MIN_PACKET_LEN,
                    ciphertextLen,
                    cmacKey,
                    expected,
                    0);
            if (!ConstantTime.equals(expected, 0, encryptedData, HEADER_LEN, TAG_LEN)) {
                throw new AuthenticationException(
                        "Integrity violation: CMAC mismatch. "
                                + "Data is corrupted, was modified, "
                                + "or the key or associated data does not match.");
            }
            // Только после успешной верификации — расшифрование
            byte[] plaintext = new byte[ciphertextLen];
            ctrEncrypt(encryptedData, MIN_PACKET_LEN, ciphertextLen, plaintext, 0, ctrKey, ZERO_IV);
            return plaintext;
        } finally {
            cmacKey.destroy();
            ctrKey.destroy();
            // Вычисленный тег затирается, хотя принятый из пакета тег не секрет: для искажённого
            // пакета это действительный CMAC под ключом пользователя для сообщения, выбранного не
            // им, и в куче он не нужен
            Arrays.fill(expected, (byte) 0);
        }
    }

    // -----------------------------------------------------------------------
    // Вспомогательные методы (package-private: deriveKeyPair общий с AuthenticatedStream,
    // ctrEncrypt и computeCmac вызывает ещё и тест как эталонные обёртки)
    // -----------------------------------------------------------------------

    /**
     * Собирает затравку KDF: {@code source[offset .. offset+length)} в начале, внешний AAD в
     * хвосте. Единственное место, где API обоих классов превращают AAD в затравку.
     *
     * <p>Граница между частями однозначна без поля длины: начало (соль или nonce) всегда
     * {@link #SALT_LEN} байт, а длина выходного материала во входе KDF_TREE не зависит от длины
     * затравки. Поэтому разные пары (соль, AAD) дают разные входы KDF. При пустом AAD затравка
     * побайтово равна {@code source[offset .. offset+length)}, то есть прежней.
     *
     * <p>Всегда создаёт новый массив и не возвращает {@code source}: затравка никогда не ссылается
     * на чужой массив, а копия начала (16 байт) и AAD на фоне прочих выделений мала. Затирать результат не
     * нужно: соль, nonce и AAD не секрет.
     *
     * @param source  массив с началом затравки (пакет, соль или заголовок потока)
     * @param offset  смещение начала в {@code source}
     * @param length  длина начала затравки
     * @param aad     внешний AAD; {@code null} равнозначен пустому массиву
     * @return новый массив {@code начало ‖ aad}
     */
    static byte[] seedWithAad(byte[] source, int offset, int length, byte[] aad) {
        int aadLength = aad == null ? 0 : aad.length;
        byte[] seed = new byte[length + aadLength];
        System.arraycopy(source, offset, seed, 0, length);
        if (aadLength > 0) {
            System.arraycopy(aad, 0, seed, length, aadLength);
        }
        return seed;
    }

    /**
     * Выводит пару независимых ключей из мастер-ключа через KDF_TREE:
     * {@code outKeys[0]} — ключ CMAC, {@code outKeys[1]} — ключ CTR.
     * Промежуточные массивы затираются; вызывающий обязан уничтожить полученные ключи.
     *
     * @param masterKey мастер-ключ (32 байта)
     * @param label     метка KDF, различает назначения ключей
     * @param seed      затравка: соль сообщения или nonce потока, а при непустом внешнем AAD -
     *                  вместе с AAD ({@code соль ‖ aad}, см. {@link #seedWithAad})
     * @param outKeys   массив из двух элементов для результата
     * @throws IllegalArgumentException если длина мастер-ключа не равна 32 байтам
     */
    static void deriveKeyPair(
            SymmetricKey masterKey, byte[] label, byte[] seed, SymmetricKey[] outKeys) {
        byte[] masterBytes = masterKey.getKey();
        try {
            // KDF_TREE принимает ключ любой длины, а Кузнечик видит только выведенные 32-байтные
            // ключи: без этой проверки ключ неверной длины принимался бы молча.
            if (masterBytes.length != KEY_LEN) {
                throw new IllegalArgumentException(
                        "Master key must be " + KEY_LEN + " bytes, got " + masterBytes.length);
            }
            // count=2 (cmacKey || ctrKey) безопасно при R=1: счётчик KDF_TREE
            // занимает 1 октет, i in {1,2} гарантированно в него влезает.
            byte[] keyMaterial =
                    KdfTreeGostR3411_2012_256.generate(masterBytes, label, seed, 2, KEY_LEN);
            try {
                byte[] cmacKeyBytes = Arrays.copyOf(keyMaterial, KEY_LEN);
                byte[] ctrKeyBytes = Arrays.copyOfRange(keyMaterial, KEY_LEN, 2 * KEY_LEN);
                try {
                    outKeys[0] = new SymmetricKey(cmacKeyBytes);
                    outKeys[1] = new SymmetricKey(ctrKeyBytes);
                } finally {
                    Arrays.fill(cmacKeyBytes, (byte) 0);
                    Arrays.fill(ctrKeyBytes, (byte) 0);
                }
            } finally {
                Arrays.fill(keyMaterial, (byte) 0);
            }
        } finally {
            Arrays.fill(masterBytes, (byte) 0);
        }
    }

    /**
     * Шифрует или расшифровывает диапазон в режиме CTR (операция симметрична) и пишет результат
     * в {@code out}. Вход и выход могут быть разными массивами. При {@code len == 0} ничего не
     * делает.
     */
    static void ctrEncrypt(
            byte[] in, int inOff, int len, byte[] out, int outOff, SymmetricKey key, byte[] iv) {
        if (len == 0) return;
        Ctr ctr = new Ctr(new Kuznyechik());
        try {
            ctr.init(true, new ParametersWithIV(key, iv));
            ctr.processBytes(in, inOff, len, out, outOff);
        } finally {
            ctr.destroy();
        }
    }

    /**
     * Вычисляет CMAC от {@code aad[0..aadLen) ‖ data[dataOff..dataOff+dataLen)} и записывает
     * {@link #TAG_LEN} байт в {@code out[outOff..]}. {@code out} может быть массивом, из которого
     * взяты {@code aad} и {@code data}: тег читается только после последнего поглощённого байта.
     *
     * @param aad     дополнительные аутентифицируемые данные или {@code null}
     * @param aadLen  длина AAD с начала {@code aad}
     * @param data    основные данные
     * @param dataOff начало данных
     * @param dataLen длина данных
     * @param key     ключ Кузнечика (32 байта)
     * @param out     буфер для тега
     * @param outOff  смещение тега
     */
    static void computeCmac(
            byte[] aad,
            int aadLen,
            byte[] data,
            int dataOff,
            int dataLen,
            SymmetricKey key,
            byte[] out,
            int outOff) {
        Cmac cmac = new Cmac(new Kuznyechik());
        try {
            cmac.init(key);
            if (aad != null) {
                cmac.update(aad, 0, aadLen);
            }
            cmac.update(data, dataOff, dataLen);
            cmac.doFinal(out, outOff);
        } finally {
            cmac.destroy();
        }
    }
}
