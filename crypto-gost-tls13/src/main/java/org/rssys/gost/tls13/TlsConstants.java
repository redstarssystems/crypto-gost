package org.rssys.gost.tls13;

/**
 * Константы протокола TLS 1.3 (RFC 8446) для ГОСТ-криптографии
 * по RFC 9367 (TLS 1.3 GOST Cipher Suites).
 * Содержит типы записей, handshake-сообщений, cipher suite ID,
 * схемы подписи, именованные группы, метки KDF и контекстные строки.
 */
public final class TlsConstants {

    // типы содержимого TLS-записей (RFC 8446 раздел 5)
    public static final byte CT_ALERT = 21;
    public static final byte CT_HANDSHAKE = 22;
    public static final byte CT_APPLICATION_DATA = 23;
    public static final byte CT_CHANGE_CIPHER_SPEC = 20;

    // типы handshake-сообщений (RFC 8446 раздел 4)
    public static final byte HT_CLIENT_HELLO = 1;
    public static final byte HT_SERVER_HELLO = 2;
    public static final byte HT_ENCRYPTED_EXTENSIONS = 8;
    public static final byte HT_CERTIFICATE = 11;
    public static final byte HT_CERTIFICATE_VERIFY = 15;
    public static final byte HT_CERTIFICATE_REQUEST = 13;
    public static final byte HT_NEW_SESSION_TICKET = 4;
    public static final byte HT_FINISHED = 20;
    public static final byte HT_KEY_UPDATE = 24;
    // message_hash — RFC 8446 §4.4.1: хеш первого ClientHello при HRR
    public static final byte HT_MESSAGE_HASH = (byte) 254;

    // версии протокола
    public static final int PROTOCOL_TLS_1_2 = 0x0303;
    public static final int PROTOCOL_TLS_1_3 = 0x0304;
    public static final byte LEGACY_VERSION_MAJOR = 0x03;
    public static final byte LEGACY_VERSION_MINOR = 0x03;

    // ГОСТ cipher suites (RFC 9367 §3.1.2)
    public static final int TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L = 0xC103; // Loop ре-кейинг
    public static final int TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S =
            0xC105; // Seal (TLSTREE, SNMAX=2^42-1)

    // IANA-имена cipher suites (RFC 9367 §3.1.2)
    public static final String IANA_TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L =
            "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L";
    public static final String IANA_TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S =
            "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S";

    // схемы подписи ГОСТ (RFC 9367 §3.2 + RFC 8446)
    // 256-бит
    public static final int SIG_GOST_TC26_A_256 = 0x0709; // id_tc26_gost_3410_2012_256_paramSetA
    public static final int SIG_GOST_CRYPTOPRO_A = 0x070A; // id_GostR3410_2001_CryptoPro_A_ParamSet
    public static final int SIG_GOST_CRYPTOPRO_B = 0x070B; // id_GostR3410_2001_CryptoPro_B_ParamSet
    public static final int SIG_GOST_CRYPTOPRO_C = 0x070C; // id_GostR3410_2001_CryptoPro_C_ParamSet
    // 512-бит
    public static final int SIG_GOST_TC26_512_A = 0x070D; // id_tc26_gost_3410_12_512_paramSetA
    public static final int SIG_GOST_TC26_512_B = 0x070E; // id_tc26_gost_3410_12_512_paramSetB
    public static final int SIG_GOST_TC26_512_C = 0x070F; // id_tc26_gost_3410_2012_512_paramSetC

    // именованные группы/кривые ГОСТ (RFC 9367 §3.1)
    // 256-бит
    public static final int GRP_GC256A = 0x0022; // id_tc26_gost_3410_2012_256_paramSetA
    public static final int GRP_GC256B = 0x0023; // id_GostR3410_2001_CryptoPro_A_ParamSet
    public static final int GRP_GC256C = 0x0024; // id_GostR3410_2001_CryptoPro_B_ParamSet
    public static final int GRP_GC256D = 0x0025; // id_GostR3410_2001_CryptoPro_C_ParamSet
    // 512-бит
    public static final int GRP_GC512A = 0x0026; // id_tc26_gost_3410_12_512_paramSetA
    public static final int GRP_GC512B = 0x0027; // id_tc26_gost_3410_12_512_paramSetB
    public static final int GRP_GC512C = 0x0028; // id_tc26_gost_3410_2012_512_paramSetC

    // размеры хешей Streebog
    public static final int STREEBOG_256_HASH_LEN = 32;
    public static final int STREEBOG_512_HASH_LEN = 64;

    // экспорт ключевого материала (RFC 8446 §7.5)
    /** Предел длины HkdfLabel.label с префиксом "tls13 " (RFC 8446 §7.1). */
    public static final int HKDF_LABEL_MAX_LENGTH = 255;

    /** Префикс метки HkdfLabel (RFC 8446 §7.1). */
    public static final String HKDF_LABEL_PREFIX = "tls13 ";

    /** Наибольшая длина метки экспорта в UTF-8: вместе с префиксом "tls13 " умещается в 255 байт. */
    public static final int EXPORTER_LABEL_MAX_LENGTH =
            HKDF_LABEL_MAX_LENGTH - HKDF_LABEL_PREFIX.length();

    /**
     * Наибольшая длина контекста экспорта. В TLS 1.3 контекст хэшируется и ограничения RFC не
     * имеет; предел 2¹⁶-1 взят из RFC 5705 §4 как защитный.
     */
    public static final int EXPORTER_CONTEXT_MAX_LENGTH = 65535;

    /** Предельная кратность длины HKDF-Expand к длине хэша (RFC 5869 §2.3). */
    public static final int HKDF_EXPAND_MAX_BLOCKS = 255;

    // размер случайного поля в ClientHello/ServerHello (RFC 8446 §4.1.2)
    public static final int RANDOM_LENGTH = 32;

    /**
     * Длина неизменных полей preamble ClientHello (RFC 8446 §4.1.2): legacy_version (2), random,
     * длина legacy_session_id (1), длина списка шифронаборов (2), compression_methods (длина 1 и
     * значение 1). Остальное в preamble: идентификатор сессии и сами шифронаборы.
     */
    public static final int CLIENT_HELLO_FIXED_PREAMBLE_LENGTH = 2 + RANDOM_LENGTH + 1 + 2 + 2;

    // TLSInnerPlaintext.length ≤ 2^14 (RFC 8446 §5.2)
    // fragment(N) || inner_type(1) + padding
    public static final int MAX_PLAINTEXT_LENGTH = 16384;
    public static final int RECORD_HEADER_SIZE = 5;

    /** Длина содержимого совместимого change_cipher_spec (RFC 8446 §5, §D.4): один октет. */
    public static final int CCS_COMPAT_PAYLOAD_LENGTH = 1;

    /** Единственное допустимое значение совместимого change_cipher_spec (RFC 8446 §5). */
    public static final byte CCS_COMPAT_VALUE = 0x01;

    /** Полный размер записи совместимого change_cipher_spec: заголовок и один октет содержимого. */
    public static final int CCS_RECORD_SIZE = RECORD_HEADER_SIZE + CCS_COMPAT_PAYLOAD_LENGTH;

    public static final int HANDSHAKE_HEADER_SIZE = 4;

    /** Заголовок CertificateVerify: схема подписи (2) и длина подписи (2) (RFC 8446 §4.4.3). */
    public static final int CERTIFICATE_VERIFY_HEADER_SIZE = 4;

    public static final int MGM_TAG_SIZE = 16;
    public static final int KUZNYECHIK_KEY_SIZE = 32;
    public static final int MGM_IV_SIZE = 16;
    public static final int MAX_CERT_CHAIN_LENGTH = 10;

    /** Максимальный размер одного сертификата в DER (256 КБ).
     *  Типичный ГОСТ-сертификат — 1–10 КБ, 256 КБ даёт 25x запас. */
    public static final int MAX_CERT_SIZE = 262_144;

    /** Длина префикса поля certificate_list{@code <0..2^24-1>} (RFC 8446 §4.4.2). */
    public static final int CERT_LIST_LENGTH_FIELD = 3;

    /** Длина префикса поля cert_data{@code <0..2^24-1>} внутри CertificateEntry. */
    public static final int CERT_ENTRY_LEN_FIELD = 3;

    /** Длина префикса поля extensions{@code <0..2^16-1>} внутри CertificateEntry. */
    public static final int CERT_ENTRY_EXT_LEN_FIELD = 2;

    /** Максимум байт в extensions одной CertificateEntry: поле extLen 16-битное.
     *  Не путать с MAX_OCSP_RESPONSE_SIZE — тот применяется при отдельном разборе
     *  GostOcspResponse, а здесь верхнюю границу задаёт само 16-битное поле длины. */
    public static final int MAX_CERT_ENTRY_EXTENSIONS_SIZE = 65_535;

    /** Верхняя граница суммарного размера реассемблируемого handshake-сообщения.
     *  <p>msgLen в заголовке — 24-битное поле (до 16 МБ), реассемблирование из многих
     *  TLS-записей может накопить буфер такого размера -> per-connection resource exhaustion.
     *  <p>Лимит вычисляется из компонентных констант так, чтобы совпадать по построению
     *  с потолком приёма парсера Certificate (самое крупное легитимное сообщение), и
     *  автоматически оставаться консистентным при изменении MAX_CERT_SIZE/MAX_CERT_CHAIN_LENGTH.
     *  <p>Слагаемое {@code + 1} — пустой request_context: парсер Certificate жёстко ожидает
     *  пустой контекст (TlsMessageParser пропускает ровно 1 байт длины). Численно ≈3.2 МБ. */
    public static final int MAX_HANDSHAKE_MESSAGE_SIZE =
            HANDSHAKE_HEADER_SIZE
                    + 1
                    + CERT_LIST_LENGTH_FIELD
                    + MAX_CERT_CHAIN_LENGTH
                            * (CERT_ENTRY_LEN_FIELD
                                    + MAX_CERT_SIZE
                                    + CERT_ENTRY_EXT_LEN_FIELD
                                    + MAX_CERT_ENTRY_EXTENSIONS_SIZE);

    // максимальный размер ciphertext в TLS-записи (RFC 8446 §5.1)
    // 2^14 + 1 (inner_type) + 16 (max padding) + 16 (MGM tag) = 16401
    // округляем до 16640 для запаса на padding
    public static final int MAX_CIPHERTEXT_LENGTH = 16640;

    /**
     * Наибольшее число KeyUpdate пира за одно окно {@link #KEY_UPDATE_RATE_WINDOW_NANOS}. Нормальный
     * темп - единицы за всё соединение, поэтому предел с большим запасом отсекает только поток
     * сообщений: каждый KeyUpdate требует HKDF и инициализации MGM.
     *
     * <p>Окно считается по времени обработки, а не отправки: если получатель отстаёт, накопленные
     * KeyUpdate разбираются пачкой и могут выйти за предел, хотя пир отправлял их редко. Для
     * настоящих приложений это недостижимо (ключ меняют раз в часы или гигабайты), но нагрузочный
     * тест обязан не давать очереди пира расти.</p>
     */
    public static final int MAX_PEER_KEY_UPDATES_PER_WINDOW = 10;

    /** Значение request_update в KeyUpdate: ответное обновление ключей не требуется (RFC 8446 §4.6.3). */
    public static final byte KEY_UPDATE_NOT_REQUESTED = 0;

    /** Значение request_update в KeyUpdate: пир должен ответить своим KeyUpdate (RFC 8446 §4.6.3). */
    public static final byte KEY_UPDATE_REQUESTED = 1;

    /** Предел длины строки из данных пира (имя хоста и т.п.) в записи журнала. */
    public static final int LOG_PEER_STRING_LIMIT = 255;

    /** Длина окна подсчёта KeyUpdate пира, наносекунды (одна секунда). */
    public static final long KEY_UPDATE_RATE_WINDOW_NANOS = 1_000_000_000L;

    /**
     * Предел числа служебных сообщений после рукопожатия, которые {@code read()} обрабатывает за
     * один вызов, не получив данных приложения (RFC 8446 §5: защита от потока служебных
     * сообщений). Единственный лимит числа сообщений: записей одно сообщение может занимать
     * несколько, а в одной записи несколько сообщений, их бюджет задаёт
     * {@link #MAX_POST_HANDSHAKE_RECORDS}.
     */
    public static final int MAX_POST_HANDSHAKE = 8;

    /**
     * Наибольшее число NewSessionTicket, которое сервер отправляет после рукопожатия. Клиентский
     * {@code read()} обрабатывает не более {@link #MAX_POST_HANDSHAKE} сообщений за вызов, а часть
     * этого лимита нужна KeyUpdate: при большем числе тикетов клиент до данных приложения не
     * дошёл бы.
     */
    public static final int MAX_TICKETS_TO_SEND = 5;

    /**
     * Наибольший размер служебного сообщения после рукопожатия вместе с заголовком, 131 342 байта.
     * После рукопожатия бывают только KeyUpdate (1 байт тела) и NewSessionTicket: lifetime (4),
     * age_add (4), nonce до 255 байт с однобайтовой длиной, ticket до 2¹⁶ - 1 байт с двухбайтовой
     * длиной и расширения до 2¹⁶ - 1 байт с двухбайтовой длиной. Общий предел
     * {@link #MAX_HANDSHAKE_MESSAGE_SIZE} рассчитан на цепочку сертификатов и для служебных
     * сообщений слишком велик: сообщение, разрезанное на однобайтовые записи, копилось бы до него.
     */
    public static final int MAX_POST_HANDSHAKE_MESSAGE_SIZE =
            HANDSHAKE_HEADER_SIZE + 4 + 4 + 1 + 255 + 2 + 65535 + 2 + 65535;

    /**
     * Наибольший размер сообщения рукопожатия, кроме Certificate, вместе с заголовком: 131 400 байт.
     * Самое крупное из них по ширине полей RFC 8446 §4.1.2 — ClientHello: legacy_version (2),
     * random (32), legacy_session_id до 32 байт с однобайтовой длиной, cipher_suites до 2¹⁶ - 2 байт
     * с двухбайтовой длиной, legacy_compression_methods до 255 байт с однобайтовой длиной и
     * расширения до 2¹⁶ - 1 байт с двухбайтовой длиной. Остальные сообщения (ServerHello,
     * EncryptedExtensions, CertificateRequest, CertificateVerify, Finished) заведомо меньше.
     * Мегабайтный {@link #MAX_HANDSHAKE_MESSAGE_SIZE} нужен только цепочке сертификатов; без
     * отдельного предела пир до своей аутентификации копил бы до него любое сообщение.
     */
    public static final int MAX_HANDSHAKE_NON_CERTIFICATE_MESSAGE_SIZE =
            HANDSHAKE_HEADER_SIZE + 2 + 32 + 1 + 32 + 2 + 65534 + 1 + 255 + 2 + 65535;

    /**
     * Бюджет handshake-записей после рукопожатия за один вызов {@code read()}: защита от потока
     * мелких записей. Выведен из пределов сообщений: {@link #MAX_POST_HANDSHAKE} сообщений, каждое
     * наибольшего размера {@link #MAX_POST_HANDSHAKE_MESSAGE_SIZE}, разрезанных на записи полного
     * размера ({@link #MAX_PLAINTEXT_LENGTH}). Это бюджет вызова, а не одного сообщения; данные
     * приложения и alert в нём не учитываются и читаются всегда.
     */
    public static final int MAX_POST_HANDSHAKE_RECORDS =
            MAX_POST_HANDSHAKE
                    * ((MAX_POST_HANDSHAKE_MESSAGE_SIZE + MAX_PLAINTEXT_LENGTH - 1)
                            / MAX_PLAINTEXT_LENGTH);

    /** Таймаут сессии по умолчанию, 24 часа (RFC 8446 §4.6.1). */
    public static final int DEFAULT_SESSION_TIMEOUT = 86400;

    /** Размер идентификатора сессии в байтах. */
    public static final int SESSION_ID_LENGTH = 32;

    /** Запас в байтах для буфера TLS-записи:
     *  RECORD_HEADER_SIZE (5) + MGM_TAG_SIZE (16) + запас на паддинг (43). */
    public static final int RECORD_BUFFER_HEADROOM = 64;

    // метки уровней TLSTREE (RFC 9367 §4.2)
    public static final String LABEL_TLSTREE_LEVEL1 = "level1";
    public static final String LABEL_TLSTREE_LEVEL2 = "level2";
    public static final String LABEL_TLSTREE_LEVEL3 = "level3";

    // коды TLS-алертов (RFC 8446 раздел 6)
    public static final byte ALERT_WARNING = 1;
    public static final byte ALERT_FATAL = 2;
    public static final byte CLOSE_NOTIFY = 0;

    /** Длина тела alert-записи: уровень и описание (RFC 8446 §6). */
    public static final int ALERT_BODY_LENGTH = 2;

    public static final byte ALERT_UNEXPECTED_MESSAGE = 10;
    public static final byte ALERT_BAD_CERTIFICATE = 42;
    public static final byte ALERT_HANDSHAKE_FAILURE = 40;
    public static final byte ALERT_ILLEGAL_PARAMETER = 47;
    public static final byte ALERT_UNKNOWN_CA = 48;
    public static final byte ALERT_DECODE_ERROR = 50;
    public static final byte ALERT_DECRYPT_ERROR = 51;
    public static final byte ALERT_MISSING_EXTENSION = 109;
    public static final byte ALERT_UNSUPPORTED_EXTENSION = 110;
    public static final byte ALERT_RECORD_OVERFLOW = 22;
    public static final byte ALERT_CERTIFICATE_EXPIRED = 45;
    public static final byte ALERT_CERTIFICATE_REVOKED = 44;
    public static final byte ALERT_CERTIFICATE_REQUIRED = 116;
    public static final byte ALERT_INTERNAL_ERROR = 80;
    public static final byte ALERT_BAD_RECORD_MAC = 20;
    public static final byte ALERT_UNSUPPORTED_CERTIFICATE = 43;
    public static final byte ALERT_CERTIFICATE_UNKNOWN = 46;
    public static final byte ALERT_ACCESS_DENIED = 49;
    public static final byte ALERT_PROTOCOL_VERSION = 70;
    public static final byte ALERT_INSUFFICIENT_SECURITY = 71;
    public static final byte ALERT_INAPPROPRIATE_FALLBACK = 86;
    public static final byte ALERT_USER_CANCELED = 90;
    public static final byte ALERT_UNRECOGNIZED_NAME = 112;
    public static final byte ALERT_BAD_CERTIFICATE_STATUS_RESPONSE = 113;
    public static final byte ALERT_UNKNOWN_PSK_IDENTITY = 115;

    // идентификаторы TLS-расширений (RFC 8446 раздел 4.2)
    public static final int EXT_SERVER_NAME = 0;
    public static final int EXT_SIGNATURE_ALGORITHMS = 13;

    /** signature_algorithms_cert (RFC 8446 §4.2.3): схемы подписи сертификатов отдельно от CertificateVerify. */
    public static final int EXT_SIGNATURE_ALGORITHMS_CERT = 50;

    public static final int EXT_SUPPORTED_GROUPS = 10;
    public static final int EXT_SUPPORTED_VERSIONS = 43;
    public static final int EXT_KEY_SHARE = 51;
    public static final int EXT_STATUS_REQUEST = 5;
    public static final int EXT_PRE_SHARED_KEY = 41;
    public static final int EXT_PSK_KEY_EXCHANGE_MODES = 45;
    public static final int EXT_CERTIFICATE_AUTHORITIES = 47;
    public static final int EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 16; // RFC 7301
    public static final int EXT_COOKIE = 44;
    // early_data (RFC 8446 §4.2.10): допустим в ClientHello, EncryptedExtensions и NewSessionTicket
    public static final int EXT_EARLY_DATA = 42;
    // oid_filters (RFC 8446 §4.2.5)
    public static final int EXT_OID_FILTERS = 48;
    // CertificateStatusType ocsp (RFC 6066 §8): тип запроса/ответа в status_request
    public static final int STATUS_TYPE_OCSP = 1;
    // Размер поля длины uint24 (OCSPResponse<1..2^24-1>, RFC 6066 §8)
    public static final int UINT24_SIZE = 3;
    // CertificateStatus: status_type(1) + uint24-длина ответа
    public static final int CERTIFICATE_STATUS_HEADER_SIZE = 1 + UINT24_SIZE;
    // Максимум длины Extension.extension_data и блока extensions записи: uint16 (RFC 8446 §4.2)
    public static final int MAX_EXTENSIONS_BLOCK_SIZE = 0xFFFF;
    // Максимум OCSP-ответа в staple. Предел задаёт не uint24 из RFC 6066, а uint16 блока
    // extensions записи: type(2) + length(2) + CertificateStatus помещаются в 2^16-1 байт.
    public static final int MAX_OCSP_STAPLE_SIZE =
            MAX_EXTENSIONS_BLOCK_SIZE - 2 - 2 - CERTIFICATE_STATUS_HEADER_SIZE;
    // max_fragment_length (RFC 6066 §4)
    public static final int EXT_MAX_FRAGMENT_LENGTH = 1;
    public static final int MAX_FRAG_LEN_512 = 1;
    public static final int MAX_FRAG_LEN_1024 = 2;
    public static final int MAX_FRAG_LEN_2048 = 3;
    public static final int MAX_FRAG_LEN_4096 = 4;

    // коды алертов
    /** no_application_protocol (RFC 7301 §3.2): сервер не выбрал протокол ALPN */
    public static final byte ALERT_NO_APPLICATION_PROTOCOL = 120;

    // режимы PSK (RFC 8446 раздел 4.2.9)
    public static final byte PSK_DHE_KE = 1;
    // Минимальный размер записи PskIdentity: длина identity (2) + identity (1) + age (4), RFC 8446
    // §4.2.11
    public static final int MIN_PSK_IDENTITY_ENTRY = 2 + 1 + 4;
    // Постоянная часть расширения pre_shared_key с одной identity и одним binder: длина списка
    // identity (2),
    // длина identity (2), obfuscated_ticket_age (4), длина списка binders (2), длина binder (1)
    public static final int PSK_EXTENSION_FIXED_LENGTH = 2 + 2 + 4 + 2 + 1;
    // PskBinderEntry: opaque<32..255> (RFC 8446 §4.2.11)
    public static final int MIN_PSK_BINDER_LENGTH = 32;
    // Сколько первых identity сервер просматривает в хранилище; остальные игнорируются без ошибки,
    // иначе клиент заставит сервер обращаться к хранилищу (возможно сетевому) на каждую из тысяч
    // identity
    public static final int MAX_PSK_IDENTITIES = 5;

    /**
     * Предел длины имени в {@code server_name}: 253 символа текстовой формы без конечной точки.
     * RFC 1035 §2.3.4 ограничивает имя 255 октетами проводной формы (метки с байтами длины и
     * корень), а RFC 6066 §3 передаёт имя текстом без точки, что даёт 253.
     */
    public static final int MAX_SERVER_NAME_LENGTH = 253;

    /** Заголовок записи ServerName: name_type(1) + длина имени(2) (RFC 6066 §3). */
    public static final int SERVER_NAME_ENTRY_HEADER_LENGTH = 3;

    /** Предел длины имени протокола ALPN: {@code ProtocolName<1..2^8-1>} (RFC 7301 §3.1). */
    public static final int ALPN_PROTOCOL_NAME_MAX_LENGTH = 255;

    /** Предел суммарной длины имён в списке ALPN: {@code protocol_name_list<2..2^16-1>} (RFC 7301 §3.1). */
    public static final int ALPN_PROTOCOL_LIST_MAX_LENGTH = 65535;

    /** Предел длины тикета: {@code opaque ticket<1..2^16-1>} (RFC 8446 §4.6.1). */
    public static final int MAX_TICKET_LENGTH = 65535;

    /** Длина ticket_nonce у выдаваемых сервером тикетов: индекс тикета в виде 8 октетов big-endian. */
    public static final int TICKET_NONCE_LENGTH = 8;

    /** Начальный размер буфера сборки handshake-сообщений из записей. */
    public static final int HANDSHAKE_BUFFER_INITIAL_CAPACITY = 2048;

    /** Наименьшая запись ServerName: заголовок и один байт имени. */
    public static final int SERVER_NAME_ENTRY_MIN_LENGTH = SERVER_NAME_ENTRY_HEADER_LENGTH + 1;

    // привязка клиентского PSK-тикета к модели доверия (см. PskBindingFactory)
    /** Доменный тег хэша привязки: отделяет его от любых других хэшей от тех же данных. */
    public static final String PSK_BINDING_DOMAIN_TAG = "gost-tls13-psk-binding";

    /**
     * Версия профиля привязки. Состав канонической записи — перечисление полей, и оно тихо
     * устареет, если в {@code TlsClientConfig} появится новая настройка, влияющая на принятие
     * сервера (политика отзыва, новый предел и т. п.). При добавлении такой настройки её нужно
     * внести в запись и поднять версию: старые тикеты перестанут предъявляться.
     */
    public static final byte PSK_BINDING_PROFILE_VERSION = 1;

    /**
     * Идентификатор модели доверия серверных записей: серверу не из чего проверять собеседника
     * при выдаче тикета, привязка серверной записи состоит из имени SNI клиента.
     */
    public static final String PSK_BINDING_SERVER_ID = "server";

    /** Режим привязки: цепочка сервера проверяется, имя сверяется с сертификатом. */
    public static final byte PSK_BINDING_MODE_CHAIN_AND_NAME = 1;

    /** Режим привязки: цепочка проверяется, имя с сертификатом не сверяется. */
    public static final byte PSK_BINDING_MODE_CHAIN_ONLY = 2;

    /** Режим привязки: сервер не аутентифицируется по цепочке (только небезопасный тестовый режим). */
    public static final byte PSK_BINDING_MODE_NO_SERVER_AUTH = 3;

    // строковое имя протокола (RFC 8446)
    public static final String PROTOCOL_TLS13 = "TLSv1.3";

    // контекстные строки CertificateVerify (RFC 8446 раздел 4.4.3)
    public static final String SERVER_CERTIFICATE_VERIFY_CTX = "TLS 1.3, server CertificateVerify";
    public static final String CLIENT_CERTIFICATE_VERIFY_CTX = "TLS 1.3, client CertificateVerify";

    // Допуск для проверки ticket_age при PSK-возобновлении (RFC 8446 §4.2.11.2)
    // ±60 секунд: компенсирует clock skew и сетевую задержку, блокирует gross replay
    public static final long PSK_AGE_TOLERANCE_MS = 60_000L;

    private TlsConstants() {}
}
