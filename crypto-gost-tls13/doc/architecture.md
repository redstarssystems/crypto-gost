# Структура пакетов

Классы организованы в подпакеты `org.rssys.gost.tls13.*`:

      (root)     TlsSession — оркестратор
                   └── TlsHandshakeEngine (engine/)

      (config)   TlsClientConfig / TlsServerConfig

      (message)  TlsMessageBuilder / TlsMessageParser / TlsEncoding

      (crypto)   TlsKeySchedule / HkdfStreebog
                   TlsTree / TlsTreeCache
                   TlsSignatureCodec / KdfGostR3411_2012_256

      (record)   TlsRecord / TlsTrafficKeys / TlsParsedRecord
                   (per-record ключи от TLSTREE из crypto/)

      (cert)     TlsCertificate / TlsCertificateValidator /
                   TlsOcspVerifier / TlsDerParser / Pkcs12Loader

      (psk)      PskStore / TlsPskHelper

      (transport) TlsTransport (interface)
                    SocketTlsTransport / InMemoryTlsTransport /
                    ChannelTlsTransport

Зависимости между подпакетами ацикличны: верхние уровни импортируют
нижние, нижние импортируют только root-классы (`TlsCiphersuite`,
`TlsConstants`, `TlsException`, `TlsUtils`).

# Слои (логическая архитектура)

    ────────────────────────────────────
      TlsSession — оркестратор
      └── engine/TlsHandshakeEngine — state machine (отвязан от I/O)
    ────────────────────────────────────
      config/TlsClientConfig / TlsServerConfig
    ────────────────────────────────────
      message/TlsMessageBuilder   TlsMessageParser
      TlsHandshakeMessage (engine/)
    ────────────────────────────────────
      crypto/TlsKeySchedule / HkdfStreebog
      record/TlsRecord / crypto:TlsTree / TlsTreeCache
      (ByteBuffer protect/unprotect overloads)
    ────────────────────────────────────
      cert/TlsCertificate / TlsOcspVerifier
      crypto/TlsSignatureCodec / cert:TlsDerParser
      record/TlsParsedRecord (public)
    ────────────────────────────────────
      transport/TlsTransport (interface)
        InMemoryTlsTransport
        SocketTlsTransport
        ChannelTlsTransport
    ────────────────────────────────────

## TlsSession (root)

Основной класс. Оркеструет handshake через `TlsHandshakeEngine`,
управляет `TlsRecord` (шифрование/дешифрование), транспортным I/O,
валидацией сертификатов. Реализует защищённую передачу данных, обработку
алертов. Методы:

<table>
<colgroup>
<col style="width: 28%" />
<col style="width: 71%" />
</colgroup>
<thead>
<tr>
<th style="text-align: left;">Метод</th>
<th style="text-align: left;">Описание</th>
</tr>
</thead>
<tbody>
<tr>
<td
style="text-align: left;"><p><code>handshakeAsClient()</code></p></td>
<td style="text-align: left;"><p>Делегирует
<code>TlsHandshakeEngine(Role.CLIENT)</code>. PSK → Cert+CV →
Finished</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>handshakeAsServer()</code></p></td>
<td style="text-align: left;"><p>Делегирует
<code>TlsHandshakeEngine(Role.SERVER)</code>. CR→Cert+CV→Fin или
PSK-abbreviated</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>write(byte[])</code></p></td>
<td style="text-align: left;"><p>Отправка данных (автоматическая
фрагментация при &gt;16383 байт)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>read()</code></p></td>
<td style="text-align: left;"><p>Приём данных + обработка пост-handshake
сообщений (KeyUpdate, NewSessionTicket)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>close()</code></p></td>
<td style="text-align: left;"><p>close_notify + уничтожение ключевого
материала</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>initiateKeyUpdate(boolean)</code></p></td>
<td style="text-align: left;"><p>Инициирует KeyUpdate (RFC 8446
§4.6.3)</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>setPskStore(PskStore)</code></p></td>
<td style="text-align: left;"><p>Устанавливает хранилище PSK для
resumption</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>setAlpnProtocols(List)</code></p></td>
<td style="text-align: left;"><p>Устанавливает ALPN-протоколы (RFC 7301)
для согласования</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>getSelectedAlpnProtocol()</code></p></td>
<td style="text-align: left;"><p>Возвращает согласованный ALPN-протокол
(null если ALPN не использовался)</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>getPeerCertificates()</code></p></td>
<td style="text-align: left;"><p>Возвращает сертификаты пира (для
mTLS)</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>getRequestedServerName()</code></p></td>
<td style="text-align: left;"><p>Возвращает SNI-имя (сервер)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>getCipherSuite()</code></p></td>
<td style="text-align: left;"><p>Возвращает согласованный cipher
suite</p></td>
</tr>
</tbody>
</table>

## TlsHandshakeEngine (engine/)

Пошаговая стейт машина для handshake, отвязанная от I/O. Принимает
handshake-фреймы (type+length+body), возвращает фреймы для отправки и
сигналы смены ключей. Используется `TlsSession` для оркестрации; в
будущем — для `SSLEngine`-совместимого JSSE-модуля.

Ключевые методы:

<table>
<colgroup>
<col style="width: 28%" />
<col style="width: 71%" />
</colgroup>
<thead>
<tr>
<th style="text-align: left;">Метод</th>
<th style="text-align: left;">Описание</th>
</tr>
</thead>
<tbody>
<tr>
<td style="text-align: left;"><p><code>start()</code></p></td>
<td style="text-align: left;"><p>Генерирует ClientHello (клиент) или
null (сервер)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>receive(frame)</code></p></td>
<td style="text-align: left;"><p>Обрабатывает входящий
handshake-фрейм</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>poll()</code></p></td>
<td style="text-align: left;"><p>Извлекает следующий исходящий фрейм
(или null)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>getReadKeys()</code> /
<code>getWriteKeys()</code></p></td>
<td style="text-align: left;"><p>Текущие ключи (с флагами
<code>has*Changed()</code> +
<code>acknowledgeKeyChange()</code>)</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>needsCertificateValidation()</code></p></td>
<td style="text-align: left;"><p>Сигнал для внешней проверки сертификата
узла</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>initiateKeyUpdate(boolean)</code></p></td>
<td style="text-align: left;"><p>Инициирует KeyUpdate (RFC 8446
§4.6.3)</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>receivePostHandshake(byte[])</code></p></td>
<td style="text-align: left;"><p>Обрабатывает KeyUpdate/NST от
пира</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>setClientAlpnProtocols(List)</code> /
<code>setServerAlpnProtocols(List)</code></p></td>
<td style="text-align: left;"><p>ALPN (RFC 7301)</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>getSelectedAlpnProtocol()</code></p></td>
<td style="text-align: left;"><p>Согласованный протокол прикладного
уровня</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>setPsk(byte[], byte[], long)</code> /
<code>setServerPsk(byte[])</code></p></td>
<td style="text-align: left;"><p>PSK для тестирования</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>isPskAccepted()</code></p></td>
<td style="text-align: left;"><p>Был ли принят PSK сервером</p></td>
</tr>
</tbody>
</table>

Режимы: полный handshake, PSK-abbreviated, mTLS. Кэширует app traffic
secrets в `finishHandshake()`/`receiveClientFinished()` для KeyUpdate.

## TlsClientConfig / TlsServerConfig / SniCertificateSelector (config/)

Builder-конфигураторы. Набор `with*()` методов.

TlsClientConfig: \* ciphersuite \*
`withClientCertificate(TlsCertificate)` /
`withClientCertificateChain(List)` / `withClientPrivateKey` \*
`withCaPublicKey`, `withServerHostname`, `withRequireOcspStapling` \*
`withAlpnProtocols(List)` — ALPN-протоколы (RFC 7301)

TlsServerConfig: \* ciphersuite, serverCertificateChain,
serverPrivateKey \* `withOcspStaplingResponse`, `withCaPublicKey` (mTLS)
\* `withAlpnProtocols(List)` — ALPN-протоколы (RFC 7301)

`SniCertificateSelector` — функциональный интерфейс: по hostname
возвращает `TlsServerCredentials` (цепочка + ключ + OCSP). Необходим для
multi-tenant серверов.

## TlsMessageBuilder / TlsMessageParser (message/)

Статические утилиты сборки/разбора handshake-сообщений. Все форматы —
RFC 8446 §4. Builder использует инжектированные ключи/сертификаты для
подписи CertificateVerify. Parser не имеет состояния.

## TlsKeySchedule / HkdfStreebog (crypto/)

Key schedule RFC 8446 §7.1 на HKDF-Streebog (RFC 5869). Состояние:
PSK→\[Early Secret\]→Handshake→Master. Для каждого перехода —
deriveSecret() через HMAC-Streebog expandLabel. DeriveResumptionPsk —
для NewSessionTicket.

## TlsRecord / TlsTree / TlsTreeCache (record/ + crypto/)

Уровень записей. MGM-AEAD шифрование (Kuznyechik + Streebog). Per-record
ключи через TLSTREE (RFC 9367 §4.2). S-вариант (SNMAX=cipher-specific)
для L- и S-режимов. TlsTreeCache — оптимизация: кэширует промежуточные
уровни KDF, пересчитывает только при изменении маскированной части
seqNum.

## TlsCertificate / TlsOcspVerifier / TlsDerParser (cert/)

- `TlsCertificate` — X.509 парсер (DER → поля). Верификация подписи,
  hostname, EKU, цепочек.

- `TlsOcspVerifier` — верификация OCSP-ответов (RFC 6960).

- `TlsDerParser` — низкоуровневые DER-TLV утилиты.

## TlsTransport (transport/)

    public interface TlsTransport extends AutoCloseable {
        void sendRecord(byte[] record) throws IOException;
        byte[] receiveRecord() throws IOException;
        void close() throws IOException;
    }

Реализации:

- `InMemoryTlsTransport` — для тестов и взаимодействия в рамках одной
  JVM.

- `SocketTlsTransport` — блокирующий I/O через `java.net.Socket`.
  Требует `socket.setSoTimeout()`.

- `ChannelTlsTransport` — NIO `SocketChannel` (blocking mode). Прерываем
  через `Thread.interrupt()`. Поддерживает `SocketChannel.close()` для
  экстренного прерывания.

# Handshake flow (клиент, полный)

1.  PSK lookup → binder computation (если PskStore не пуст)

2.  ECDHE keygen → ClientHello с PSK/SNI/ALPN extensions

3.  ServerHello + PSK accept/reject

4.  ECDHE shared secret → Handshake Secret

5.  EncryptedExtensions (с ALPN-протоколом, если согласован)

6.  \[если нет PSK\] Certificate → CertificateVerify

7.  Server Finished → verify

8.  \[если mTLS\] Client Certificate → CertificateVerify

9.  Client Finished → Master Secret → app traffic keys

10. NewSessionTicket (от сервера) + KeyUpdate (опционально)

# Threading model

- `TlsSession` **не thread-safe**. Одна сессия = один поток.

- `InMemoryPskStore` **thread-safe** (ConcurrentHashMap с атомарным
  compute() для expire+remove). Может быть shared между сессиями.

- `InMemoryTlsTransport.Pair` **не thread-safe** для single-ended,
  thread-safe для paired (LinkedBlockingQueue).

- `SocketTlsTransport`, `ChannelTlsTransport` не thread-safe — один
  экземпляр на одну TLS-сессию.

# Ограничения

- **0-RTT не поддерживается**

- **External PSK не поддерживается** (только resumption PSK)

- **HRR не поддерживается** (единственная named group в key\_share —
  GC256A)

- **KeyUpdate** реализован (RFC 8446 §4.6.3)

- **OCSP только issuer-based** (delegated OCSP не поддерживается)

- **DN сравнение** — byte-exact DER. Для MVP достаточно, но не учитывает
  эквивалентные кодировки.

- **CertificateRequest.certificate\_authorities** не отправляется

- **InMemoryPskStore.get()+remove() race** — документирован, single-use
  best-effort
