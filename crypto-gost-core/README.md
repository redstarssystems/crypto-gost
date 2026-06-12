# Криптографическое ядро алгоритмов ГОСТ — crypto-gost-core

Поддерживаемые алгоритмы ГОСТ в модуле `crypto-gost-core`:

- **ГОСТ Р 34.11-2012** — хэш-функция «Стрибог» 256 и 512 бит (RFC
  6986).

- **ГОСТ Р 34.12-2015** — блочный шифр «Кузнечик», ключ 256 бит.

- **ГОСТ Р 34.13-2015** — режимы шифрования CBC, CFB, CTR, OFB;
  имитовставка (CMAC).

- **ГОСТ Р 34.10-2012** — электронная подпись 256 и 512 бит (RFC 7091).

- **HMAC-Стрибог** — RFC 7836 (HMAC-Streebog-256 и HMAC-Streebog-512).

- **MGM (Multilinear Galois Mode)** — AEAD-режим для Кузнечика,
  RFC 9058. Совместим с OpenSSL.

- **CTR-ACPKM и CTR-ACPKM-OMAC** — режимы шифрования с ACPKM
  (Re-keying), RFC 8645, RFC 9337 §5.

- **KDF\_GOSTR3411\_2012\_256 и KDF\_TREE\_GOSTR3411\_2012\_256** —
  функции выработки ключевого материала, RFC 7836 §4.4 и §4.5.

- **ECDH (ГОСТ Р 34.10-2012)** — сырой общий секрет (X-координата
  точки), для протокольных реализаций (TLS 1.3), RFC 9367 §6.1.1.

- **VKO\_GOSTR3410\_2012\_256** — согласование ключей с UKM и
  хэшированием Стрибог-256, RFC 7836 §4.3.1.

- **KExp15/KImp15** — экспорт и импорт ключей на шифре Кузнечик
  (MAC-then-Encrypt), RFC 9189 §8.2.1.

- **PBKDF2-HMAC-Стрибог** — вывод ключа из пароля, RFC 2898 §5.2.

Дополнительные алгоритмы (не ГОСТ):

- **SCrypt** — функция выработки ключа на основе пароля (RFC 7914).

**Для модуля `crypto-gost-core` выполнена кросс-валидация на
совместимость с `openssl (ГОСТ)` и `Bouncycastle`.**

Криптографическое ядро предоставляет два независимых API для работы:

- `org.rssys.gost.api` — высокоуровневый API, не требует регистрации
  провайдера. Код лаконичнее, ориентирован на пользователя.

- `org.rssys.gost.jca` — JCA/JCE-совместимый API, интегрируется со
  стандартной инфраструктурой Java.

Все статические методы потокобезопасны.  

## Генерация ключей

### Управление симметричными ключами

#### Настройка провайдера (только для JCA API)

Перед использованием JCA-методов необходимо зарегистрировать провайдер
один раз:

    import java.security.Security;
    import org.rssys.gost.jca.RssysGostProvider;
    Security.addProvider(new RssysGostProvider());

#### Генерация симметричного ключа

Генерация случайного 256-битного ключа для шифра "Кузнечик" (ГОСТ Р
34.12-2015). По умолчанию, как источник энтропии используется единый
экземпляр `CryptoRandom` (org.rssys.gost.util.CryptoRandom.INSTANCE).

Через `org.rssys.gost.api`

    import org.rssys.gost.api.KeyGenerator;
    import org.rssys.gost.cipher.SymmetricKey;

    SymmetricKey key = KeyGenerator.generateSymmetricKey();
    try {
        // использование ключа
    } finally {
        key.destroy(); // обнуляет ключевой материал в памяти
    }

Через JCA (`org.rssys.gost.jca`)

    import javax.crypto.KeyGenerator;
    import javax.crypto.SecretKey;

    KeyGenerator kg = KeyGenerator.getInstance("Kuznyechik", "RssysGostProvider");
    SecretKey key = kg.generateKey();
    try {
        // использование ключа
    } finally {
        key.destroy(); // обнуляет ключевой материал в памяти
    }

#### Импорт и экспорт симметричного ключа

Симметричный ключ хранится как сырые байты `byte[]`.

Никогда не храните симметричный ключ в открытом виде. Для хранения
используйте шифрование ключа другим ключом (KEK) или вывод из пароля
через scrypt (см. ниже).

#### org.rssys.gost.api

Экспорт ключа в byte\[\]

    import org.rssys.gost.cipher.SymmetricKey;

    SymmetricKey key = ...; // выработан или загружен ранее
    // getKey() возвращает defensive copy — мутация результата не влияет на ключ внутри объекта
    byte[] rawKey = key.getKey(); // 32 байта
    try {
        // сохранить rawKey в зашифрованном хранилище ...
    } finally {
        java.util.Arrays.fill(rawKey, (byte) 0); // обнулить после использования
    }

Импорт ключа из byte\[\]

    import org.rssys.gost.cipher.SymmetricKey;

    byte[] rawKey = ...; // 32 байта, загружены из хранилища
    // Конструктор делает defensive copy — мутация rawKey после не влияет на ключ
    SymmetricKey key = new SymmetricKey(rawKey);
    try {
        // использование ключа ...
    } finally {
        key.destroy();                             // обнуляет ключ внутри объекта
        java.util.Arrays.fill(rawKey, (byte) 0);  // обнулить исходный массив
    }

Вывод ключа из пароля (scrypt, RFC 7914. не ГОСТ)

См. также `Pbkdf2Streebog` для выработки ключа из пароля строго по ГОСТ.

    import org.rssys.gost.api.KeyGenerator;
    import org.rssys.gost.cipher.SymmetricKey;
    import org.rssys.gost.util.CryptoRandom;

    // Соль должна быть случайной и уникальной для каждого пользователя/объекта
    // Минимальная рекомендуемая длина соли: 16 байт
    byte[] password = "секретный пароль".getBytes(StandardCharsets.UTF_8);
    byte[] salt     = new byte[16];
    CryptoRandom.INSTANCE.nextBytes(salt); // 
    SymmetricKey key = KeyGenerator.deriveKey(password, salt); // 
    try {
        // использование ключа ...
    } finally {
        key.destroy();
        java.util.Arrays.fill(password, (byte) 0); // 
    }

- Соль не является секретом — её можно хранить рядом с зашифрованными
  данными. Главное требование: соль уникальна для каждого объекта
  шифрования.

- Параметры по умолчанию: N=524288, r=8, p=1. Операция ресурсоёмкая — не
  вызывайте в цикле и не блокируйте UI-поток.

- `deriveKey` не обнуляет массив пароля — это ответственность
  вызывающего кода.

#### JCA (org.rssys.gost.jca)

Экспорт ключа в byte\[\]

    import org.rssys.gost.jca.key.GostSecretKey;

    GostSecretKey key = ...; // выработан или загружен ранее

    // returns defensive copy, бросает IllegalStateException если ключ уничтожен
    byte[] rawKey = key.getEncoded(); // 32 байта
    try {
        // сохранить rawKey в зашифрованном хранилище ...
    } finally {
        java.util.Arrays.fill(rawKey, (byte) 0);
    }

Импорт ключа из byte\[\] через `SecretKeyFactory` (рекомендуется)

    import javax.crypto.SecretKey;
    import javax.crypto.SecretKeyFactory;
    import javax.crypto.spec.SecretKeySpec;

    byte[] rawKey = ...; // 32 байта, загружены из хранилища
    SecretKeySpec spec = new SecretKeySpec(rawKey, "Kuznyechik");
    SecretKeyFactory skf = SecretKeyFactory.getInstance("Kuznyechik", "RssysGostProvider");
    SecretKey key = skf.generateSecret(spec);
    try {
        // использование ключа ...
    } finally {
        key.destroy();
        java.util.Arrays.fill(rawKey, (byte) 0);
    }

Импорт ключа через прямой конструктор `GostSecretKey`

    import org.rssys.gost.jca.key.GostSecretKey;
    byte[] rawKey = ...; // 32 байта, загружены из хранилища
    // algorithm: "Kuznyechik", "HmacGOST3411-2012-256", "HmacGOST3411-2012-512", "CMAC-Kuznyechik"
    GostSecretKey key = new GostSecretKey("Kuznyechik", rawKey);
    try {
        // использование ключа ...
    } finally {
        key.destroy();
        java.util.Arrays.fill(rawKey, (byte) 0);
    }

Конвертация между `SymmetricKey` и `GostSecretKey`

    import org.rssys.gost.cipher.SymmetricKey;
    import org.rssys.gost.jca.key.GostSecretKey;

    // api/ → JCA: SymmetricKey → GostSecretKey
    SymmetricKey symKey = ...; // из api/
    GostSecretKey jcaKey = new GostSecretKey("Kuznyechik", symKey); // 

    // JCA → api/: GostSecretKey → SymmetricKey
    GostSecretKey jcaKey2 = ...; // из JCA
    SymmetricKey symKey2 = jcaKey2.toSymmetricKey(); // 

- Конвертация создаёт копию ключевых байт. Уничтожение одного объекта не
  влияет на другой — вызывайте `destroy()` на обоих.

## Шифрование данных

Все алгоритмы используют шифр Кузнечик (ГОСТ Р 34.12-2015) с ключом 256
бит. Ключи считаются выработанными на предыдущем шаге (см. раздел
«Управление симметричными ключами»).

### Выбор алгоритма

В таблице приведены только некоторые режимы, рекомендуемые для начала,
обеспечивающие безопасную работу. Под API в таблице понимается или
`org.rssys.gost.api` или `org.rssys.gost.jca`

<table>
<colgroup>
<col style="width: 50%" />
<col style="width: 16%" />
<col style="width: 33%" />
</colgroup>
<thead>
<tr>
<th style="text-align: left;">Сценарий</th>
<th style="text-align: left;">Доступность в API</th>
<th style="text-align: left;">Алгоритм в API / JCA</th>
</tr>
</thead>
<tbody>
<tr>
<td style="text-align: left;"><p>Шифрование блока данных аутентификацией
и контролем целостности,<br />
ГОСТ Р 34.13-2015 CTR+CMAC</p></td>
<td style="text-align: left;"><p><code>api</code></p></td>
<td style="text-align: left;"><p><code>AuthenticatedCipher</code><br />
</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Шифрование блока данных<br />
(без аутентификации и без контроля целостности)<br />
ГОСТ Р 34.13-2015 CTR</p></td>
<td style="text-align: left;"><p><code>api</code> / JCA</p></td>
<td style="text-align: left;"><p><code>Cipher(CTR)</code> /
<code>Kuznyechik/CTR/NoPadding</code></p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Потоковое шифрование (файл или сокет) с
аутентификацией и контролем целостности<br />
ГОСТ Р 34.13-2015 CTR+CMAC</p></td>
<td style="text-align: left;"><p><code>api</code></p></td>
<td
style="text-align: left;"><p><code>AuthenticatedStream</code></p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Файл или сокет без
аутентификации</p></td>
<td style="text-align: left;"><p><code>api</code> / JCA</p></td>
<td style="text-align: left;"><p><code>Cipher.encryptingStream</code> /
<code>CipherOutputStream</code></p></td>
</tr>
<tr>
<td style="text-align: left;"><p>Шифрование буфера с аутентификацией
целостности<br />
(не ГОСТ, но носит рекомендательный характер)</p></td>
<td style="text-align: left;"><p><code>api</code> / JCA</p></td>
<td style="text-align: left;"><p><code>MgmCipher</code> /
<code>Kuznyechik/MGM/NoPadding</code></p></td>
</tr>
</tbody>
</table>

### Шифрование буфера

#### org.rssys.gost.api

AuthenticatedCipher — CTR + CMAC (ГОСТ Р 34.13-2015) с аутентификацией и
контролем целостности данных.

AuthenticatedCipher — это строительный блок, т.е. вам нужно понимать что
вы делаете и как его применять. В случае неверного применения есть риск
потери конфиденциальности данных.

Если не хочется вникать в детали — **используйте `AuthenticatedStream`,
который рекомендуется для большинства задач** шифрования потоков байтов
и файлов, (но не для TLS) и избавляет от знания нюансов криптографии.

    import org.rssys.gost.api.AuthenticatedCipher;
    import org.rssys.gost.cipher.SymmetricKey;
    import org.rssys.gost.util.AuthenticationException;

    SymmetricKey key = ...; // выработан ранее
    byte[] plaintext  = "открытые данные".getBytes(StandardCharsets.UTF_8);

    // Шифрование: IV генерируется автоматически
    // Формат пакета: [IV (8 байт)] [CMAC(ciphertext) (16 байт)] [шифртекст]
    byte[] packet = AuthenticatedCipher.seal(plaintext, key);

    // Расшифрование
    try {
        byte[] decrypted = AuthenticatedCipher.open(packet, key);
    } catch (AuthenticationException e) {
        // CMAC не совпал: данные повреждены или подменены
    } finally {
        key.destroy();
    }

MgmCipher — AEAD без AAD.

Это альтернатива AuthenticatedCipher, там тоже Кузнечик, но используется
другой режим.

MgmCipher также является строительным блоком, вам нужно понимать, что вы
делаете. Если не хочется вникать в детали — **используйте
`AuthenticatedStream`, который рекомендуется для большинства задач**
шифрования потоков байтов и файлов, но не для TLS.

    import org.rssys.gost.api.MgmCipher;
    import org.rssys.gost.cipher.SymmetricKey;
    import org.rssys.gost.util.AuthenticationException;

    SymmetricKey key = ...; // выработан ранее
    byte[] plaintext  = "открытые данные".getBytes(StandardCharsets.UTF_8);

    // Шифрование — ICN генерируется автоматически, шифр "Кузнечик"
    // Формат пакета: [ICN (16 байт)] [шифртекст] [тег (16 байт)]
    byte[] packet = MgmCipher.seal(plaintext, key);

    // Расшифрование
    try {
        byte[] decrypted = MgmCipher.open(packet, key);
    } catch (AuthenticationException e) {
        // Тег не совпал: данные повреждены или подменены
    }

MgmCipher — AEAD с AAD (ассоциированные данные).

Этот режим также является строительным блоком и необходимо понимание,
как его встраивать и использовать.

    import org.rssys.gost.api.MgmCipher;
    import org.rssys.gost.cipher.SymmetricKey;
    import org.rssys.gost.util.AuthenticationException;

    SymmetricKey key = ...; // выработан ранее
    byte[] plaintext  = "открытые данные".getBytes(StandardCharsets.UTF_8);
    byte[] aad        = "заголовок сообщения".getBytes(StandardCharsets.UTF_8);

    // см. ниже про AAD
    // Шифрование: AAD аутентифицируется, но не шифруется и не включается в пакет
    byte[] packet = MgmCipher.seal(plaintext, key, aad);

    // Расшифрование: AAD должен совпадать с переданным при шифровании
    try {
        byte[] decrypted = MgmCipher.open(packet, key, aad);
    } catch (AuthenticationException e) {
        // Тег не совпал: данные или AAD повреждены / подменены
    } finally {
        key.destroy();
    }

AAD — любые данные (заголовок, метаданные, идентификатор сессии и т.д.),
которые нужно включить в процесс аутентификации вместе с шифртекстом, но
не шифровать и передать в открытом виде.

Cipher — CTR без аутентификации

    import org.rssys.gost.api.Cipher;
    import org.rssys.gost.cipher.SymmetricKey;

    SymmetricKey key = ...; // выработан ранее
    byte[] plaintext  = "данные".getBytes(StandardCharsets.UTF_8);

    // Шифрование: IV (8 байт) генерируется автоматически и включается в начало результата
    // Формат результата: [IV (8 байт)] [шифртекст]
    byte[] encrypted = Cipher.encrypt(plaintext, key, Cipher.Mode.CTR);

    // Расшифрование: IV извлекается автоматически из начала массива
    byte[] decrypted = Cipher.decrypt(encrypted, key, Cipher.Mode.CTR);
    key.destroy();

Режим CTR без аутентификации не защищает от подмены данных. Если
целостность важна — используйте `AuthenticatedCipher` (ГОСТ Р
34.13-2015) или `MgmCipher` (Р 1323565.1.026-2019, рекомендация).

#### JCA (org.rssys.gost.jca)

Kuznyechik/CTR/NoPadding — без аутентификации и контроля целостности
данных.

Строительный блок, который требует понимания в использовании.

    import javax.crypto.Cipher;
    import javax.crypto.spec.IvParameterSpec;
    import org.rssys.gost.jca.key.GostSecretKey;
    GostSecretKey key = ...; // выработан ранее

    byte[] plaintext = "данные".getBytes(StandardCharsets.UTF_8);

    // Шифрование: IV (8 байт) генерируется автоматически
    Cipher cipher = Cipher.getInstance("Kuznyechik/CTR/NoPadding", "RssysGostProvider");
    cipher.init(Cipher.ENCRYPT_MODE, key);
    byte[] ciphertext = cipher.doFinal(plaintext);
    byte[] iv         = cipher.getIV(); // 

    // Расшифрование
    cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
    byte[] decrypted = cipher.doFinal(ciphertext);
    key.destroy();

- IV необходимо передать получателю вместе с `ciphertext`.

Режим CTR без аутентификации не защищает от подмены данных. Если
целостность важна — используйте `AuthenticatedCipher` /
`AuthenticatedStream` из `org.rssys.gost.api` (ГОСТ Р 34.13-2015) или
`Kuznyechik/MGM/NoPadding` (Р 1323565.1.026-2019).

Kuznyechik/MGM/NoPadding — AEAD без AAD

Строительный блок, который требует понимания в использовании.

    import javax.crypto.Cipher;
    import javax.crypto.spec.IvParameterSpec;
    import org.rssys.gost.jca.key.GostSecretKey;

    GostSecretKey key = ...; // выработан ранее
    byte[] plaintext = "открытые данные".getBytes(StandardCharsets.UTF_8);

    // Шифрование: ICN генерируется автоматически
    Cipher cipher = Cipher.getInstance("Kuznyechik/MGM/NoPadding", "RssysGostProvider");
    cipher.init(Cipher.ENCRYPT_MODE, key);
    byte[] ciphertext = cipher.doFinal(plaintext); // [шифртекст][тег (16 байт)]
    byte[] icn        = cipher.getIV();            // 

    // Расшифрование
    cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(icn));
    try {
        byte[] decrypted = cipher.doFinal(ciphertext);
    } catch (javax.crypto.AEADBadTagException e) {
        // Тег не совпал: данные повреждены или подменены
    } finally {
        key.destroy();
    }

- ICN необходимо передать получателю вместе с `ciphertext`. В отличие от
  `MgmCipher.seal`, JCA не включает ICN в выходной буфер автоматически.

Kuznyechik/MGM/NoPadding — AEAD с AAD

    import javax.crypto.Cipher;
    import javax.crypto.spec.IvParameterSpec;
    import org.rssys.gost.jca.key.GostSecretKey;

    GostSecretKey key = ...; // выработан ранее
    byte[] plaintext = "открытые данные".getBytes(StandardCharsets.UTF_8);
    byte[] aad       = "заголовок".getBytes(StandardCharsets.UTF_8);

    // Шифрование
    Cipher cipher = Cipher.getInstance("Kuznyechik/MGM/NoPadding", "RssysGostProvider");
    cipher.init(Cipher.ENCRYPT_MODE, key);
    cipher.updateAAD(aad);                          // 
    byte[] ciphertext = cipher.doFinal(plaintext);
    byte[] icn        = cipher.getIV();

    // Расшифрование
    cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(icn));
    cipher.updateAAD(aad);                          // 
    try {
        byte[] decrypted = cipher.doFinal(ciphertext);
    } catch (javax.crypto.AEADBadTagException e) {
        // Тег не совпал
    } finally {
        key.destroy();
    }

- `updateAAD` должен вызываться до `doFinal`. AAD при шифровании и
  расшифровании должен совпадать.

### Потоковое шифрование (файл / сокет)

#### org.rssys.gost.api

AuthenticatedStream — предназначен для потокового шифрования
сокета/файла с аутентификацией и контролем целостности данных
(рекомендуется для большинства задач).

Можно использовать этот режим для шифрования буфера данных в памяти.

AuthenticatedStream представляет высокоуровневый интерфейс, который
спроектирован так, что закрывает все возможные атаки на использование
режимов шифрования и избавляет от знания нюансов криптографии.

    import org.rssys.gost.api.AuthenticatedStream;
    import org.rssys.gost.cipher.SymmetricKey;
    import org.rssys.gost.util.AuthenticationException;
    import java.io.*;
    import java.nio.file.*;

    SymmetricKey key = ...; // выработан ранее

    // Шифрование файла
    Path src       = Path.of("plaintext.bin");
    Path encrypted = Path.of("encrypted.bin");
    try (InputStream  in  = Files.newInputStream(src);
         OutputStream raw = Files.newOutputStream(encrypted);
         OutputStream out = AuthenticatedStream.sealing(raw, key)) { // 
        in.transferTo(out);
    }

    // Расшифрование файла
    Path decrypted = Path.of("decrypted.bin");
    try (InputStream  raw = Files.newInputStream(encrypted);
         InputStream  in  = AuthenticatedStream.opening(raw, key);  // 
         OutputStream out = Files.newOutputStream(decrypted)) {
        in.transferTo(out);
    } catch (IOException e) {
        if (e.getCause() instanceof AuthenticationException) {
            // CMAC чанка не совпал: файл повреждён или подменён
        }
        throw e;
    } finally {
        key.destroy();
    }

- `sealing` записывает заголовок потока и шифрует данные чанками по 64
  КБ. Каждый чанк содержит собственный IV и CMAC с порядковым номером —
  усечение, перестановка и дублирование чанков обнаруживаются
  автоматически. Максимальный размер чанка — 1 МБ.

- `opening` проверяет CMAC каждого чанка до возврата данных вызывающему.

- Каждый поток выводит два независимых ключа (`cmacKey` для CMAC и
  `ctrKey` для CTR) через KDF\_TREE\_GOSTR3411\_2012\_256 из
  мастер-ключа и случайного streamNonce.

При использовании `AuthenticatedStream` один мастер-ключ можно безопасно
использовать для произвольного числа потоков и объемов данных.
Производные ключи разных потоков вычислительно независимы. Компрометация
одного потока не затрагивает остальные.

Cipher.encryptingStream / decryptingStream — CTR без аутентификации.

Строительный блок, который требует понимания в использовании.

    import org.rssys.gost.api.Cipher;
    import org.rssys.gost.cipher.SymmetricKey;
    import java.io.*;
    import java.nio.file.*;

    SymmetricKey key = ...; // выработан ранее

    // Шифрование: IV (8 байт) записывается в поток автоматически первым
    Path src       = Path.of("plaintext.bin");
    Path encrypted = Path.of("encrypted.bin");
    try (InputStream  in  = Files.newInputStream(src);
         OutputStream raw = Files.newOutputStream(encrypted);
         OutputStream out = Cipher.encryptingStream(raw, key, Cipher.Mode.CTR)) {
        in.transferTo(out);
    }

    // Расшифрование: IV читается из потока автоматически
    Path decrypted = Path.of("decrypted.bin");
    try (InputStream  raw = Files.newInputStream(encrypted);
         InputStream  in  = Cipher.decryptingStream(raw, key, Cipher.Mode.CTR);
         OutputStream out = Files.newOutputStream(decrypted)) {
        in.transferTo(out);
    } finally {
        key.destroy();
    }

CTR без аутентификации не обнаруживает повреждение или подмену данных.
Для потоков с требованием целостности используйте `AuthenticatedStream`.

#### JCA (org.rssys.gost.jca)

CipherOutputStream / CipherInputStream — CTR без аутентификации и
контроля целостности данных.

CipherOutputStream / CipherInputStream это строительные блоки, которые
требуют понимания в использовании.

    import javax.crypto.Cipher;
    import javax.crypto.CipherInputStream;
    import javax.crypto.CipherOutputStream;
    import javax.crypto.spec.IvParameterSpec;
    import org.rssys.gost.jca.key.GostSecretKey;
    import java.io.*;
    import java.nio.file.*;

    GostSecretKey key = ...; // выработан ранее
    Cipher cipher = Cipher.getInstance("Kuznyechik/CTR/NoPadding", "RssysGostProvider");

    // Шифрование: IV генерируется автоматически, записываем его явно перед шифртекстом
    Path src       = Path.of("plaintext.bin");
    Path encrypted = Path.of("encrypted.bin");
    cipher.init(Cipher.ENCRYPT_MODE, key);
    byte[] iv = cipher.getIV(); // 
    try (InputStream        in  = Files.newInputStream(src);
         OutputStream       raw = Files.newOutputStream(encrypted)) {
        raw.write(iv);                               // 
        try (OutputStream out = new CipherOutputStream(raw, cipher)) {
            in.transferTo(out);
        }
    }

    // Расшифрование: читаем IV явно из начала потока
    Path decrypted = Path.of("decrypted.bin");
    try (InputStream  raw = Files.newInputStream(encrypted)) {
        byte[] ivRead = raw.readNBytes(iv.length);   // 
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ivRead));
        try (InputStream  in  = new CipherInputStream(raw, cipher);
             OutputStream out = Files.newOutputStream(decrypted)) {
            in.transferTo(out);
        }
    } finally {
        key.destroy();
    }

- JCA не управляет IV автоматически в потоковом API — приложение
  отвечает за запись и чтение IV из потока.

Для потоков с аутентификацией целостности используйте
`AuthenticatedStream` из `org.rssys.gost.api`.

## Режимы CTR-ACPKM и CTR-ACPKM-OMAC (RFC 8645, RFC 9337 §5)

**Данные режимы являются строительными блоками и требуется понимание их
использования.**

Оба режима доступны только через JCA-интерфейс (`Cipher.getInstance`). В
`api.Cipher.Mode` эти режимы не представлены.

### Когда использовать какой режим

<table style="width:100%;">
<colgroup>
<col style="width: 14%" />
<col style="width: 28%" />
<col style="width: 28%" />
<col style="width: 14%" />
<col style="width: 14%" />
</colgroup>
<thead>
<tr>
<th style="text-align: left;">Режим</th>
<th style="text-align: left;">Когда использовать</th>
<th style="text-align: left;">Аутентификация</th>
<th style="text-align: left;">Потоковый update</th>
<th style="text-align: left;">Буферизует всё</th>
</tr>
</thead>
<tbody>
<tr>
<td style="text-align: left;"><p><code>CTR-ACPKM</code></p></td>
<td style="text-align: left;"><p>Потоковое шифрование, большие файлы.
Аутентификация — отдельно.</p></td>
<td style="text-align: left;"><p>Нет</p></td>
<td style="text-align: left;"><p>✓ — да</p></td>
<td style="text-align: left;"><p>❌ — нет</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>CTR-ACPKM-OMAC</code></p></td>
<td style="text-align: left;"><p>Файлы с аутентификацией
(Encrypt-then-MAC). Данные помещаются в память.</p></td>
<td style="text-align: left;"><p>Да (OMAC-тег)</p></td>
<td style="text-align: left;"><p>❌ — нет</p></td>
<td style="text-align: left;"><p>✓ — да</p></td>
</tr>
</tbody>
</table>

Практическое следствие из таблицы:

- **Только `CTR-ACPKM`** (без OMAC) подходит для потокового шифрования
  через `CipherOutputStream` / `update` — данные шифруются порциями без
  буферизации.

- **`CTR-ACPKM-OMAC` и `MGM`** буферизуют весь plaintext в памяти до
  вызова `doFinal`. Используйте их только когда данные помещаются в
  память целиком.

`engineUpdate` буферизует все данные — реальное шифрование происходит
только в `doFinal`. Не используйте этот режим через `CipherOutputStream`
для больших файлов.

### Ключевые понятия

**UKM (User Keying Material)** — нонс, аналог IV. Его нельзя повторять с
тем же ключом — повтор UKM полностью компрометирует шифрование.

- `CTR-ACPKM`: UKM ≥ 8 байт (первые 8 байт используются как IV счётчика)

- `CTR-ACPKM-OMAC`: UKM = ровно 16 байт (используется в KDF\_TREE для
  вывода пары ключей: ключа шифрования и ключа OMAC)

**UKM при расшифровании** необходимо передавать явно через
`IvParameterSpec` — он должен совпадать с тем что был при шифровании.
После шифрования UKM можно получить через `cipher.getIV()`.

### CTR-ACPKM — потоковое шифрование

Строительный блок, который требует понимания в использовании.

`engineUpdate` шифрует данные немедленно — подходит для
`CipherOutputStream` и обработки данных порциями без буферизации.

Шифрование (UKM генерируется автоматически)

    import javax.crypto.Cipher;
    import javax.crypto.spec.IvParameterSpec;

    SecretKey key = ...; // 32-байтный ключ Кузнечика
    Cipher cipher = Cipher.getInstance("Kuznyechik/CTR-ACPKM/NoPadding", "RssysGostProvider");

    // UKM генерируется автоматически при отсутствии IvParameterSpec
    cipher.init(Cipher.ENCRYPT_MODE, key);
    byte[] ukm = cipher.getIV(); // 

    byte[] plaintext  = ...;
    byte[] ciphertext = cipher.doFinal(plaintext);

    // ukm и ciphertext передать получателю вместе

- UKM (≥ 8 байт) генерируется автоматически из `CryptoRandom`. Сохраните
  его — без него расшифрование невозможно. Передавайте открыто рядом с
  шифртекстом.

Шифрование с явным UKM

Строительный блок, который требует понимания в использовании.

    import org.rssys.gost.util.CryptoRandom;

    byte[] ukm = new byte[8];
    CryptoRandom.INSTANCE.nextBytes(ukm); // каждый раз новый UKM

    Cipher cipher = Cipher.getInstance("Kuznyechik/CTR-ACPKM/NoPadding", "RssysGostProvider");
    cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ukm));
    byte[] ciphertext = cipher.doFinal(plaintext);

Расшифрование

    byte[] ukm        = ...; // тот же UKM что при шифровании
    byte[] ciphertext = ...;

    Cipher cipher = Cipher.getInstance("Kuznyechik/CTR-ACPKM/NoPadding", "RssysGostProvider");
    cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ukm)); // 
    byte[] plaintext = cipher.doFinal(ciphertext);

- При расшифровании `IvParameterSpec` обязателен.

Потоковое шифрование больших файлов через CipherOutputStream.
Строительный блок, который требует понимания в использовании.

    import java.io.InputStream;
    import java.io.OutputStream;
    import javax.crypto.CipherOutputStream;
    import org.rssys.gost.util.CryptoRandom;

    byte[] ukm = new byte[8];
    CryptoRandom.INSTANCE.nextBytes(ukm);

    Cipher cipher = Cipher.getInstance("Kuznyechik/CTR-ACPKM/NoPadding", "RssysGostProvider");
    cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ukm));

    OutputStream out = ...;
    out.write(ukm); // 

    try (CipherOutputStream cos = new CipherOutputStream(out, cipher);
         InputStream in = ...) {
        byte[] buf = new byte[65536];
        int n;
        while ((n = in.read(buf)) != -1) {
            cos.write(buf, 0, n); // шифруется и пишется немедленно, без буферизации
        }
    } // 

- UKM записывается в начало потока открытым текстом — при расшифровании
  читается первым.

- `CipherOutputStream.close()` вызывает `doFinal` — для `CTR-ACPKM` без
  OMAC это no-op (нет тега), все данные уже записаны через `update`.

### CTR-ACPKM-OMAC — шифрование с аутентификацией (данные в памяти)

Строительный блок, который требует понимания в использовании.

Использует `KdfTreeGostR3411_2012_256` для вывода пары ключей из UKM:
ключа шифрования и ключа OMAC. 16-байтный тег добавляется в конец
шифртекста.

`engineUpdate` буферизует все данные — реальное шифрование происходит
только в `doFinal`. Не используйте этот режим через `CipherOutputStream`
для больших файлов.

Шифрование

    import org.rssys.gost.util.CryptoRandom;

    byte[] ukm = new byte[16]; // 
    CryptoRandom.INSTANCE.nextBytes(ukm);

    Cipher cipher = Cipher.getInstance("Kuznyechik/CTR-ACPKM-OMAC/NoPadding", "RssysGostProvider");
    cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ukm));

    byte[] plaintext  = ...;
    byte[] ciphertext = cipher.doFinal(plaintext); // 

- UKM для CTR-ACPKM-OMAC — ровно 16 байт.

- Длина `ciphertext` = `plaintext.length + 16` (тег в конце).

Расшифрование

    import javax.crypto.AEADBadTagException;

    byte[] ukm        = ...; // 16 байт, тот же что при шифровании
    byte[] ciphertext = ...;

    Cipher cipher = Cipher.getInstance("Kuznyechik/CTR-ACPKM-OMAC/NoPadding", "RssysGostProvider");
    cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ukm));

    try {
        byte[] plaintext = cipher.doFinal(ciphertext); // проверяет тег
    } catch (AEADBadTagException e) {
        // данные повреждены или ключ/UKM неверны
        throw new SecurityException("Аутентификация не прошла", e);
    }

Алиасы для работы с OID из ASN.1:  
`1.2.643.7.1.1.5.2.1` → `Kuznyechik/CTR-ACPKM/NoPadding`  
`1.2.643.7.1.1.5.2.2` → `Kuznyechik/CTR-ACPKM-OMAC/NoPadding`

## Хэш-функция Стрибог (ГОСТ Р 34.11-2012)

Стрибог — криптографическая хэш-функция в двух вариантах: 256 бит и 512
бит.

Библиотека предоставляет два независимы API по вызову хеш-функций:

- `org.rssys.gost.api` — прямой API, не требует регистрации провайдера.

- `org.rssys.gost.jca` — JCA/JCE-совместимый API.

Результат хеширования - big-endian (MSB first) массив байт, совместимый
с OpenSSL. RFC 6986 приводит тест-векторы в ГОСТ-нотации (right-to-left)
— байты будут в обратном порядке при прямом сравнении.

### org.rssys.gost.api

Блочный режим хеширования данных. Хешируемые данные целиком в памяти.

    import org.rssys.gost.api.Digest;

    byte[] data = "данные".getBytes(StandardCharsets.UTF_8);

    // Стрибог-256 (ГОСТ Р 34.11-2012), вывод 32 байта
    byte[] hash256 = Digest.digest256(data);

    // Стрибог-512 (ГОСТ Р 34.11-2012), вывод 64 байта
    byte[] hash512 = Digest.digest512(data);

Инкрементальный режим хеширования. Данные из файла или сокета
обрабатываются в потоковом режиме, без накопления в памяти.

    import org.rssys.gost.api.Digest;
    import java.io.InputStream;
    import java.nio.file.Files;
    import java.nio.file.Path;

    // Стрибог-256
    Digest h256 = new Digest(Digest.Algorithm.STREEBOG_256);
    byte[] buf = new byte[8192];
    int n;
    try (InputStream in = Files.newInputStream(Path.of("data.bin"))) {
        while ((n = in.read(buf)) != -1) {
            h256.update(buf, 0, n);
        }
    }
    byte[] hash256 = h256.digest();

    // Стрибог-512
    Digest h512 = new Digest(Digest.Algorithm.STREEBOG_512);
    try (InputStream in = Files.newInputStream(Path.of("data.bin"))) {
        while ((n = in.read(buf)) != -1) {
            h512.update(buf, 0, n);
        }
    }
    byte[] hash512 = h512.digest();

Экземпляр `Digest` не является потокобезопасным. Создавайте отдельный
экземпляр на каждый поток.

### JCA (org.rssys.gost.jca)

Блочный режим хеширования данных. Хешируемые данные целиком в памяти.

    import java.security.MessageDigest;

    // Стрибог-256
    MessageDigest md256 = MessageDigest.getInstance("GOST3411-2012-256", "RssysGostProvider"); // 
    byte[] hash256 = md256.digest(data);

    // Стрибог-512
    MessageDigest md512 = MessageDigest.getInstance("GOST3411-2012-512", "RssysGostProvider");
    byte[] hash512 = md512.digest(data);

- Алиасы: `"Streebog-256"`, `"1.2.643.7.1.1.2.2"` для 256-бит;
  `"Streebog-512"`, `"1.2.643.7.1.1.2.3"` для 512-бит.

Инкрементальный режим хеширования. Данные из файла или сокета
обрабатываются в потоковом режиме, без накопления в памяти.

    import java.security.MessageDigest;
    import java.io.InputStream;
    import java.nio.file.Files;
    import java.nio.file.Path;

    MessageDigest md256 = MessageDigest.getInstance("GOST3411-2012-256", "RssysGostProvider");
    byte[] buf = new byte[8192];
    int n;
    try (InputStream in = Files.newInputStream(Path.of("data.bin"))) {
        while ((n = in.read(buf)) != -1) {
            md256.update(buf, 0, n);
        }
    }
    byte[] hash256 = md256.digest();

## HMAC-Streebog (RFC 7836)

HMAC — код аутентификации сообщений на основе хэш-функции "Стрибог".  
Данная функция требует симметричный ключ.  
В библиотеке представлено два варианта функции: HMAC-Streebog-256 (32
байта) и HMAC-Streebog-512 (64 байта).

### org.rssys.gost.api

Блочный режим вычисления HMAC. Защищаемые данные целиком в памяти.

    import org.rssys.gost.api.Digest;
    import org.rssys.gost.api.CmacApi;
    import org.rssys.gost.cipher.SymmetricKey;

    SymmetricKey key = ...; // выработан ранее
    byte[] data = "данные".getBytes(StandardCharsets.UTF_8);

    // HMAC-Streebog-256
    byte[] mac256 = Digest.hmac256(data, key);

    // HMAC-Streebog-256
    byte[] mac512 = Digest.hmac512(data, key);

    // Проверка целостности — constant-time сравнение (защита от timing-атак)
    boolean ok = CmacApi.verifyMac(expected, mac256);

Инкрементальный режим вычисления HMAC. Данные из файла или сокета
обрабатываются в потоковом режиме, без накопления в памяти.

    import org.rssys.gost.api.Digest;
    import org.rssys.gost.api.CmacApi;
    import org.rssys.gost.cipher.SymmetricKey;
    import java.io.InputStream;
    import java.nio.file.Files;
    import java.nio.file.Path;

    SymmetricKey key = ...; // выработан ранее

    // HMAC-Streebog-256
    Digest m256 = new Digest(Digest.Algorithm.HMAC_256, key);
    byte[] buf = new byte[8192];
    int n;
    try (InputStream in = Files.newInputStream(Path.of("data.bin"))) {
        while ((n = in.read(buf)) != -1) {
            m256.update(buf, 0, n);
        }
    }
    byte[] mac256 = m256.digest();

    // HMAC-Streebog-512
    Digest m512 = new Digest(Digest.Algorithm.HMAC_512, key);
    try (InputStream in = Files.newInputStream(Path.of("data.bin"))) {
        while ((n = in.read(buf)) != -1) {
            m512.update(buf, 0, n);
        }
    }
    byte[] mac512 = m512.digest();

    // Проверка целостности
    boolean ok = CmacApi.verifyMac(expected, mac256);

    key.destroy();

Экземпляр `Digest` не является потокобезопасным. Создавайте отдельный
экземпляр на каждый поток.

### JCA (org.rssys.gost.jca)

Блочный режим вычисления HMAC. Защищаемые данные целиком в памяти.

    import javax.crypto.Mac;
    import org.rssys.gost.jca.key.GostSecretKey;

    GostSecretKey key = ...; // выработан ранее
    byte[] data = "данные".getBytes(StandardCharsets.UTF_8);

    // HMAC-Streebog-256
    Mac mac256 = Mac.getInstance("HmacGOST3411-2012-256", "RssysGostProvider"); // 
    mac256.init(key);
    byte[] result256 = mac256.doFinal(data);

    // HMAC-Streebog-512
    Mac mac512 = Mac.getInstance("HmacGOST3411-2012-512", "RssysGostProvider");
    mac512.init(key);
    byte[] result512 = mac512.doFinal(data);

    key.destroy();

- Алиасы: `"HMAC-Streebog-256"`, `"1.2.643.7.1.1.4.1"` для 256-бит;
  `"HMAC-Streebog-512"`, `"1.2.643.7.1.1.4.2"` для 512-бит.

Инкрементальный режим вычисления HMAC. Данные из файла или сокета
обрабатываются в потоковом режиме, без накопления в памяти.

    import javax.crypto.Mac;
    import org.rssys.gost.jca.key.GostSecretKey;
    import java.io.InputStream;
    import java.nio.file.Files;
    import java.nio.file.Path;

    GostSecretKey key = ...; // выработан ранее

    Mac mac256 = Mac.getInstance("HmacGOST3411-2012-256", "RssysGostProvider");
    mac256.init(key);
    byte[] buf = new byte[8192];
    int n;
    try (InputStream in = Files.newInputStream(Path.of("data.bin"))) {
        while ((n = in.read(buf)) != -1) {
            mac256.update(buf, 0, n);
        }
    }
    byte[] result256 = mac256.doFinal();

    key.destroy();

## CMAC-Кузнечик (ГОСТ Р 34.13-2015)

CMAC — имитовставка на основе блочного шифра Кузнечик. Для вычисления
необходим симметричный ключ.  

Полный тег: 16 байт (128 бит = размер блока). Допускается усечение тега.

CMAC строится на блочном шифре (Кузнечик). HMAC строится на хэш-функции
(Стрибог). **Это разные алгоритмы с разной областью применения.**

### org.rssys.gost.api

Блочный режим вычисления CMAC. Защищаемые данные целиком в памяти.

    import org.rssys.gost.api.CmacApi;
    import org.rssys.gost.cipher.SymmetricKey;

    SymmetricKey key = ...; // выработан ранее
    byte[] data = "данные".getBytes(StandardCharsets.UTF_8);

    // Полный тег CMAC, 16 байт
    byte[] tag = CmacApi.cmac(data, key);

    // Усечённый тег, 8 байт (первые 8 байт полного тега)
    byte[] tag8 = CmacApi.cmac(data, key, 8);

    // Проверка целостности — constant-time сравнение (защита от timing-атак)
    boolean ok = CmacApi.verifyMac(expected, tag);

    key.destroy();

Инкрементальный режим режим вычисления CMAC. Данные из файла или сокета
обрабатываются в потоковом режиме, без накопления в памяти.

    import org.rssys.gost.api.CmacApi;
    import org.rssys.gost.cipher.SymmetricKey;
    import java.io.InputStream;
    import java.nio.file.Files;
    import java.nio.file.Path;

    SymmetricKey key = ...; // выработан ранее

    CmacApi cmac = new CmacApi(key);
    byte[] buf = new byte[8192];
    int n;
    try (InputStream in = Files.newInputStream(Path.of("data.bin"))) {
        while ((n = in.read(buf)) != -1) {
            cmac.update(buf, 0, n);
        }
    }
    byte[] tag = cmac.digest(); // 16 байт

    // Проверка целостности
    boolean ok = CmacApi.verifyMac(expected, tag);

    key.destroy();

Экземпляр `CmacApi` не является потокобезопасным. Создавайте отдельный
экземпляр на каждый поток.

### JCA (org.rssys.gost.jca)

Блочный режим вычисления CMAC. Данные целиком находятся в памяти.

    import javax.crypto.Mac;
    import org.rssys.gost.jca.key.GostSecretKey;

    GostSecretKey key = ...; // выработан ранее
    byte[] data = "данные".getBytes(StandardCharsets.UTF_8);

    Mac mac = Mac.getInstance("CMAC-Kuznyechik", "RssysGostProvider");
    mac.init(key);
    byte[] tag = mac.doFinal(data);

    key.destroy();

Инкрементальный режим вычисления CMAC. Данные из файла или сокета
обрабатываются в потоковом режиме, без накопления в памяти.

    import javax.crypto.Mac;
    import org.rssys.gost.jca.key.GostSecretKey;
    import java.io.InputStream;
    import java.nio.file.Files;
    import java.nio.file.Path;

    GostSecretKey key = ...; // выработан ранее

    Mac mac = Mac.getInstance("CMAC-Kuznyechik", "RssysGostProvider");
    mac.init(key);
    byte[] buf = new byte[8192];
    int n;
    try (InputStream in = Files.newInputStream(Path.of("data.bin"))) {
        while ((n = in.read(buf)) != -1) {
            mac.update(buf, 0, n);
        }
    }
    byte[] tag = mac.doFinal();

    key.destroy();

## Электронная подпись ГОСТ Р 34.10-2012

Электронная подпись — алгоритм ГОСТ Р 34.10-2012 (RFC 7091).

- в методах **sign/veify** хэш для переданных данных выбирается и
  вычисляется автоматически по параметрам кривой: Streebog-256 для
  256-битных кривых, Streebog-512 для 512-битных.

- Нонс k генерируется детерминированно по RFC 6979 §3.2 (HMAC-Стрибог) —
  одно сообщение + один ключ всегда дают одну подпись.

- Формат подписи: `s ∥ r` big-endian, без DER/ASN.1. Длина: 64 байта
  (256-бит кривые) или 128 байт (512-бит кривые).

Библиотека предоставляет два независимых API для вычисления электронной
подписи:

- `org.rssys.gost.api` — прямой API, не требует регистрации провайдера.

- `org.rssys.gost.jca` — JCA/JCE-совместимый API.

### org.rssys.gost.api

Подпись и проверка подписи для "сырых" данных.

**В данном режиме, хеш вычисляется автоматически, внутри методов
sign/verify.**

    import org.rssys.gost.api.KeyGenerator;
    import org.rssys.gost.api.KeyPair;
    import org.rssys.gost.api.Signature;
    import org.rssys.gost.signature.ECParameters;

    byte[] data = "сообщение для подписи".getBytes(StandardCharsets.UTF_8);

    // Генерация ключевой пары — кривая CryptoPro-A (256 бит)
    KeyPair pair = KeyGenerator.generateKeyPair(ECParameters.cryptoProA());

    try {
        // Подпись: хеш Стрибог-256 вычисляется автоматически для данных data, базируясь на параметрах кривой. То есть отдельно хэш вычислять не нужно.
        // Формат: s ∥ r big-endian, длина 64 байта
        byte[] signature = Signature.sign(data, pair.getPrivate());
        // Проверка подписи. Хэш для data вычисляется внути автоматически.
        boolean valid = Signature.verify(data, signature, pair.getPublic());
        // valid => true
        // Подмена данных обнаруживается
        byte[] tampered = data.clone();
        tampered[0] ^= 0x01;
        boolean invalid = Signature.verify(tampered, signature, pair.getPublic());
        // invalid => false
    } finally {
        pair.getPrivate().destroy(); // обнуляет d в памяти
    }

Импорт закрытого ключа из byte\[\] и подпись

    import org.rssys.gost.api.Signature;
    import org.rssys.gost.signature.ECParameters;
    import org.rssys.gost.signature.PrivateKeyParameters;
    import java.math.BigInteger;

    byte[] dBytes = ...; // 32 байта закрытого ключа, big-endian
    ECParameters params = ECParameters.cryptoProA();
    PrivateKeyParameters priv = new PrivateKeyParameters(new BigInteger(1, dBytes), params);

    try {
        byte[] signature = Signature.sign(data, priv); // хеш нужной битности вычисляется автоматически
        // ...
    } finally {
        priv.destroy();
        java.util.Arrays.fill(dBytes, (byte) 0); // очистить исходный массив
    }

Импорт открытого ключа из координат и верификация

    import org.rssys.gost.api.Signature;
    import org.rssys.gost.signature.ECParameters;
    import org.rssys.gost.signature.ECPoint;
    import org.rssys.gost.signature.PublicKeyParameters;
    import java.math.BigInteger;

    byte[] qxBytes = ...; // 32 байта координаты Qx, big-endian
    byte[] qyBytes = ...; // 32 байта координаты Qy, big-endian
    ECParameters params = ECParameters.cryptoProA();
    ECPoint q = ECPoint.affine(new BigInteger(1, qxBytes), new BigInteger(1, qyBytes), params);
    PublicKeyParameters pub = new PublicKeyParameters(q, params);

    boolean valid = Signature.verify(data, signature, pub);

Получение открытого ключа из закрытого: Q = d·G

    import org.rssys.gost.api.Signature;
    import org.rssys.gost.signature.PrivateKeyParameters;
    import org.rssys.gost.signature.PublicKeyParameters;

    PrivateKeyParameters priv = ...; // загружен ранее

    try {
        // Вычисляет Q = d·G — скалярное умножение базовой точки
        PublicKeyParameters pub = Signature.derivePublicKey(priv);
        // Полученный ключ можно использовать для верификации
        boolean valid = Signature.verify(data, signature, pub);
    } finally {
        priv.destroy();
    }

### Подпись готового хэша (signHash / verifyHash)

Данные методы используются, когда хэш вычислен отдельно.

Хэш должен соответствовать кривой: Стрибог-256 (32 байта) для 256-битных
кривых, Стрибог-512 (64 байта) для 512-битных. Передача хэша другого
алгоритма (SHA-256, MD5 и т.п.) нарушает требования ГОСТ Р 34.10-2012.

Нонс k генерируется детерминированно по RFC 6979 — идентично
`Signature.sign`.

#### org.rssys.gost.api

Подпись готового хэша

    import org.rssys.gost.api.Digest;
    import org.rssys.gost.api.KeyGenerator;
    import org.rssys.gost.api.KeyPair;
    import org.rssys.gost.api.Signature;
    import org.rssys.gost.signature.ECParameters;
    byte[] data = "сообщение".getBytes(StandardCharsets.UTF_8);
    KeyPair pair = KeyGenerator.generateKeyPair(ECParameters.cryptoProA());
    try {
        // Хэш вычислен заранее
        byte[] hash = Digest.digest256(data); // 32 байта для 256-битной кривой
        // Подпись готового хэша
        byte[] signature = Signature.signHash(hash, pair.getPrivate()); // 64 байта
        // Проверка подписи для хэша
        boolean valid = Signature.verifyHash(hash, signature, pair.getPublic());
        // valid => true
    } finally {
        pair.getPrivate().destroy();
    }

Кросс-совместимость sign ↔ signHash

    import org.rssys.gost.api.Digest;
    import org.rssys.gost.api.Signature;
    KeyPair pair = KeyGenerator.generateKeyPair(ECParameters.cryptoProA());
    try {
        byte[] hash = Digest.digest256(data);
        // sign и signHash дают одинаковый результат для тех же данных
        byte[] sig1 = Signature.sign(data, pair.getPrivate());     // хэш внутри
        byte[] sig2 = Signature.signHash(hash, pair.getPrivate()); // хэш снаружи
        // sig1 и sig2 идентичны побайтово — детерминированность RFC 6979
        Arrays.equals(sig1, sig2) // => true
        // verify и verifyHash взаимозаменяемы
        boolean ok1 = Signature.verify(data, sig2, pair.getPublic());      // 
        boolean ok2 = Signature.verifyHash(hash, sig1, pair.getPublic()); // 
        // ok1 == ok2 == true
    } finally {
        pair.getPrivate().destroy();
    }

- `verify(data, sig)` и `verifyHash(hash, sig)` принимают подписи,
  созданные как через `sign`, так и через `signHash`.

### JCA (org.rssys.gost.jca)

Генерация ключевой пары, подпись и верификация

    import java.security.KeyPair;
    import java.security.KeyPairGenerator;
    import java.security.Signature;
    import java.security.spec.ECGenParameterSpec;

    byte[] data = "сообщение для подписи".getBytes(StandardCharsets.UTF_8);

    // Генерация ключевой пары — кривая tc26-gost-A-256 (256 бит)
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECGOST3410-2012", "RssysGostProvider");
    kpg.initialize(new ECGenParameterSpec("tc26-gost-A-256")); // 

    KeyPair pair = kpg.generateKeyPair();

    try {
        // Подпись — хеш Стрибог-256 вычисляется автоматически базируясь на параметрах кривой
        Signature signer = Signature.getInstance("ECGOST3410-2012-256", "RssysGostProvider"); // 
        signer.initSign(pair.getPrivate());
        signer.update(data);
        byte[] signature = signer.sign(); // 64 байта

        // Верификация
        Signature verifier = Signature.getInstance("ECGOST3410-2012-256", "RssysGostProvider");
        verifier.initVerify(pair.getPublic());
        verifier.update(data);
        boolean valid = verifier.verify(signature);
        // valid => true
    } finally {
        pair.getPrivate().destroy();
    }

- Поддерживаемые имена кривых: `"cryptopro-A"`, `"cryptopro-B"`,
  `"cryptopro-C"`, `"tc26-gost-A-256"` (256 бит); `"tc26-gost-A-512"`,
  `"tc26-gost-B-512"`, `"tc26-gost-C-512"` (512 бит).  
  Инициализация по размеру: `kpg.initialize(256)` → `cryptopro-A`,
  `kpg.initialize(512)` → `tc26-gost-A-512`.

- Для 512-битных кривых используйте `"ECGOST3410-2012-512"`.

Алиасы: OID `"1.2.643.7.1.1.3.2"` (256 бит), `"1.2.643.7.1.1.3.3"` (512
бит).

Импорт закрытого ключа из PKCS#8 DER и подпись

    import java.security.KeyFactory;
    import java.security.PrivateKey;
    import java.security.Signature;
    import java.security.spec.PKCS8EncodedKeySpec;

    byte[] pkcs8Der = ...; // DER-кодирование в формате PKCS#8 PrivateKeyInfo
    KeyFactory kf = KeyFactory.getInstance("ECGOST3410-2012", "RssysGostProvider");

    PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8Der));

    try {
        Signature signer = Signature.getInstance("ECGOST3410-2012-256", "RssysGostProvider");
        signer.initSign(priv);
        signer.update(data);
        byte[] signature = signer.sign();
        // ...
    } finally {
        priv.destroy();
    }

Импорт открытого ключа из X.509 DER и верификация

    import java.security.KeyFactory;
    import java.security.PublicKey;
    import java.security.Signature;
    import java.security.spec.X509EncodedKeySpec;

    byte[] x509Der = ...; // DER-кодирование в формате X.509 SubjectPublicKeyInfo
    KeyFactory kf = KeyFactory.getInstance("ECGOST3410-2012", "RssysGostProvider");
    PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(x509Der));
    Signature verifier = Signature.getInstance("ECGOST3410-2012-256", "RssysGostProvider");
    verifier.initVerify(pub);
    verifier.update(data);

    boolean valid = verifier.verify(signature);

Экспорт ключей в DER для хранения или передачи

    import org.rssys.gost.jca.key.GostECPrivateKey;
    import org.rssys.gost.jca.key.GostECPublicKey;

    // Экспорт открытого ключа — X.509 SubjectPublicKeyInfo DER
    byte[] pubDer = pair.getPublic().getEncoded(); // 

    // Экспорт закрытого ключа — PKCS#8 PrivateKeyInfo DER
    // ВНИМАНИЕ: хранить только в зашифрованном виде
    byte[] privDer = pair.getPrivate().getEncoded(); // 
    try {
        // сохранить privDer ...
    } finally {
        java.util.Arrays.fill(privDer, (byte) 0); // очистить после использования
        pair.getPrivate().destroy();
    }

- `getEncoded()` возвращает `null` если ключ уничтожен (`destroy()` был
  вызван).

### Поддерживаемые кривые

<table style="width:100%;">
<colgroup>
<col style="width: 33%" />
<col style="width: 33%" />
<col style="width: 16%" />
<col style="width: 16%" />
</colgroup>
<thead>
<tr>
<th style="text-align: left;">Имя кривой</th>
<th style="text-align: left;">Стандарт</th>
<th style="text-align: left;">Бит</th>
<th style="text-align: left;">Хэш подписи</th>
</tr>
</thead>
<tbody>
<tr>
<td style="text-align: left;"><p><code>cryptopro-A</code></p></td>
<td style="text-align: left;"><p>RFC 4357 §11.2</p></td>
<td style="text-align: left;"><p>256</p></td>
<td style="text-align: left;"><p>Стрибог-256</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>cryptopro-B</code></p></td>
<td style="text-align: left;"><p>RFC 4357 §11.3</p></td>
<td style="text-align: left;"><p>256</p></td>
<td style="text-align: left;"><p>Стрибог-256</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>cryptopro-C</code></p></td>
<td style="text-align: left;"><p>RFC 4357 §11.4</p></td>
<td style="text-align: left;"><p>256</p></td>
<td style="text-align: left;"><p>Стрибог-256</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>tc26-gost-A-256</code></p></td>
<td style="text-align: left;"><p>RFC 7836, Appendix A.2</p></td>
<td style="text-align: left;"><p>256</p></td>
<td style="text-align: left;"><p>Стрибог-256</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>tc26-gost-A-512</code></p></td>
<td style="text-align: left;"><p>RFC 7836, Appendix A.1</p></td>
<td style="text-align: left;"><p>512</p></td>
<td style="text-align: left;"><p>Стрибог-512</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>tc26-gost-B-512</code></p></td>
<td style="text-align: left;"><p>RFC 7836</p></td>
<td style="text-align: left;"><p>512</p></td>
<td style="text-align: left;"><p>Стрибог-512</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>tc26-gost-C-512</code></p></td>
<td style="text-align: left;"><p>RFC 7836</p></td>
<td style="text-align: left;"><p>512</p></td>
<td style="text-align: left;"><p>Стрибог-512</p></td>
</tr>
</tbody>
</table>

### Что даёт RFC 6979

Детерминированный k через HMAC-DRBG (HMAC-Стрибог) решает проблему
плохого ГСЧ радикально: k = HMAC-DRBG(закрытый ключ, хеш сообщения).

Свойства:

- Два разных сообщения → два разных k (хеши разные → DRBG даёт разный
  вывод).

- Одно сообщение подписывается всегда одним k → никакой вариативности
  нет.

- `k` не предсказуем без знания закрытого ключа (HMAC — псевдослучайная
  функция).

- Не зависит от качества системного ГСЧ.

## Согласование ключей и выработка сессионных ключей

**VKO** (Выработка Ключевого Объекта) — алгоритм, с помощью которого две
стороны независимо вычисляют одинаковый секретный ключ, зная свой
закрытый ключ и открытый ключ партнёра. Секрет никогда не передаётся по
каналу — каждая сторона получает его самостоятельно.

**UKM** (случайное число сессии) гарантирует, что для каждого сеанса
вырабатывается новый уникальный секрет, даже если долгосрочные ключи
сторон не менялись.

**KDF** (функция выработки ключей, Key Derivation Function) — алгоритм,
который превращает один секрет в несколько независимых ключей нужной
длины. На вход подаётся секрет (например, результат VKO) и контекст
(метка, затравка). На выходе — готовые к использованию ключи: отдельно
для шифрования, отдельно для проверки целостности.  
Даже если один из выходных ключей скомпрометирован, остальные и исходный
секрет остаются в безопасности.

### VKO + KDF — рекомендуемая схема для прикладного использования

Для большинства задач (защищённый обмен данными, CMS, IKEv2) используйте
связку VKO → KDF: VKO вырабатывает общий секрет с учётом случайного UKM,
KDF разворачивает его в готовые сессионные ключи.

Обе стороны независимо вычисляют **одинаковые** ключи, не передавая
секрет по каналу. UKM (случайное число) гарантирует уникальность ключей
каждой сессии — даже если статические ключи сторон не меняются.

VKO + KDF вырабатывают сессионные ключи — то есть ключи, которые обе
стороны вычисляют независимо и сразу используют для шифрования трафика.
Это работает когда обе стороны онлайн одновременно и договариваются о
ключах в реальном времени.

    import org.rssys.gost.api.KeyAgreement;
    import org.rssys.gost.api.KeyGenerator;
    import org.rssys.gost.api.KeyPair;
    import org.rssys.gost.kdf.KdfTreeGostR3411_2012_256;
    import org.rssys.gost.signature.ECParameters;
    import org.rssys.gost.jca.spec.GostUkmParameterSpec;
    import java.math.BigInteger;
    import org.rssys.gost.util.CryptoRandom;
    import java.util.Arrays;

    ECParameters params = ECParameters.cryptoProA();

    KeyPair alice = KeyGenerator.generateKeyPair(params);
    KeyPair bob   = KeyGenerator.generateKeyPair(params);

    // UKM — случайное число, минимум 8 байт; генерируется инициатором сессии
    // и передаётся партнёру открыто (например, в заголовке сообщения)
    byte[] ukmBytes = new byte[8];
    CryptoRandom.INSTANCE.nextBytes(ukmBytes);
    BigInteger ukm = new BigInteger(1, ukmBytes);

    byte[] keys = null;
    try {
        // Алиса вычисляет KEK с ключами Боба
        byte[] kekAlice = KeyAgreement.vkoGostR3410_2012_256(
                alice.getPrivate(), bob.getPublic(), ukm);

        // Боб вычисляет тот же KEK с ключами Алисы
        byte[] kekBob = KeyAgreement.vkoGostR3410_2012_256(
                bob.getPrivate(), alice.getPublic(), ukm);

        // kekAlice == kekBob — 32 байта, одинаковы с обеих сторон

        // KDF_TREE: из KEK получить ключ шифрования и ключ MAC
        byte[] label = "session keys".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        keys = KdfTreeGostR3411_2012_256.generate(kekAlice, label, ukmBytes, 2, 32);

        byte[] encKey = Arrays.copyOfRange(keys, 0, 32);  // ключ шифрования
        byte[] macKey = Arrays.copyOfRange(keys, 32, 64); // ключ аутентификации

        // использовать encKey и macKey...

    } finally {
        alice.getPrivate().destroy();
        bob.getPrivate().destroy();
        if (keys != null) Arrays.fill(keys, (byte) 0);
    }

UKM передаётся партнёру открыто — это не секрет. Его назначение —
сделать KEK уникальным для каждой сессии, даже при статических ключах
сторон. Рекомендуется минимум 64 бит (8 байт).

### VKO через JCA

    import javax.crypto.KeyAgreement;
    import org.rssys.gost.jca.spec.GostUkmParameterSpec;
    import java.math.BigInteger;

    BigInteger ukm = new BigInteger(1, ukmBytes); // ukmBytes — случайные 8+ байт

    KeyAgreement ka = KeyAgreement.getInstance("VKOGOST3410-2012-256", "RssysGostProvider");
    ka.init(alice.getPrivate(), new GostUkmParameterSpec(ukm)); // 
    ka.doPhase(bob.getPublic(), true);
    byte[] kek = ka.generateSecret(); // 32 байта KEK_VKO

- UKM обязателен. Вызов `ka.init(key)` без `GostUkmParameterSpec`
  выбросит `InvalidKeyException`.

### Raw ECDH — только для протокольной реализации

Строительный блок, который требует понимания в использовании.

`computeSharedSecret` и `ECDHGOST2012` возвращают **сырую** X-координату
точки без хэширования и без UKM. Это примитив для реализации протоколов
(TLS 1.3 ГОСТ использует его внутри key schedule). Для прикладного кода
используйте VKO выше.

Результат — X-координата точки `d·Qpeer` в little-endian. Длина: 32
байта для 256-битных кривых, 64 байта для 512-битных.

    import org.rssys.gost.api.KeyAgreement;

    // Только для протокольной реализации — результат передаётся в KDF протокола
    byte[] shared = KeyAgreement.computeSharedSecret(myPriv, peerPub);
    try {
        // передать shared в KDF протокола (например, HKDF в TLS 1.3)...
    } finally {
        Arrays.fill(shared, (byte) 0);
    }

Через JCA (`ECDHGOST2012`) — аналогично, без UKM:

    KeyAgreement ka = KeyAgreement.getInstance("ECDHGOST2012", "RssysGostProvider");
    ka.init(myPriv);
    ka.doPhase(peerPub, true);
    byte[] shared = ka.generateSecret(); // 

- Поддерживаемые алгоритмы для `generateSecret(String)`:
  `"ECDHGOST2012"` и `"RAW"`.

## Защищённая передача ключа (KExp15/KImp15)

KExp15/KImp15 — алгоритм защищённой передачи симметричного ключа от
одной стороны к другой.

**Типичный сценарий:** отправитель шифрует ключ контента на KEK,
полученном через VKO, и передаёт получателю. Получатель независимо
вычисляет тот же KEK и расшифровывает ключ контента.

**KEK** (Key Encryption Key, ключ шифрования ключей) — симметричный
ключ, который используется не для шифрования данных, а для защиты
другого ключа при передаче.

KExp15 используется когда нужно физически передать другой стороне ключ
шифрования, который уже существует (в отличие от схемы VKO + KDF,
которая позволяет договориться двум сторонам вместе об общем ключе
онлайн).

**Например:** Алиса зашифровала документ на случайном ключе CEK. Теперь
ей нужно передать CEK Бобу, чтобы он мог расшифровать документ. Боб не
участвовал в выработке CEK — он его не знает. В CMS/PKCS#7: документ
шифруется один раз на CEK, а CEK отдельно упаковывается через KExp15 для
каждого получателя. Десять получателей — десять упакованных копий CEK,
один шифртекст документа.

Полная схема: VKO → KDF\_TREE → KExp15 / KImp15

    import org.rssys.gost.api.KeyAgreement;
    import org.rssys.gost.api.KeyExport;
    import org.rssys.gost.api.KeyGenerator;
    import org.rssys.gost.api.KeyPair;
    import org.rssys.gost.cipher.SymmetricKey;
    import org.rssys.gost.kdf.KdfTreeGostR3411_2012_256;
    import org.rssys.gost.signature.ECParameters;
    import org.rssys.gost.util.CryptoRandom;
    import java.math.BigInteger;
    import java.util.Arrays;

    ECParameters params = ECParameters.cryptoProA();

    // Долгосрочные ключевые пары сторон (обычно загружаются из сертификатов)
    KeyPair aliceKeyPair = KeyGenerator.generateKeyPair(params);
    KeyPair bobKeyPair   = KeyGenerator.generateKeyPair(params);

    // UKM — случайное число сессии, делает KEK уникальным для каждой передачи.
    // Генерируется отправителем и передаётся Бобу открыто (например, в заголовке сообщения).
    byte[] sessionUkm = new byte[8];
    CryptoRandom.INSTANCE.nextBytes(sessionUkm);
    BigInteger ukmValue = new BigInteger(1, sessionUkm);

    // CEK — ключ, которым зашифрован документ или файл.
    // Именно его нужно безопасно передать Бобу.
    SymmetricKey contentKey = KeyGenerator.generateSymmetricKey();

    // wrappedContentKey — CEK, упакованный (зашифрованный) на KEK.
    // Только это значение передаётся Бобу по открытому каналу вместе с sessionUkm.
    byte[] wrappedContentKey = null;
    byte[] aliceDerivedKeys  = null;
    try {
        // ── Отправитель (Алиса) ──────────────────────────────────────────────

        // Шаг 1: вычислить общий секрет KEK через VKO.
        // Алиса использует свой закрытый ключ и открытый ключ Боба.
        byte[] aliceKek = KeyAgreement.vkoGostR3410_2012_256(
                aliceKeyPair.getPrivate(), bobKeyPair.getPublic(), ukmValue);

        // Шаг 2: из KEK вывести два рабочих ключа — для MAC и для шифрования.
        // Порядок K_MAC/K_ENC в массиве определяется протоколом — здесь условный пример.
        aliceDerivedKeys = KdfTreeGostR3411_2012_256.generate(
                aliceKek, "kexp15".getBytes(), sessionUkm, 2, 32);
        SymmetricKey aliceKMac = new SymmetricKey(Arrays.copyOfRange(aliceDerivedKeys, 0, 32));
        SymmetricKey aliceKEnc = new SymmetricKey(Arrays.copyOfRange(aliceDerivedKeys, 32, 64));

        // Шаг 3: упаковать CEK — зашифровать его на паре ключей (kMac, kEnc).
        // Результат: CEK, защищённый для передачи по открытому каналу.
        wrappedContentKey = KeyExport.kExp15(
                contentKey.getKey(), aliceKMac, aliceKEnc, sessionUkm); // 

        // ── Передача ─────────────────────────────────────────────────────────
        // Алиса отправляет Бобу открыто: sessionUkm + wrappedContentKey.
        // Сам CEK и KEK по каналу не передаются никогда.

        // ── Получатель (Боб) ─────────────────────────────────────────────────

        // Шаг 1: вычислить тот же KEK через VKO.
        // Боб использует свой закрытый ключ и открытый ключ Алисы.
        // KEK у Боба будет идентичен KEK у Алисы.
        byte[] bobKek = KeyAgreement.vkoGostR3410_2012_256(
                bobKeyPair.getPrivate(), aliceKeyPair.getPublic(), ukmValue);

        // Шаг 2: вывести те же рабочие ключи из KEK и sessionUkm.
        byte[] bobDerivedKeys = KdfTreeGostR3411_2012_256.generate(
                bobKek, "kexp15".getBytes(), sessionUkm, 2, 32);
        SymmetricKey bobKMac = new SymmetricKey(Arrays.copyOfRange(bobDerivedKeys, 0, 32));
        SymmetricKey bobKEnc = new SymmetricKey(Arrays.copyOfRange(bobDerivedKeys, 32, 64));

        // Шаг 3: распаковать CEK — расшифровать и проверить целостность.
        // Если wrappedContentKey был повреждён или ключи неверны — AuthenticationException.
        byte[] contentKeyBytes = KeyExport.kImp15(
                wrappedContentKey, bobKMac, bobKEnc, sessionUkm); // 

        // Боб получил CEK и может расшифровать документ
        SymmetricKey decryptedContentKey = new SymmetricKey(contentKeyBytes);

    } finally {
        aliceKeyPair.getPrivate().destroy();
        bobKeyPair.getPrivate().destroy();
        contentKey.destroy();
        if (aliceDerivedKeys != null) Arrays.fill(aliceDerivedKeys, (byte) 0);
    }

- `kExp15` возвращает `contentKey.length + 16` байт: зашифрованный CEK +
  OMAC-тег целостности.

- `kImp15` бросает `AuthenticationException` если данные повреждены или
  ключи неверны.

UKM передаётся получателю открыто (например, в заголовке сообщения). Его
назначение — сделать KEK уникальным для каждой сессии.

## Функции выработки ключей (KDF)

Библиотека предоставляет три KDF-алгоритма для разных задач.

<table style="width:100%;">
<colgroup>
<col style="width: 28%" />
<col style="width: 42%" />
<col style="width: 28%" />
</colgroup>
<thead>
<tr>
<th style="text-align: left;">Класс</th>
<th style="text-align: left;">Назначение</th>
<th style="text-align: left;">RFC</th>
</tr>
</thead>
<tbody>
<tr>
<td
style="text-align: left;"><p><code>KdfGostR3411_2012_256</code></p></td>
<td style="text-align: left;"><p>Выработка ключевого материала из
мастер-ключа и метки. Применяется в TLSTREE (RFC 9367).</p></td>
<td style="text-align: left;"><p>RFC 7836 §4.4</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>KdfTreeGostR3411_2012_256</code></p></td>
<td style="text-align: left;"><p>Выработка нескольких ключей из одного
мастер-ключа. Применяется в CTR-ACPKM-OMAC (RFC 9337 §5.1.1).</p></td>
<td style="text-align: left;"><p>RFC 7836 §4.5</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>Pbkdf2Streebog</code></p></td>
<td style="text-align: left;"><p>Вывод ключа из пароля. Применяется при
расшифровании PKCS#12.</p></td>
<td style="text-align: left;"><p>RFC 2898 §5.2</p></td>
</tr>
</tbody>
</table>

`KdfGostR3411_2012_256` (§4.4) и `KdfTreeGostR3411_2012_256` (§4.5) —
разные алгоритмы с разным форматом буфера и разным назначением, несмотря
на похожие названия. Не путайте их.

### KdfGostR3411\_2012\_256 — выработка ключевого материала (RFC 7836 §4.4)

Формула:
`K(i) = HMAC-Streebog256(key, [i]_b || label || 0x00 || seed || [L]_b)`,
результат: `K(1) || K(2) || ...` до нужной длины.

Выработка 32 байт ключевого материала

    import org.rssys.gost.kdf.KdfGostR3411_2012_256;

    byte[] masterKey = ...; // 32-байтный мастер-ключ
    byte[] label     = "key expansion".getBytes(StandardCharsets.UTF_8);
    byte[] seed      = ...; // случайная затравка

    // Выработать 32 байта (один блок Streebog-256)
    byte[] keyMaterial = KdfGostR3411_2012_256.expand(masterKey, label, seed, 32);
    try {
        // использование keyMaterial...
    } finally {
        java.util.Arrays.fill(keyMaterial, (byte) 0);
    }

Выработка большего объёма ключевого материала

    import org.rssys.gost.kdf.KdfGostR3411_2012_256;

    byte[] masterKey = ...;
    byte[] label     = "traffic keys".getBytes(StandardCharsets.UTF_8);
    byte[] seed      = ...;

    // 64 байта = два блока по 32; функция итерирует автоматически
    byte[] keyMaterial = KdfGostR3411_2012_256.expand(masterKey, label, seed, 64);
    try {
        byte[] key1 = Arrays.copyOfRange(keyMaterial, 0, 32);  // первый ключ
        byte[] key2 = Arrays.copyOfRange(keyMaterial, 32, 64); // второй ключ
        // ...
    } finally {
        java.util.Arrays.fill(keyMaterial, (byte) 0);
    }

### KdfTreeGostR3411\_2012\_256 — дерево ключей (RFC 7836 §4.5)

Формула:
`K(i) = HMAC-Streebog256(K_in, label || 0x00 || seed || INT(i,4) || INT(L,4))`,
результат: `K(1) || K(2) || ... || K(count)`.

Отличие от §4.4: счётчик `i` и длина `L` кодируются фиксированными 4
байтами big-endian; каждый блок не превышает 32 байт (размер вывода
HMAC-Streebog-256).

Выработка ключа шифрования и ключа аутентификации из одного мастер-ключа

    import org.rssys.gost.kdf.KdfTreeGostR3411_2012_256;

    byte[] masterKey = ...; // 32-байтный мастер-ключ
    byte[] label     = "kdf tree".getBytes(StandardCharsets.UTF_8);
    byte[] seed      = ...; // уникальная затравка для каждой сессии

    // count=2: два ключа по 32 байта
    // Результат: K(1) || K(2), итого 64 байта
    byte[] keys = KdfTreeGostR3411_2012_256.generate(masterKey, label, seed, 2, 32);
    try {
        byte[] encKey = Arrays.copyOfRange(keys, 0, 32);  // K(1) — ключ шифрования
        byte[] macKey = Arrays.copyOfRange(keys, 32, 64); // K(2) — ключ аутентификации
        // ...
    } finally {
        java.util.Arrays.fill(keys, (byte) 0);
    }

Выработка одного ключа

    import org.rssys.gost.kdf.KdfTreeGostR3411_2012_256;

    byte[] masterKey = ...;
    byte[] label     = "session key".getBytes(StandardCharsets.UTF_8);
    byte[] seed      = ...;

    // count=1, keyLen=32: один ключ 32 байта
    byte[] sessionKey = KdfTreeGostR3411_2012_256.generate(masterKey, label, seed, 1, 32);
    try {
        // использование sessionKey...
    } finally {
        java.util.Arrays.fill(sessionKey, (byte) 0);
    }

`keyLen` не может превышать 32 байта (размер вывода HMAC-Streebog-256 по
RFC 7836 §4.5). Для большего объёма увеличивайте `count`, а не `keyLen`.

### Pbkdf2Streebog — вывод ключа из пароля (RFC 2898 §5.2)

PBKDF2 с PRF = HMAC-Streebog-512 (RFC 9337 §4). Используется при работе
с PKCS#12 и для хранения ключей, защищённых паролем.

Вывод ключа из пароля (HMAC-Streebog-512)

    import org.rssys.gost.kdf.Pbkdf2Streebog;
    import org.rssys.gost.util.CryptoRandom;

    byte[] password   = "секретный пароль".getBytes(StandardCharsets.UTF_8);
    byte[] salt       = new byte[16];
    CryptoRandom.INSTANCE.nextBytes(salt); // 
    int    iterations = 100_000;                      // 
    int    keyLen     = 32;                           // байт

    byte[] derivedKey = Pbkdf2Streebog.generate(password, salt, iterations, keyLen);
    try {
        // использование derivedKey...
    } finally {
        java.util.Arrays.fill(derivedKey, (byte) 0);
        java.util.Arrays.fill(password, (byte) 0);   // 
    }

- Соль не является секретом — её можно хранить рядом с зашифрованными
  данными. Главное требование: соль уникальна для каждого объекта.

- Число итераций определяет вычислительную стоимость. NIST рекомендует
  не менее 600 000 для PBKDF2-HMAC-SHA256; для Streebog-512 подбирайте
  исходя из требуемого времени выполнения.

- `Pbkdf2Streebog.generate` не обнуляет массив пароля — это
  ответственность вызывающего кода.

JCA-вариант через SecretKeyFactory

    import javax.crypto.SecretKey;
    import javax.crypto.SecretKeyFactory;
    import javax.crypto.spec.PBEKeySpec;
    import org.rssys.gost.util.CryptoRandom;

    char[] password   = "секретный пароль".toCharArray();
    byte[] salt       = new byte[16];
    CryptoRandom.INSTANCE.nextBytes(salt);
    int    iterations = 100_000;
    int    keyLenBits = 256;                           // 

    SecretKeyFactory skf = SecretKeyFactory.getInstance(
            "PBKDF2WithHmacStreebog512", "RssysGostProvider");
    PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyLenBits);
    try {
        SecretKey key = skf.generateSecret(spec);      // 
        byte[] raw = key.getEncoded();
        // передать raw в KDF или использовать как ключ шифрования...
        java.util.Arrays.fill(raw, (byte) 0);
    } finally {
        spec.clearPassword();
        java.util.Arrays.fill(password, '\0');
    }

- Длина ключа в **битах** (в отличие от `Pbkdf2Streebog.generate`, где
  байты).

- Возвращает `GostSecretKey` с
  `getAlgorithm() = "PBKDF2WithHmacStreebog512"`. Алиас
  `"PBKDF2WithHmacGOST3411-2012-512"` даёт тот же результат.

Символы пароля за пределами Basic Multilingual Plane (U+10000 и выше)
кодируются как CESU-8, а не UTF-8. Для паролей из ASCII и кириллицы
поведение идентично стандартному UTF-8.

## Замечания по безопасности API

- **Очистка ключей** — `SymmetricKey`, `PrivateKeyParameters`,
  `ECDSASigner` реализуют `javax.security.auth.Destroyable`. Вызывайте
  `destroy()` в блоке `finally`.

- **Сравнение MAC** — используйте `verifyMac()` вместо
  `Arrays.equals()`. `verifyMac` использует `MessageDigest.isEqual()` —
  constant-time.

- **IV** — каждый вызов `encrypt()` без явного IV генерирует новый
  случайный IV. Повторное использование IV с одним ключом в CTR/OFB
  нарушает конфиденциальность.

- **Thread-safety** — статические методы всех классов API
  потокобезопасны.

## Замечания по безопасности JCA

- **Закрытые ключи** — `PrivateKeyParameters` реализует `Destroyable`.
  После использования вызывайте `((Destroyable) privateKey).destroy()`.

- **ICN в MGM** — повтор ICN с тем же ключом полностью компрометирует
  защиту. Используйте `ENCRYPT_MODE` без явного ICN: он генерируется
  через `CryptoRandom` автоматически.

- **AAD** — `updateAAD` должен вызываться до `update`/`doFinal`. Порядок
  важен.

- **AEADBadTagException** — не кэшируйте данные из потока расшифрования
  до получения этого исключения или успешного завершения.

## Кросс-валидация

Тесты кросс-валидации проводились на Alt linux p11 x86-64, где OpenSSL
(3.3.3 11 Feb 2025) имеет поддержку ГОСТ-алгоритмов (gost engine).

Запуск всех тестов (kuznyechick, digest-mac, sign, keys) кросс-валидации
одной командой:

    mvn -Pcrossval test -Dexec.skip=true

### Режимы алгоритма Кузнечик

[Методика кросс-валидации режимов блочного шифра
Кузнечик](../x-validation-tests/kuznyechik/doc/kuznyechik-cross-validation.md).

Для модуля `crypto-gost-core` выполнена кросс-валидация на совместимость
с предыдущим релизом, OpenSSL (Кузнечик) и BouncyCastle 1.84.
Поддерживаются режимы: CTR, CBC, CFB, OFB, MGM(только между
crypto-gost).

Все тесты в модуле `x-validation-tests/kuznyechik`:

    # Все тесты (JUnit): BC + OpenSSL + interop
    mvn -Pcrossval -pl x-validation-tests/kuznyechik -am test -Dexec.skip=true

    # Только BouncyCastle
    mvn -Pcrossval -pl x-validation-tests/kuznyechik -am test -Dexec.skip=true \
        -Dtest=BcCrossValidationTest -Dsurefire.failIfNoSpecifiedTests=false

    # Только OpenSSL
    mvn -Pcrossval -pl x-validation-tests/kuznyechik -am test -Dexec.skip=true \
        -Dtest=OpenSslCrossValidationTest -Dsurefire.failIfNoSpecifiedTests=false

    # Все тесты с cross-version (previous.ver=0.3.4 подтягивается автоматически)
    mvn -Pcrossval -pl x-validation-tests/kuznyechik -am test -Dexec.skip=true

### Коды аутентификации (MAC)

[Методика кросс-валидации хэшей и
MAC](../x-validation-tests/digest-mac/doc/digest-mac-cross-validation.md).

Для модуля `crypto-gost-core` выполнена кросс-валидация на совместимость
по следующим алгоритмам:

- Streebog-256/512 (хэш),

- HMAC-Streebog-256/512,

- CMAC-Kuznyechik.

Валидация выполняется против BouncyCastle и OpenSSL (GOST-провайдер).

Все тесты в модуле `x-validation-tests/digest-mac`:

    # Все тесты (JUnit): BC + OpenSSL
    mvn -Pcrossval -pl x-validation-tests/digest-mac -am test -Dexec.skip=true

    # Только BouncyCastle
    mvn -Pcrossval -pl x-validation-tests/digest-mac -am test -Dexec.skip=true \
        -Dtest=BcMacCrossValidationTest -Dsurefire.failIfNoSpecifiedTests=false

    # Только OpenSSL
    mvn -Pcrossval -pl x-validation-tests/digest-mac -am test -Dexec.skip=true \
        -Dtest=OpenSslMacCrossValidationTest -Dsurefire.failIfNoSpecifiedTests=false

### Проверка совместимостей ключей ГОСТ Р 34.10-2012

[Методика кросс-валидации ключей ГОСТ Р
34.10-2012](../x-validation-tests/keys/doc/keys-cross-validation.md).

Для модуля `crypto-gost-core` выполнена кросс-валидация на совместимость
по генерации ключей ГОСТ Р 34.10-2012 (256 и 512 бит). Валидация
выполняется против BouncyCastle и OpenSSL (GOST-провайдер).
Поддерживаются кривые: CryptoPro-A/B/C, TC26-A/B/C-256, TC26-A/B/C-512.

Все тесты в модуле `x-validation-tests/keys`:

    # Все тесты (JUnit): BC (7 кривых) + OpenSSL (6 кривых)
    mvn -Pcrossval -pl x-validation-tests/keys -am test -Dexec.skip=true

    # Только BC (7 кривых)
    mvn -Pcrossval -pl x-validation-tests/keys -am test -Dexec.skip=true \
        -Dtest=BcKey*CrossValidationTest -Dsurefire.failIfNoSpecifiedTests=false

    # Только OpenSSL (6 кривых)
    mvn -Pcrossval -pl x-validation-tests/keys -am test -Dexec.skip=true \
        -Dtest=OpenSsl*CrossValidationTest -Dsurefire.failIfNoSpecifiedTests=false

### Электронная подпись (ГОСТ Р 34.10-2012)

[Методика кросс-валидации ГОСТ Р 34.10-2012 (электронная
подпись)](../x-validation-tests/sign/doc/sign-cross-validation.md).

Для модуля `crypto-gost-core` выполнена кросс-валидация на совместимость
по алгоритму подписи ГОСТ Р 34.10-2012 (256 и 512 бит). Валидация
выполняется против BouncyCastle и OpenSSL (GOST-провайдер).

Поддерживаются кривые: CryptoPro-A/B/C, TC26-A/B/C-256, TC26-A/B/C-512.

Все тесты в модуле `x-validation-tests/sign`:

    # Все тесты (JUnit): BC (7 кривых, 2800 проверок) + OpenSSL (6 кривых, 120 проверок)
    mvn -Pcrossval -pl x-validation-tests/sign -am test -Dexec.skip=true

    # Только BC (7 кривых)
    mvn -Pcrossval -pl x-validation-tests/sign -am test -Dexec.skip=true \
        -Dtest=BcSignCrossValidationTest -Dsurefire.failIfNoSpecifiedTests=false

    # Только OpenSSL (6 кривых, 256 и 512 бит)
    mvn -Pcrossval -pl x-validation-tests/sign -am test -Dexec.skip=true \
        -Dtest=OpenSsl*CrossValidationTest -Dsurefire.failIfNoSpecifiedTests=false

# Поддержать проект

Если проект оказался полезным, вы можете поддержать проект на
[**Boosty**](https://boosty.to/mike_ananev/donate)

# Лицензия

Автор: Михаил Ананьев.  

Данный проект распространяется под *Открытой лицензией на программное
обеспечение "Рэд старс системс"*, версия 1.0.  
Текст лицензии находится в файле LICENSE или по
[ссылке](https://gitflic.ru/project/red-stars-systems/licenses/blob?file=open-license%2FLICENSE).
