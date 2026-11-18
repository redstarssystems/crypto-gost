package org.rssys.gost.crossval.util;

import java.io.IOException;

/**
 * Доступ к хранилищу доверенных корней КриптоПро ({@code uRoot}), нужный
 * {@link TrustedRootSession}. Отдельный интерфейс позволяет проверять логику сессии без
 * КриптоПро на поддельном хранилище.
 *
 * <p>Сертификат опознаётся по идентификатору ключа ({@code keyid}) и точному DER: у старого и
 * нового корня с одним ключом {@code keyid} одинаков, а DER различается.
 */
public interface RootStore {

    /** @return число сертификатов с этим {@code keyid} в хранилище (0, если нет) */
    int countByKeyId(byte[] keyId) throws IOException;

    /**
     * Выгружает единственный сертификат с этим {@code keyid}.
     *
     * @return DER сертификата
     * @throws IllegalStateException если сертификатов с этим {@code keyid} не ровно один
     */
    byte[] exportByKeyId(byte[] keyId) throws IOException;

    /** Устанавливает сертификат в хранилище. */
    void install(byte[] der) throws IOException;

    /** Удаляет все сертификаты с этим {@code keyid}; вызывать, когда он ровно один. */
    void deleteByKeyId(byte[] keyId) throws IOException;

    /**
     * @return вывод хранилища для сертификатов с этим {@code keyid}: подсказка оператору, как
     *         удалить лишний корень по отпечатку. Только корневые сертификаты, личные не выводятся.
     */
    String describeByKeyId(byte[] keyId) throws IOException;
}
