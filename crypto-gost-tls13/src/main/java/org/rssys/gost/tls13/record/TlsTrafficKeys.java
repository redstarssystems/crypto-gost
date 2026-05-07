package org.rssys.gost.tls13.record;

import org.rssys.gost.tls13.TlsUtils;

/**
 * Traffic-ключи: key (32 байта) и IV (16 байт).
 * <p>
 * Вырабатываются из traffic secret через HKDF-Expand-Label (RFC 8446 §7.3).
 * После использования обязательно вызывать {@link #destroy()}.
 */
public final class TlsTrafficKeys {
    private final byte[] key;
    private final byte[] iv;

    /**
     * @param key ключевой материал (32 байта)
     * @param iv  инициализационный вектор (16 байт)
     */
    public TlsTrafficKeys(byte[] key, byte[] iv) {
        this.key = key;
        this.iv = iv;
    }

    /** @return ключ шифрования */
    public byte[] getKey() {
        return key.clone();
    }

    /** @return IV для MGM */
    public byte[] getIv() {
        return iv.clone();
    }

    /** Затирает ключевой материал (security, RFC 8446 §7.3). */
    public void destroy() {
        TlsUtils.wipeArray(key);
        TlsUtils.wipeArray(iv);
    }
}
