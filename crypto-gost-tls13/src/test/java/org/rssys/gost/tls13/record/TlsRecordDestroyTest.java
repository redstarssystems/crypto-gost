package org.rssys.gost.tls13.record;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.ByteBuffer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.util.CryptoRandom;

/**
 * Уничтоженная запись непригодна: после {@code destroy()} ключ обнулён, и шифрование нулевым
 * ключом выглядело бы как обычная работа, поэтому использование отвергается явно.
 */
@DisplayName("TlsRecord: использование после destroy()")
class TlsRecordDestroyTest {

    private static final TlsCiphersuite SUITE =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;

    private static TlsRecord newRecord() {
        byte[] key = new byte[TlsConstants.KUZNYECHIK_KEY_SIZE];
        byte[] iv = new byte[TlsConstants.MGM_IV_SIZE];
        CryptoRandom.INSTANCE.nextBytes(key);
        CryptoRandom.INSTANCE.nextBytes(iv);
        return new TlsRecord(key, iv, TlsConstants.MGM_TAG_SIZE, SUITE);
    }

    @Test
    @DisplayName("protect после destroy: IllegalStateException, а не шифрование нулевым ключом")
    void protectAfterDestroyIsRejected() {
        TlsRecord record = newRecord();
        record.destroy();

        assertThrows(
                IllegalStateException.class,
                () -> record.protect(TlsConstants.CT_APPLICATION_DATA, new byte[] {1}),
                "Уничтоженная запись не должна шифровать");
    }

    @Test
    @DisplayName("unprotect после destroy: IllegalStateException")
    void unprotectAfterDestroyIsRejected() {
        TlsRecord writer = newRecord();
        TlsRecord reader = newRecord();
        byte[] wire = writer.protect(TlsConstants.CT_APPLICATION_DATA, new byte[] {1});
        reader.destroy();

        assertThrows(
                IllegalStateException.class,
                () -> reader.unprotect(wire),
                "Уничтоженная запись не должна расшифровывать");
    }

    @Test
    @DisplayName(
            "unprotect(ByteBuffer) после destroy: IllegalStateException даже на коротком входе")
    void unprotectBufferAfterDestroyIsRejected() {
        TlsRecord reader = newRecord();
        reader.destroy();

        // Короткий вход иначе дал бы NEED_MORE_INPUT, не доходя до расшифровки
        assertThrows(
                IllegalStateException.class,
                () -> reader.unprotect(ByteBuffer.allocate(1), ByteBuffer.allocate(64)),
                "Уничтоженная запись не должна принимать и ждать данные");
    }

    @Test
    @DisplayName("unprotectInto после destroy: IllegalStateException")
    void unprotectIntoAfterDestroyIsRejected() {
        TlsRecord writer = newRecord();
        TlsRecord reader = newRecord();
        byte[] wire = writer.protect(TlsConstants.CT_APPLICATION_DATA, new byte[] {1});
        reader.destroy();

        assertThrows(
                IllegalStateException.class,
                () -> reader.unprotectInto(wire, new byte[16], 0),
                "Уничтоженная запись не должна расшифровывать");
    }

    @Test
    @DisplayName("destroy идемпотентен: повторный вызов безопасен")
    void destroyIsIdempotent() {
        TlsRecord record = newRecord();
        record.destroy();

        assertDoesNotThrow(record::destroy, "Повторное уничтожение не должно падать");
    }
}
