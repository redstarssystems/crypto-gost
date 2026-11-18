package org.rssys.gost.api;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FilterInputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.util.AuthenticationException;

@DisplayName("AuthenticatedStream: close() закрывает нижний поток, как FilterStream")
class AuthenticatedStreamCloseTest {

    private final SymmetricKey key = KeyGenerator.generateSymmetricKey();

    /** Выходной поток, считающий закрытия и при необходимости отказывающий в записи. */
    private static final class CountingOutput extends FilterOutputStream {
        int closeCount;
        boolean failWrites;

        CountingOutput() {
            super(new ByteArrayOutputStream());
        }

        @Override
        public void write(int b) throws IOException {
            if (failWrites) throw new IOException("запись отклонена");
            out.write(b);
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            if (failWrites) throw new IOException("запись отклонена");
            out.write(b, off, len);
        }

        @Override
        public void close() {
            closeCount++;
        }

        byte[] written() {
            return ((ByteArrayOutputStream) out).toByteArray();
        }
    }

    /** Входной поток, считающий закрытия. */
    private static final class CountingInput extends FilterInputStream {
        int closeCount;

        CountingInput(byte[] data) {
            super(new ByteArrayInputStream(data));
        }

        @Override
        public void close() {
            closeCount++;
        }
    }

    private byte[] sealed(byte[] plain) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (OutputStream sealing = AuthenticatedStream.sealing(bytes, key)) {
            sealing.write(plain);
        }
        return bytes.toByteArray();
    }

    @Test
    @DisplayName(
            "Шифрующий поток закрывает нижний ровно один раз, повторный close ничего не делает")
    void sealingClosesUnderlyingOnce() throws IOException {
        CountingOutput target = new CountingOutput();
        OutputStream sealing = AuthenticatedStream.sealing(target, key);
        sealing.write(new byte[10]);
        sealing.close();
        sealing.close();
        assertEquals(1, target.closeCount, "нижний поток должен быть закрыт один раз");
        assertTrue(target.written().length > 0, "последний чанк должен быть записан до закрытия");
    }

    @Test
    @DisplayName("Сбой записи последнего чанка не оставляет нижний поток открытым")
    void sealingClosesUnderlyingWhenFinalWriteFails() throws IOException {
        CountingOutput target = new CountingOutput();
        OutputStream sealing = AuthenticatedStream.sealing(target, key);
        sealing.write(new byte[10]);
        target.failWrites = true;
        assertThrows(
                IOException.class, sealing::close, "ошибка записи должна дойти до вызывающего");
        assertEquals(1, target.closeCount, "дескриптор не должен утечь");
    }

    @Test
    @DisplayName("Расшифровывающий поток закрывает нижний ровно один раз")
    void openingClosesUnderlyingOnce() throws Exception {
        byte[] plain = new byte[100];
        Arrays.fill(plain, (byte) 5);
        CountingInput source = new CountingInput(sealed(plain));
        InputStream opening = AuthenticatedStream.opening(source, key);
        assertArrayEquals(plain, opening.readAllBytes(), "открытый текст");
        opening.close();
        opening.close();
        assertEquals(1, source.closeCount, "нижний поток должен быть закрыт один раз");
    }

    @Test
    @DisplayName("Чтение после close даёт IOException, а не исключение на уничтоженном ключе")
    void readAfterCloseThrowsIoException() throws Exception {
        InputStream opening =
                AuthenticatedStream.opening(new ByteArrayInputStream(sealed(new byte[40])), key);
        opening.close();
        assertThrows(IOException.class, opening::read, "read() после close");
        assertThrows(
                IOException.class, () -> opening.read(new byte[8], 0, 8), "read(buf) после close");
        assertEquals(
                0, opening.read(new byte[8], 0, 0), "read нулевой длины по контракту InputStream");
    }

    @Test
    @DisplayName("Если заголовок не разобран, нижний поток остаётся открытым для вызывающего")
    void openingFailureLeavesUnderlyingOpen() {
        CountingInput source = new CountingInput(new byte[3]);
        assertThrows(
                AuthenticationException.class,
                () -> AuthenticatedStream.opening(source, key),
                "заголовок обрезан");
        assertEquals(0, source.closeCount, "закрытие остаётся за вызывающим");
    }

    @Test
    @DisplayName("Круговой проход через try-with-resources сохраняет данные")
    void roundTripWithTryWithResources() throws Exception {
        byte[] plain = new byte[5000];
        Arrays.fill(plain, (byte) 9);
        try (InputStream opening =
                AuthenticatedStream.opening(new ByteArrayInputStream(sealed(plain)), key)) {
            assertArrayEquals(
                    plain, opening.readAllBytes(), "открытый текст после обратного прохода");
        }
    }
}
