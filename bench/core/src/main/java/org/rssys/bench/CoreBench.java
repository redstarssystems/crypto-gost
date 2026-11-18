package org.rssys.bench;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.concurrent.TimeUnit;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.infra.Blackhole;
import org.rssys.crypto.util.SCrypt;
import org.rssys.gost.api.AuthenticatedCipher;
import org.rssys.gost.api.AuthenticatedStream;
import org.rssys.gost.api.Cipher;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.MgmCipher;
import org.rssys.gost.cipher.Kuznyechik;
import org.rssys.gost.cipher.ParametersWithIV;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.cipher.mode.Mgm;
import org.rssys.gost.util.CryptoRandom;

/**
 * JMH-замеры мест, где важны время и давление на сборщик мусора: scrypt, MGM, потоковые обёртки
 * {@code Cipher}, {@code AuthenticatedCipher}, {@code AuthenticatedStream}, инициализация
 * Кузнечика и {@code SymmetricKey.getKey}.
 *
 * <p>Главная метрика здесь не время, а выделения памяти на операцию: запускать с
 * {@code -prof gc} и смотреть {@code gc.alloc.rate.norm} (байт на операцию, от шума машины не
 * зависит).
 */
@State(Scope.Thread)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Warmup(iterations = 4, time = 2)
@Measurement(iterations = 5, time = 2)
@Fork(2)
public class CoreBench {

    private static final int SMALL = 64;
    private static final int CHUNK = 4096;

    /** Мелкий чанк потока: на нём стоимость развёртывания ключа на чанк не тонет в шифровании. */
    private static final int SMALL_CHUNK = 128;

    private static final int SMALL_CHUNKS_IN_STREAM = 64;

    @Param({"CTR", "CFB", "OFB"})
    public Cipher.Mode mode;

    private SymmetricKey key;
    private byte[] password;
    private byte[] salt;
    private byte[] small;
    private byte[] aad;
    private byte[] sealedSmall;
    private byte[] authSealed;
    private byte[] authSealedWithAad;
    private byte[] chunk;
    private byte[] readBuf;
    private OutputStream encryptingOut;
    private InputStream decryptingIn;
    private OutputStream sealingOut;
    private byte[] streamSealed;
    private OutputStream sealingSmallOut;
    private byte[] streamSealedSmall;
    private byte[] streamSealedSmallWithAad;
    private Kuznyechik kuznyechik;

    @Setup
    public void setup() throws IOException {
        key = KeyGenerator.generateSymmetricKey();
        password = new byte[16];
        salt = new byte[16];
        small = new byte[SMALL];
        aad = new byte[16];
        chunk = new byte[CHUNK];
        readBuf = new byte[CHUNK];
        CryptoRandom.INSTANCE.nextBytes(password);
        CryptoRandom.INSTANCE.nextBytes(salt);
        CryptoRandom.INSTANCE.nextBytes(small);
        CryptoRandom.INSTANCE.nextBytes(aad);
        CryptoRandom.INSTANCE.nextBytes(chunk);
        sealedSmall = MgmCipher.seal(small, key, aad);
        authSealed = AuthenticatedCipher.seal(chunk, key);
        authSealedWithAad = AuthenticatedCipher.seal(chunk, key, aad);

        byte[] iv = new byte[mode == Cipher.Mode.CTR ? 8 : 16];
        CryptoRandom.INSTANCE.nextBytes(iv);
        encryptingOut = Cipher.encryptingStream(OutputStream.nullOutputStream(), key, iv, mode);
        // Бесконечный источник: содержимое не важно, важна работа расшифрования над буфером
        decryptingIn =
                Cipher.decryptingStream(
                        new InputStream() {
                            @Override
                            public int read() {
                                return 0;
                            }

                            @Override
                            public int read(byte[] b, int off, int len) {
                                return len;
                            }
                        },
                        key,
                        iv,
                        mode);

        sealingOut = AuthenticatedStream.sealing(OutputStream.nullOutputStream(), key, CHUNK);
        ByteArrayOutputStream sealed = new ByteArrayOutputStream();
        try (OutputStream s = AuthenticatedStream.sealing(sealed, key, CHUNK)) {
            for (int i = 0; i < 16; i++) {
                s.write(chunk);
            }
        }
        streamSealed = sealed.toByteArray();

        sealingSmallOut =
                AuthenticatedStream.sealing(OutputStream.nullOutputStream(), key, SMALL_CHUNK);
        ByteArrayOutputStream sealedSmallChunks = new ByteArrayOutputStream();
        try (OutputStream s = AuthenticatedStream.sealing(sealedSmallChunks, key, SMALL_CHUNK)) {
            for (int i = 0; i < SMALL_CHUNKS_IN_STREAM; i++) {
                s.write(chunk, 0, SMALL_CHUNK);
            }
        }
        streamSealedSmall = sealedSmallChunks.toByteArray();
        ByteArrayOutputStream sealedSmallChunksWithAad = new ByteArrayOutputStream();
        try (OutputStream s =
                AuthenticatedStream.sealing(sealedSmallChunksWithAad, key, SMALL_CHUNK, aad)) {
            for (int i = 0; i < SMALL_CHUNKS_IN_STREAM; i++) {
                s.write(chunk, 0, SMALL_CHUNK);
            }
        }
        streamSealedSmallWithAad = sealedSmallChunksWithAad.toByteArray();
        kuznyechik = new Kuznyechik();
    }

    @TearDown
    public void tearDown() throws IOException {
        encryptingOut.close();
        decryptingIn.close();
        sealingOut.close();
        sealingSmallOut.close();
    }

    @Benchmark
    public byte[] scrypt() throws Exception {
        // N = 2^12, r = 8: 4 МиБ рабочей памяти, чтобы замер не упирался в выделение V
        return SCrypt.generate(password, salt, 1 << 12, 8, 1, 32);
    }

    @Benchmark
    public byte[] mgmSeal() {
        return MgmCipher.seal(small, key, aad);
    }

    @Benchmark
    public byte[] mgmOpen() throws Exception {
        return MgmCipher.open(sealedSmall, key, aad);
    }

    /** Тег короче блока: писался через временный массив. */
    @Benchmark
    public byte[] mgmShortTag() {
        Mgm mgm = new Mgm(new Kuznyechik(), 12);
        byte[] icn = new byte[16];
        byte[] out = new byte[SMALL + 12];
        try {
            mgm.init(true, new ParametersWithIV(key, icn));
            mgm.processBytes(small, 0, SMALL, out, 0);
            mgm.finishEncryption(out, SMALL);
            return out;
        } finally {
            mgm.destroy();
        }
    }

    @Benchmark
    public void wrapEncrypt(Blackhole bh) throws IOException {
        encryptingOut.write(chunk, 0, CHUNK);
        bh.consume(chunk);
    }

    @Benchmark
    public int wrapDecrypt() throws IOException {
        return decryptingIn.read(readBuf, 0, CHUNK);
    }

    @Benchmark
    public byte[] authSeal() {
        return AuthenticatedCipher.seal(chunk, key);
    }

    @Benchmark
    public byte[] authOpen() throws Exception {
        return AuthenticatedCipher.open(authSealed, key);
    }

    /** Пакет с внешним AAD в 16 байт: к цене {@code authSeal} добавляется затравка KDF с AAD. */
    @Benchmark
    public byte[] authSealWithAad() {
        return AuthenticatedCipher.seal(chunk, key, aad);
    }

    @Benchmark
    public byte[] authOpenWithAad() throws Exception {
        return AuthenticatedCipher.open(authSealedWithAad, key, aad);
    }

    @Benchmark
    public void streamWrite() throws IOException {
        sealingOut.write(chunk, 0, CHUNK);
    }

    @Benchmark
    public long streamRead() throws Exception {
        long total = 0;
        try (InputStream in = AuthenticatedStream.opening(new ByteArrayInputStream(streamSealed), key)) {
            int n;
            while ((n = in.read(readBuf)) > 0) {
                total += n;
            }
        }
        return total;
    }

    /** Один мелкий чанк (128 байт) на операцию. */
    @Benchmark
    public void streamWriteSmallChunk() throws IOException {
        sealingSmallOut.write(chunk, 0, SMALL_CHUNK);
    }

    /** Чтение потока из 64 мелких чанков по 128 байт. */
    @Benchmark
    public long streamReadSmallChunks() throws Exception {
        long total = 0;
        try (InputStream in =
                AuthenticatedStream.opening(new ByteArrayInputStream(streamSealedSmall), key)) {
            int n;
            while ((n = in.read(readBuf)) > 0) {
                total += n;
            }
        }
        return total;
    }

    /** То же, что {@code streamReadSmallChunks}, но поток открыт с внешним AAD в 16 байт. */
    @Benchmark
    public long streamReadSmallChunksWithAad() throws Exception {
        long total = 0;
        try (InputStream in =
                AuthenticatedStream.opening(
                        new ByteArrayInputStream(streamSealedSmallWithAad), key, aad)) {
            int n;
            while ((n = in.read(readBuf)) > 0) {
                total += n;
            }
        }
        return total;
    }

    @Benchmark
    public long kuznyechikInit() {
        kuznyechik.init(true, key);
        kuznyechik.encryptToFields(1L, 2L);
        return kuznyechik.getEncBufHi();
    }

    @Benchmark
    public byte[] symmetricKeyGetKey() {
        return key.getKey();
    }
}
