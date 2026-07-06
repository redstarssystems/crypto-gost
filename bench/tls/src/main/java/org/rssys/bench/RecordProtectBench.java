package org.rssys.bench;

import org.openjdk.jmh.annotations.*;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.record.TlsRecord;
import java.util.concurrent.TimeUnit;

/**
 * JMH-бенчмарк record layer: protect и unprotect (AEAD Кузнечик-MGM).
 * <p>
 * Зачем: protect/unprotect вызывается на каждую TLS-запись.
 * Для долгоживущих сессий это доминирующий путь. Измеряем raw AEAD throughput
 * без handshake overhead. Размеры данных: 100B (мелкие сообщения), 1KB,
 * 16KB (полная TLS record) — через {@link Param}.
 */
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@State(Scope.Benchmark)
public class RecordProtectBench {

    private TlsRecord writerRecord;
    private TlsRecord readerRecord;
    @Param({"100", "1024", "16383"})
    private int dataSize;
    private byte[] data;

    @Setup(Level.Trial)
    public void setup() throws Exception {
        TlsCiphersuite cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        // Случайные ключи — для AEAD throughput это эквивалентно
        // handshake-выработанным. Нас интересует производительность
        // Кузнечик-MGM, а не key schedule.
        byte[] key = new byte[32];
        byte[] iv = new byte[16];
        java.security.SecureRandom.getInstanceStrong().nextBytes(key);
        java.security.SecureRandom.getInstanceStrong().nextBytes(iv);

        writerRecord = new TlsRecord(key, iv, cs.getTagLen(), cs);
        readerRecord = new TlsRecord(key.clone(), iv.clone(), cs.getTagLen(), cs);
        data = new byte[dataSize];
        java.security.SecureRandom.getInstanceStrong().nextBytes(data);
    }

    @Benchmark
    public byte[] protect() {
        return writerRecord.protect(TlsConstants.CT_APPLICATION_DATA, data);
    }

    @Benchmark
    public int unprotect() throws Exception {
        // Комбинированный protect+unprotect на каждой итерации.
        // seqNum растёт монотонно на writer и reader независимо —
        // nonce совпадает, никаких сбросов не требуется.
        // Чистый decrypt = комбинированный − protect (измеряется отдельно
        // в benchmark protect() выше). Соотношения между размерами данных
        // (100B / 1KB / 16KB) сохраняются для любого из трёх значений.
        byte[] record = writerRecord.protect(TlsConstants.CT_APPLICATION_DATA, data);
        readerRecord.unprotect(record);
        return (int) readerRecord.getSequenceNumber();
    }
    // shared writerRecord/readerRecord OK при @Threads(1).
    // При многопоточном замере (@Threads(N)) переделать на @State(Scope.Thread).
}
