package org.rssys.bench;

import org.openjdk.jmh.annotations.*;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsSession;
import org.rssys.gost.tls13.config.TlsClientConfig;
import org.rssys.gost.tls13.config.TlsServerConfig;
import org.rssys.gost.tls13.record.TlsRecord;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;
import java.util.concurrent.TimeUnit;

/**
 * JMH-бенчмарк record layer: protect и unprotect.
 * <p>
 * Зачем: protect/unprotect вызывается на каждую TLS-запись.
 * Для долгоживущих сессий (часы/дни) это доминирующий по числу вызовов путь.
 * Измеряем raw throughput record layer без handshake overhead.
 */
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@State(Scope.Benchmark)
public class RecordProtectBench {

    private TlsRecord writerRecord;
    private TlsRecord readerRecord;
    private TlsRecord writerRecordLarge;
    private TlsRecord readerRecordLarge;
    private byte[] smallData;
    private byte[] largeData;
    private byte[] protectedRecord;

    @Setup(Level.Trial)
    public void setup() throws Exception {
        TlsCiphersuite cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;

        // Вырабатываем ключи через полный handshake
        BenchHelper.Bundle bundle = BenchHelper.createBundle();
        BenchHelper.Bundle caBundle = BenchHelper.createBundle();

        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();
        TlsServerConfig sc = new TlsServerConfig(
                pair.getServerTransport(), cs, bundle.cert, bundle.priv);
        // caPublicKey не ставим — иначе mTLS.
        TlsClientConfig cc = new TlsClientConfig(pair.getClientTransport(), cs)
                .withCaPublicKey(bundle.cert.getPublicKey());

        TlsSession server = TlsSession.createServer(sc);
        TlsSession client = TlsSession.createClient(cc);
        Thread st = new Thread(() -> { try { server.handshakeAsServer(); } catch (Exception e) { throw new RuntimeException(e); } });
        st.start();
        client.handshakeAsClient();
        st.join();
        client.close();
        server.close();

        // Создаём TlsRecord с теми же ключами, что используются после handshake
        // (RW — заглушка, так как writerRecord/readerRecord private в TlsSession)
        // Вместо этого создаём независимые TlsRecord с одинаковыми ключами
        // из первого handshake. На практике берем ключи из handshakeServerKeys.
        // Но они private. Используем публичный интерфейс: создаём TlsRecord напрямую.
        byte[] key = new byte[32];
        byte[] iv = new byte[16];
        java.security.SecureRandom.getInstanceStrong().nextBytes(key);
        java.security.SecureRandom.getInstanceStrong().nextBytes(iv);

        writerRecord = new TlsRecord(key, iv, cs.getTagLen(), cs);
        readerRecord = new TlsRecord(key.clone(), iv.clone(), cs.getTagLen(), cs);

        smallData = new byte[100];
        largeData = new byte[16383];
        java.security.SecureRandom.getInstanceStrong().nextBytes(smallData);
        java.security.SecureRandom.getInstanceStrong().nextBytes(largeData);

        protectedRecord = writerRecord.protect(TlsConstants.CT_APPLICATION_DATA, smallData);
        // Сброс seqNum, чтобы reader мог расшифровать
        readerRecord.setSequenceNumber(0);
    }

    @Benchmark
    public byte[] protectSmall() {
        return writerRecord.protect(TlsConstants.CT_APPLICATION_DATA, smallData);
    }

    @Benchmark
    public byte[] protectLarge() {
        return writerRecord.protect(TlsConstants.CT_APPLICATION_DATA, largeData);
    }

    @Benchmark
    public int unprotect() throws Exception {
        // TlsParsedRecord — package-private. Для бенчмарка возвращаем порядковый номер.
        readerRecord.unprotect(protectedRecord);
        return (int) readerRecord.getSequenceNumber();
    }
}
