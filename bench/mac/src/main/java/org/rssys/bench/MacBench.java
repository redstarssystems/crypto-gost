package org.rssys.bench;

import org.bouncycastle.crypto.digests.GOST3411_2012_256Digest;
import org.bouncycastle.crypto.digests.GOST3411_2012_512Digest;
import org.bouncycastle.crypto.engines.GOST3412_2015Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.openjdk.jmh.annotations.*;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.cipher.Kuznyechik;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.digest.Streebog256;
import org.rssys.gost.digest.Streebog512;
import org.rssys.gost.mac.Cmac;
import org.rssys.gost.mac.Hmac;

import java.util.concurrent.TimeUnit;

@State(Scope.Thread)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@Warmup(iterations = 2, time = 1)
@Measurement(iterations = 2, time = 1)
@Fork(1)
public class MacBench {

    @Param({"16", "32", "64", "256", "1024", "65535"})
    public String sizeStr;

    private byte[] data;
    private int size;
    private SymmetricKey gostKey;
    private byte[] keyBytes;

    @Setup
    public void setup() throws Exception {
        size = Integer.parseInt(sizeStr);
        data = new byte[size];
        for (int i = 0; i < size; i++) {
            data[i] = (byte)(i & 0xFF);
        }
        gostKey = KeyGenerator.generateSymmetricKey();
        keyBytes = gostKey.getKey();
    }

    @Benchmark
    public byte[] cmacGost() {
        Cmac mac = new Cmac(new Kuznyechik());
        mac.init(gostKey);
        mac.update(data, 0, size);
        byte[] out = new byte[mac.getMacSize()];
        mac.doFinal(out, 0);
        return out;
    }

    @Benchmark
    public byte[] cmacBc() {
        org.bouncycastle.crypto.macs.CMac mac =
                new org.bouncycastle.crypto.macs.CMac(new GOST3412_2015Engine());
        mac.init(new KeyParameter(keyBytes));
        mac.update(data, 0, size);
        byte[] out = new byte[mac.getMacSize()];
        mac.doFinal(out, 0);
        return out;
    }

    @Benchmark
    public byte[] hmac256Gost() {
        Hmac mac = new Hmac(new Streebog256());
        mac.init(gostKey);
        mac.update(data, 0, size);
        byte[] out = new byte[mac.getMacSize()];
        mac.doFinal(out, 0);
        return out;
    }

    @Benchmark
    public byte[] hmac256Bc() {
        org.bouncycastle.crypto.macs.HMac mac =
                new org.bouncycastle.crypto.macs.HMac(new GOST3411_2012_256Digest());
        mac.init(new KeyParameter(keyBytes));
        mac.update(data, 0, size);
        byte[] out = new byte[mac.getMacSize()];
        mac.doFinal(out, 0);
        return out;
    }

    @Benchmark
    public byte[] hmac512Gost() {
        Hmac mac = new Hmac(new Streebog512());
        mac.init(gostKey);
        mac.update(data, 0, size);
        byte[] out = new byte[mac.getMacSize()];
        mac.doFinal(out, 0);
        return out;
    }

    @Benchmark
    public byte[] hmac512Bc() {
        org.bouncycastle.crypto.macs.HMac mac =
                new org.bouncycastle.crypto.macs.HMac(new GOST3411_2012_512Digest());
        mac.init(new KeyParameter(keyBytes));
        mac.update(data, 0, size);
        byte[] out = new byte[mac.getMacSize()];
        mac.doFinal(out, 0);
        return out;
    }
}
