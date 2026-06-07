package org.rssys.gost.crossval.digestmac;

import org.bouncycastle.crypto.digests.GOST3411_2012_256Digest;
import org.bouncycastle.crypto.digests.GOST3411_2012_512Digest;
import org.bouncycastle.crypto.engines.GOST3412_2015Engine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;



/**
 * Stateless обёртка над BouncyCastle.
 *
 * Каждый метод создаёт свежий экземпляр движка — накопление состояния
 * между вызовами исключено. Это гарантирует изоляцию тестовых случаев:
 * сбой в одном размере/алгоритме не влияет на последующие вызовы,
 * и не нужна очистка внутреннего состояния между итерациями цикла.
 */
public final class BcMacHelper {
    private BcMacHelper() {}

    public static byte[] bcDigest256(byte[] msg) {
        GOST3411_2012_256Digest d = new GOST3411_2012_256Digest();
        d.update(msg, 0, msg.length);
        byte[] out = new byte[d.getDigestSize()];
        d.doFinal(out, 0);
        return out;
    }

    public static byte[] bcDigest512(byte[] msg) {
        GOST3411_2012_512Digest d = new GOST3411_2012_512Digest();
        d.update(msg, 0, msg.length);
        byte[] out = new byte[d.getDigestSize()];
        d.doFinal(out, 0);
        return out;
    }

    public static byte[] bcHmac256(byte[] keyBytes, byte[] msg) {
        HMac mac = new HMac(new GOST3411_2012_256Digest());
        mac.init(new KeyParameter(keyBytes));
        mac.update(msg, 0, msg.length);
        byte[] out = new byte[mac.getMacSize()];
        mac.doFinal(out, 0);
        return out;
    }

    public static byte[] bcHmac512(byte[] keyBytes, byte[] msg) {
        HMac mac = new HMac(new GOST3411_2012_512Digest());
        mac.init(new KeyParameter(keyBytes));
        mac.update(msg, 0, msg.length);
        byte[] out = new byte[mac.getMacSize()];
        mac.doFinal(out, 0);
        return out;
    }

    public static byte[] bcCmac(byte[] keyBytes, byte[] msg) {
        CMac mac = new CMac(new GOST3412_2015Engine());
        mac.init(new KeyParameter(keyBytes));
        mac.update(msg, 0, msg.length);
        byte[] out = new byte[mac.getMacSize()];
        mac.doFinal(out, 0);
        return out;
    }
}
