package org.rssys.gost.digest;

public interface Digest {
    String getAlgorithmName();

    int getDigestSize();

    int getByteLength();

    void update(byte in);

    void update(byte[] in, int inOff, int len);

    int doFinal(byte[] out, int outOff);

    void reset();
}
