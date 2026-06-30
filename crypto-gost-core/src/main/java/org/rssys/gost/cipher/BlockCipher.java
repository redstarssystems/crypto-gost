package org.rssys.gost.cipher;

import org.rssys.gost.util.DataLengthException;

public interface BlockCipher {
    void init(boolean forEncryption, CipherParameters params) throws IllegalArgumentException;

    String getAlgorithmName();

    int getBlockSize();

    int processBlock(byte[] in, int inOff, byte[] out, int outOff)
            throws DataLengthException, IllegalStateException;

    void reset();
}
