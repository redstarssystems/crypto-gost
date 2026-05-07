package org.rssys.gost.mac;

import org.rssys.gost.cipher.CipherParameters;
import org.rssys.gost.util.DataLengthException;

public interface Mac {
    void init(CipherParameters params) throws IllegalArgumentException;

    String getAlgorithmName();

    int getMacSize();

    void update(byte in) throws IllegalStateException;

    void update(byte[] in, int inOff, int len)
            throws DataLengthException, IllegalStateException;

    int doFinal(byte[] out, int outOff)
            throws DataLengthException, IllegalStateException;

    void reset();
}
