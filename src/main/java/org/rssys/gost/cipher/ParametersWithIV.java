package org.rssys.gost.cipher;

public class ParametersWithIV implements CipherParameters {
    private CipherParameters parameters;
    private byte[] iv;

    public ParametersWithIV(CipherParameters parameters, byte[] iv) {
        this(parameters, iv, 0, iv.length);
    }

    public ParametersWithIV(CipherParameters parameters, byte[] iv, int ivOff, int ivLen) {
        this.iv = new byte[ivLen];
        this.parameters = parameters;
        System.arraycopy(iv, ivOff, this.iv, 0, ivLen);
    }

    /**
     * Возвращает копию вектора инициализации (defensive copy).
     * Мутация возвращённого массива не влияет на внутреннее состояние.
     */
    public byte[] getIV() {
        return java.util.Arrays.copyOf(iv, iv.length);
    }

    public CipherParameters getParameters() {
        return parameters;
    }
}
