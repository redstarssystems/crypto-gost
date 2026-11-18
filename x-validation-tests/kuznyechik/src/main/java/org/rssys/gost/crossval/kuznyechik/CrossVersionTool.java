package org.rssys.gost.crossval.kuznyechik;

import org.rssys.gost.api.Cipher;
import org.rssys.gost.api.MgmCipher;
import org.rssys.gost.cipher.SymmetricKey;

import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

/**
 * Утилита для кросс-версионной проверки совместимости между разными версиями crypto-gost.
 *
 * <p>Поддерживает два режима работы:
 * <ul>
 *   <li>одноразовый файловый режим (backward compatible CLI);</li>
 *   <li>режим {@code serve} — долгоживущий worker: запросы и ответы бинарным протоколом
 *       через stdin/stdout. Нужен, чтобы не поднимать новую JVM на каждый тестовый кейс.</li>
 * </ul>
 *
 * <p><b>Важный инвариант:</b> при запуске с JAR предыдущей версии на classpath код режима
 * {@code serve} исполняется против API этой версии, а компилируется против текущей. Поэтому
 * здесь допустимо использовать только методы, существующие в предыдущем релизе
 * ({@code Cipher.encrypt/decrypt(data, key, iv, mode[, padding])},
 * {@code MgmCipher.sealWithIcn/open}, {@code SymmetricKey(byte[])}, {@code SymmetricKey.destroy()}).
 * Использование более нового overload-а даст {@code NoSuchMethodError} только в рантайме.
 *
 * <p>Файловый режим:
 * <pre>
 * CrossVersionTool &lt;ctr|cbc|cfb|ofb&gt; &lt;encrypt|decrypt&gt;
 *     &lt;keyHex&gt; &lt;ivHex&gt; &lt;inFile&gt; &lt;outFile&gt;
 * CrossVersionTool mgm &lt;seal|open&gt;
 *     &lt;keyHex&gt; &lt;icnHex&gt; &lt;inFile&gt; &lt;outFile&gt;
 * </pre>
 *
 * IV для CTR: используются первые 8 байт, остальные игнорируются.
 * Padding для CBC: PKCS7 (по умолчанию Cipher).
 */
public class CrossVersionTool {

    /** Версия бинарного протокола режима serve. */
    public static final byte PROTOCOL_VERSION = 1;

    /** Жёсткий лимит размера любого кадра (вход и выход). Fail-closed. */
    public static final int MAX_FRAME_BYTES = 16 * 1024 * 1024;

    /** Операция выполнена успешно. */
    public static final byte STATUS_OK = 0;

    /** Ошибка операции (некорректные данные, провал аутентификации) — worker продолжает работу. */
    public static final byte STATUS_OP_ERROR = 1;

    public static final byte MODE_CTR = 0;
    public static final byte MODE_CBC = 1;
    public static final byte MODE_CFB = 2;
    public static final byte MODE_OFB = 3;
    public static final byte MODE_MGM = 4;

    public static final byte OP_ENCRYPT = 0;
    public static final byte OP_DECRYPT = 1;

    private static final byte[] EMPTY_AAD = new byte[0];

    /** AAD для пустого открытого текста: MGM не обрабатывает пустые P и A одновременно (RFC 9058 §6). */
    private static final byte[] NON_EMPTY_AAD = {1, 2, 3, 4};

    /** Накладные расходы пакета MGM: ICN (16 байт) и тег (16 байт). */
    private static final int MGM_PACKET_OVERHEAD = 32;

    /**
     * AAD для проверки MGM между версиями: пустой, кроме случая пустого открытого текста, где
     * подставляется непустой (иначе текущая версия отвергает сообщение намеренно, RFC 9058 §6).
     * Один и тот же выбор должны делать обе стороны: и worker, и тест.
     *
     * @param plaintextLength длина открытого текста
     * @return AAD для сообщения такой длины
     */
    public static byte[] mgmAadFor(int plaintextLength) {
        return plaintextLength == 0 ? NON_EMPTY_AAD.clone() : EMPTY_AAD;
    }

    public static void main(String[] args) throws Exception {
        if (args.length >= 1 && "serve".equals(args[0])) {
            serve();
            return;
        }

        if (args.length < 6) {
            System.err.println("Использование:");
            System.err.println("  CrossVersionTool <ctr|cbc|cfb|ofb> <encrypt|decrypt>");
            System.err.println("                  <keyHex> <ivHex> <inFile> <outFile>");
            System.err.println("  CrossVersionTool mgm <seal|open>");
            System.err.println("                  <keyHex> <icnHex> <inFile> <outFile>");
            System.err.println("  CrossVersionTool serve");
            System.exit(1);
        }

        String mode = args[0].toLowerCase();

        if ("mgm".equals(mode)) {
            handleMgm(args);
            return;
        }

        boolean encrypt = args[1].equalsIgnoreCase("encrypt");
        byte[] keyBytes = hex(args[2]);
        byte[] iv = hex(args[3]);
        Path inFile = Paths.get(args[4]);
        Path outFile = Paths.get(args[5]);

        byte[] data = Files.readAllBytes(inFile);
        SymmetricKey key = new SymmetricKey(keyBytes);

        Cipher.Mode cipherMode;
        switch (mode) {
            case "ctr":
                cipherMode = Cipher.Mode.CTR;
                if (iv.length > 8) {
                    byte[] truncatedIv = new byte[8];
                    System.arraycopy(iv, 0, truncatedIv, 0, 8);
                    iv = truncatedIv;
                }
                break;
            case "cbc":
                cipherMode = Cipher.Mode.CBC;
                break;
            case "cfb":
                cipherMode = Cipher.Mode.CFB;
                break;
            case "ofb":
                cipherMode = Cipher.Mode.OFB;
                break;
            default:
                System.err.println("Неизвестный режим: " + mode);
                System.exit(1);
                return;
        }

        byte[] result;
        if (encrypt) {
            result = Cipher.encrypt(data, key, iv, cipherMode);
        } else {
            result = Cipher.decrypt(data, key, iv, cipherMode);
        }

        Files.write(outFile, result);
    }

    /**
     * Долгоживущий worker: читает запросы из stdin, отвечает в stdout, пока не получит EOF.
     *
     * <p>Поток протокола изолируется от диагностики: {@code System.out} подменяется на
     * {@code System.err}, поэтому случайный вывод предыдущей версии библиотеки не портит кадры.
     *
     * <p>Ошибка операции возвращается статусом, ошибка фрейминга/IO — фатальна: продолжать
     * на рассинхронизированном потоке нельзя.
     */
    private static void serve() throws IOException {
        PrintStream protocol = System.out;
        System.setOut(System.err);
        DataInputStream in = new DataInputStream(System.in);
        DataOutputStream out = new DataOutputStream(new BufferedOutputStream(protocol));

        while (true) {
            int version = in.read();
            if (version == -1) {
                return;
            }
            if (version != PROTOCOL_VERSION) {
                throw new IOException("Unsupported protocol version: " + version);
            }
            byte modeCode = in.readByte();
            byte opCode = in.readByte();
            byte[] keyBytes = readFrame(in);
            byte[] iv = readFrame(in);
            byte[] payload = readFrame(in);

            try {
                byte[] result = execute(modeCode, opCode, keyBytes, iv, payload);
                try {
                    writeResponse(out, STATUS_OK, result);
                } finally {
                    wipe(result);
                }
            } catch (Exception e) {
                writeResponse(out, STATUS_OP_ERROR, errorMessage(e));
            } finally {
                wipe(keyBytes);
                wipe(iv);
                wipe(payload);
            }
        }
    }

    private static byte[] execute(byte modeCode, byte opCode, byte[] keyBytes, byte[] iv, byte[] payload)
            throws Exception {
        SymmetricKey key = new SymmetricKey(keyBytes);
        byte[] ivUse = iv;
        try {
            if (modeCode == MODE_MGM) {
                if (opCode == OP_ENCRYPT) {
                    return MgmCipher.sealWithIcn(payload, key, iv, mgmAadFor(payload.length));
                }
                return MgmCipher.open(
                        payload, key, mgmAadFor(payload.length - MGM_PACKET_OVERHEAD));
            }
            Cipher.Mode mode = cipherMode(modeCode);
            if (mode == Cipher.Mode.CTR && iv.length > 8) {
                ivUse = Arrays.copyOf(iv, 8);
            }
            if (opCode == OP_ENCRYPT) {
                return Cipher.encrypt(payload, key, ivUse, mode);
            }
            return Cipher.decrypt(payload, key, ivUse, mode);
        } finally {
            if (ivUse != iv) {
                wipe(ivUse);
            }
            key.destroy();
        }
    }

    private static Cipher.Mode cipherMode(byte modeCode) throws IOException {
        switch (modeCode) {
            case MODE_CTR:
                return Cipher.Mode.CTR;
            case MODE_CBC:
                return Cipher.Mode.CBC;
            case MODE_CFB:
                return Cipher.Mode.CFB;
            case MODE_OFB:
                return Cipher.Mode.OFB;
            default:
                throw new IOException("Unknown cipher mode code: " + modeCode);
        }
    }

    private static byte[] readFrame(DataInputStream in) throws IOException {
        int length = in.readInt();
        if (length < 0 || length > MAX_FRAME_BYTES) {
            throw new IOException("Invalid frame length: " + length);
        }
        byte[] data = new byte[length];
        in.readFully(data);
        return data;
    }

    private static void writeResponse(DataOutputStream out, byte status, byte[] body) throws IOException {
        if (body.length > MAX_FRAME_BYTES) {
            throw new IOException("Response frame too large: " + body.length);
        }
        out.writeByte(status);
        out.writeInt(body.length);
        out.write(body);
        out.flush();
    }

    private static byte[] errorMessage(Exception e) {
        String message = e.getMessage();
        String text = e.getClass().getSimpleName() + (message == null ? "" : ": " + message);
        return text.getBytes(StandardCharsets.UTF_8);
    }

    private static void wipe(byte[] data) {
        if (data != null) {
            Arrays.fill(data, (byte) 0);
        }
    }

    /**
     * Обработка MGM subcommand.
     * args: mgm &lt;seal|open&gt; &lt;keyHex&gt; &lt;icnHex&gt; &lt;inFile&gt; &lt;outFile&gt;
     *
     * ICN генерируется случайно на каждый тестовый случай (в CrossVersionTest),
     * не фиксирован — каждый вызов seal с новым ICN, повтора ICN при одном ключе не происходит.
     * AAD пустой (кроме пустого открытого текста, см. {@link #mgmAadFor}) — тест проверяет
     * совместимость ядра MGM, не AAD-обработку.
     */
    private static void handleMgm(String[] args) throws Exception {
        boolean seal = args[1].equalsIgnoreCase("seal");
        byte[] keyBytes = hex(args[2]);
        byte[] icn = hex(args[3]);
        Path inFile = Paths.get(args[4]);
        Path outFile = Paths.get(args[5]);

        SymmetricKey key = new SymmetricKey(keyBytes);
        byte[] data = Files.readAllBytes(inFile);

        byte[] result;
        if (seal) {
            result = MgmCipher.sealWithIcn(data, key, icn, mgmAadFor(data.length));
        } else {
            result = MgmCipher.open(data, key, mgmAadFor(data.length - MGM_PACKET_OVERHEAD));
        }
        Files.write(outFile, result);
    }

    /** Парсит hex-строку в массив байт. */
    static byte[] hex(String s) {
        int len = s.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            out[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return out;
    }
}
