package org.rssys.gost.tls13;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.rssys.gost.tls13.psk.TlsPskHelper;
import org.rssys.gost.util.CryptoRandom;

/**
 * Конструктор ClientHello с произвольным набором PSK identity и намеренными нарушениями структуры.
 *
 * <p>Берёт за основу кадр, который собрал настоящий клиент (все расширения, кроме
 * {@code pre_shared_key} и {@code psk_key_exchange_modes}, сохраняются как есть), и пересобирает
 * PSK-часть. Binder каждой identity считается настоящим {@link TlsPskHelper} по усечённому
 * ClientHello, поэтому корректно собранный кадр проходит проверку сервера. Нужен тестам, которым
 * штатный клиент (одна identity) не даёт построить несколько identity, дубликаты, чужой порядок
 * расширений и битые длины.
 */
public final class PskClientHelloFixture {

    private static final int HANDSHAKE_HEADER = 4;
    private static final int HASH_LEN = TlsConstants.STREEBOG_256_HASH_LEN;

    /** Одна предлагаемая identity: тикет, возраст и PSK, которым считается её binder. */
    public record Identity(byte[] ticket, long obfuscatedAge, byte[] psk) {}

    private record Extension(int type, byte[] data) {}

    private final byte[] preamble;
    private final List<Extension> baseExtensions = new ArrayList<>();
    private final List<Identity> identities = new ArrayList<>();
    private final Map<Integer, Integer> binderLengthOverrides = new HashMap<>();
    private final List<Extension> beforePsk = new ArrayList<>();
    private final List<Extension> afterPsk = new ArrayList<>();
    private byte[] modesData = {0x01, TlsConstants.PSK_DHE_KE};
    private boolean includeModes = true;
    private boolean duplicateModes;
    private boolean duplicatePsk;
    private boolean omitPskExtension;
    private int binderCountDelta;
    private int bindersLengthDelta;
    private byte[] garbageAfterBinders = new byte[0];
    private byte[] transcriptPrefix;
    private int bindersVectorOffset;

    /**
     * @param baseFrame кадр ClientHello, собранный штатным клиентом (с PSK или без него)
     */
    public PskClientHelloFixture(byte[] baseFrame) {
        byte[] body = java.util.Arrays.copyOfRange(baseFrame, HANDSHAKE_HEADER, baseFrame.length);
        int pos = 2 + TlsConstants.RANDOM_LENGTH;
        pos += 1 + (body[pos] & 0xFF);
        pos += 2 + u16(body, pos);
        pos += 1 + (body[pos] & 0xFF);
        int extensionsEnd = pos + 2 + u16(body, pos);
        this.preamble = java.util.Arrays.copyOfRange(body, 0, pos);
        pos += 2;
        while (pos < extensionsEnd) {
            int type = u16(body, pos);
            int length = u16(body, pos + 2);
            if (type != TlsConstants.EXT_PRE_SHARED_KEY
                    && type != TlsConstants.EXT_PSK_KEY_EXCHANGE_MODES) {
                baseExtensions.add(
                        new Extension(
                                type,
                                java.util.Arrays.copyOfRange(body, pos + 4, pos + 4 + length)));
            }
            pos += 4 + length;
        }
    }

    /** Убирает из основы расширение заданного типа (например, signature_algorithms). */
    public PskClientHelloFixture withoutBaseExtension(int type) {
        baseExtensions.removeIf(extension -> extension.type() == type);
        return this;
    }

    /** Заменяет тело расширения основы на заданные байты, в том числе заведомо битые. */
    public PskClientHelloFixture replaceBaseExtension(int type, byte[] data) {
        for (int i = 0; i < baseExtensions.size(); i++) {
            if (baseExtensions.get(i).type() == type) {
                baseExtensions.set(i, new Extension(type, data));
                return this;
            }
        }
        throw new IllegalArgumentException("Extension " + type + " not in base frame");
    }

    /** Добавляет identity в конец списка. */
    public PskClientHelloFixture identity(byte[] ticket, long obfuscatedAge, byte[] psk) {
        identities.add(new Identity(ticket, obfuscatedAge, psk));
        return this;
    }

    /** Заменяет binder с номером {@code index} случайными байтами заданной длины. */
    public PskClientHelloFixture binderLength(int index, int length) {
        binderLengthOverrides.put(index, length);
        return this;
    }

    /** Не добавляет ни {@code pre_shared_key}, ни {@code psk_key_exchange_modes} (ClientHello без PSK). */
    public PskClientHelloFixture withoutPskExtension() {
        omitPskExtension = true;
        return this;
    }

    /** Убирает {@code psk_key_exchange_modes}. */
    public PskClientHelloFixture withoutModes() {
        includeModes = false;
        return this;
    }

    /** Задаёт тело {@code psk_key_exchange_modes} целиком (первый байт - длина списка). */
    public PskClientHelloFixture modes(byte... data) {
        modesData = data.clone();
        return this;
    }

    /** Повторяет {@code psk_key_exchange_modes}. */
    public PskClientHelloFixture duplicateModes() {
        duplicateModes = true;
        return this;
    }

    /** Повторяет {@code pre_shared_key} после первого экземпляра. */
    public PskClientHelloFixture duplicatePsk() {
        duplicatePsk = true;
        return this;
    }

    /** Добавляет расширение после {@code pre_shared_key} (нарушение: он обязан быть последним). */
    public PskClientHelloFixture extensionAfterPsk(int type, byte[] data) {
        afterPsk.add(new Extension(type, data.clone()));
        return this;
    }

    /** Добавляет расширение перед {@code pre_shared_key} (например, повтор типа из основы). */
    public PskClientHelloFixture extensionBeforePsk(int type, byte[] data) {
        beforePsk.add(new Extension(type, data.clone()));
        return this;
    }

    /** Меняет число binder: положительное добавляет случайные, отрицательное убирает с конца. */
    public PskClientHelloFixture binderCountDelta(int delta) {
        binderCountDelta = delta;
        return this;
    }

    /** Искажает заявленную длину вектора binders. */
    public PskClientHelloFixture bindersLengthDelta(int delta) {
        bindersLengthDelta = delta;
        return this;
    }

    /** Дописывает байты после вектора binders внутри расширения. */
    public PskClientHelloFixture garbageAfterBinders(byte[] garbage) {
        garbageAfterBinders = garbage.clone();
        return this;
    }

    /** Считает binder как для второго ClientHello после HRR: с префиксом {@code message_hash || HRR}. */
    public PskClientHelloFixture afterHrr(byte[] prefix) {
        transcriptPrefix = prefix.clone();
        return this;
    }

    /** @return смещение вектора binders во фрейме последнего {@link #build()} */
    public int bindersVectorOffset() {
        return bindersVectorOffset;
    }

    /** Собирает handshake-фрейм ClientHello. */
    public byte[] build() {
        ByteArrayOutputStream before = new ByteArrayOutputStream();
        for (Extension e : baseExtensions) writeExtension(before, e.type(), e.data());
        for (Extension e : beforePsk) writeExtension(before, e.type(), e.data());
        if (includeModes && !omitPskExtension) {
            writeExtension(before, TlsConstants.EXT_PSK_KEY_EXCHANGE_MODES, modesData);
            if (duplicateModes) {
                writeExtension(before, TlsConstants.EXT_PSK_KEY_EXCHANGE_MODES, modesData);
            }
        }

        // pre_shared_key: identities, затем binders (пока нулевые)
        ByteArrayOutputStream ids = new ByteArrayOutputStream();
        for (Identity id : identities) {
            writeU16(ids, id.ticket().length);
            ids.writeBytes(id.ticket());
            writeU32(ids, id.obfuscatedAge());
        }
        int binderCount = Math.max(0, identities.size() + binderCountDelta);
        int[] lengths = new int[binderCount];
        int bindersBytes = 0;
        for (int i = 0; i < binderCount; i++) {
            lengths[i] = binderLengthOverrides.getOrDefault(i, HASH_LEN);
            bindersBytes += 1 + lengths[i];
        }
        byte[] pskData = new byte[2 + ids.size() + 2 + bindersBytes + garbageAfterBinders.length];
        int p = 0;
        pskData[p++] = (byte) (ids.size() >>> 8);
        pskData[p++] = (byte) ids.size();
        System.arraycopy(ids.toByteArray(), 0, pskData, p, ids.size());
        p += ids.size();
        int vectorInData = p;
        int declaredBindersLength = bindersBytes + bindersLengthDelta;
        pskData[p++] = (byte) (declaredBindersLength >>> 8);
        pskData[p++] = (byte) declaredBindersLength;
        int[] binderPositionsInData = new int[binderCount];
        for (int i = 0; i < binderCount; i++) {
            pskData[p++] = (byte) lengths[i];
            binderPositionsInData[i] = p;
            p += lengths[i];
        }
        System.arraycopy(garbageAfterBinders, 0, pskData, p, garbageAfterBinders.length);

        ByteArrayOutputStream extensions = new ByteArrayOutputStream();
        extensions.writeBytes(before.toByteArray());
        int pskDataStart = extensions.size() + 4;
        if (!omitPskExtension) {
            writeExtension(extensions, TlsConstants.EXT_PRE_SHARED_KEY, pskData);
            if (duplicatePsk) {
                writeExtension(extensions, TlsConstants.EXT_PRE_SHARED_KEY, pskData);
            }
        }
        for (Extension e : afterPsk) writeExtension(extensions, e.type(), e.data());

        byte[] extBytes = extensions.toByteArray();
        byte[] frame = new byte[HANDSHAKE_HEADER + preamble.length + 2 + extBytes.length];
        int bodyLength = frame.length - HANDSHAKE_HEADER;
        frame[0] = TlsConstants.HT_CLIENT_HELLO;
        frame[1] = (byte) (bodyLength >>> 16);
        frame[2] = (byte) (bodyLength >>> 8);
        frame[3] = (byte) bodyLength;
        System.arraycopy(preamble, 0, frame, HANDSHAKE_HEADER, preamble.length);
        int extLenPos = HANDSHAKE_HEADER + preamble.length;
        frame[extLenPos] = (byte) (extBytes.length >>> 8);
        frame[extLenPos + 1] = (byte) extBytes.length;
        int extStart = extLenPos + 2;
        System.arraycopy(extBytes, 0, frame, extStart, extBytes.length);

        int framePskData = extStart + pskDataStart;
        bindersVectorOffset = framePskData + vectorInData;
        for (int i = 0; i < binderCount && !omitPskExtension; i++) {
            int at = framePskData + binderPositionsInData[i];
            byte[] binder;
            if (i < identities.size() && !binderLengthOverrides.containsKey(i)) {
                byte[] psk = identities.get(i).psk();
                binder =
                        transcriptPrefix == null
                                ? TlsPskHelper.computeBinder(
                                        frame, bindersVectorOffset, psk, HASH_LEN)
                                : TlsPskHelper.computeBinderAfterHrr(
                                        transcriptPrefix,
                                        frame,
                                        bindersVectorOffset,
                                        psk,
                                        HASH_LEN);
            } else {
                binder = new byte[lengths[i]];
                CryptoRandom.INSTANCE.nextBytes(binder);
            }
            System.arraycopy(binder, 0, frame, at, binder.length);
        }
        return frame;
    }

    private static void writeExtension(ByteArrayOutputStream out, int type, byte[] data) {
        writeU16(out, type);
        writeU16(out, data.length);
        out.writeBytes(data);
    }

    private static void writeU16(ByteArrayOutputStream out, int value) {
        out.write(value >>> 8);
        out.write(value);
    }

    private static void writeU32(ByteArrayOutputStream out, long value) {
        out.write((int) (value >>> 24));
        out.write((int) (value >>> 16));
        out.write((int) (value >>> 8));
        out.write((int) value);
    }

    private static int u16(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }
}
