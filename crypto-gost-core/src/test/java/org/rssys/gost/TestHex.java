package org.rssys.gost;

import java.util.HexFormat;

/** Разбор и вывод шестнадцатеричных строк в тестах: пробельные символы при разборе игнорируются. */
public final class TestHex {

    private static final HexFormat HEX = HexFormat.of();

    private TestHex() {}

    /** Байты из строки hex (любой регистр); пробелы и переводы строк допустимы. */
    public static byte[] bytes(String hex) {
        return HEX.parseHex(hex.replaceAll("\\s+", ""));
    }

    /** Строка hex строчными буквами без разделителей. */
    public static String string(byte[] bytes) {
        return HEX.formatHex(bytes);
    }
}
