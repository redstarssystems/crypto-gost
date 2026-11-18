package org.rssys.gost.tls13;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.lang.reflect.Field;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("TlsAlerts: имя и код alert для журнала")
class TlsAlertsTest {

    @Test
    @DisplayName("Известный код: имя и значение")
    void knownCode() {
        assertEquals("bad_certificate", TlsAlerts.name(TlsConstants.ALERT_BAD_CERTIFICATE));
        assertEquals("bad_certificate (42)", TlsAlerts.forLog(TlsConstants.ALERT_BAD_CERTIFICATE));
        assertEquals("close_notify (0)", TlsAlerts.forLog(TlsConstants.CLOSE_NOTIFY));
    }

    @Test
    @DisplayName("Неизвестный код не теряется: unknown и hex")
    void unknownCode() {
        assertEquals("unknown", TlsAlerts.name((byte) 1));
        assertEquals("unknown (0x01)", TlsAlerts.forLog(1));
    }

    @Test
    @DisplayName("У каждого объявленного кода alert есть имя")
    void allDeclaredCodesHaveNames() throws Exception {
        for (Field field : TlsConstants.class.getFields()) {
            if (field.getType() != byte.class) {
                continue;
            }
            String fieldName = field.getName();
            if (!(fieldName.equals("CLOSE_NOTIFY") || fieldName.startsWith("ALERT_"))) {
                continue;
            }
            // ALERT_WARNING и ALERT_FATAL - уровни alert, а не коды описания
            if (fieldName.equals("ALERT_WARNING") || fieldName.equals("ALERT_FATAL")) {
                continue;
            }
            assertNotEquals(
                    "unknown", TlsAlerts.name(field.getByte(null)), "нет имени для " + fieldName);
        }
    }
}
