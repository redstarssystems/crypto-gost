package org.rssys.gost.jsse;

import java.nio.file.Path;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.LoggerNameContract;

@DisplayName("Имя логгера jsse равно FQCN класса")
class LoggerNameContractTest {

    @Test
    void loggerNamesMatchClasses() throws Exception {
        LoggerNameContract.assertNamesMatchClasses(Path.of("src/main/java"));
    }
}
