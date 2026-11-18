package org.rssys.gost.pkix;

import java.nio.file.Path;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("Имя логгера pkix равно FQCN класса")
class LoggerNameContractTest {

    @Test
    void loggerNamesMatchClasses() throws Exception {
        LoggerNameContract.assertNamesMatchClasses(Path.of("src/main/java"));
    }
}
