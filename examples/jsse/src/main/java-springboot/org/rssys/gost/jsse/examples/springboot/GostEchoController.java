package org.rssys.gost.jsse.examples.springboot;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Минимальный эхо-эндпоинт для проверки интеграции.
 * <p>
 * POST /echo с телом "PING" -> "PONG".
 */
@RestController
public class GostEchoController {

    @PostMapping("/echo")
    public String echo(@RequestBody String body) {
        return "PING".equals(body.trim()) ? "PONG" : "UNKNOWN";
    }
}
