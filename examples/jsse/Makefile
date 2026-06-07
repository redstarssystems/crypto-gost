MVN ?= mvn
Q   = -q
CLS = org.rssys.gost.jsse.examples
SKIP = -DskipTests -Dmaven.javadoc.skip=true
FILTER = 2>&1 | grep -v 'warn\|WARN'

# Поиск native-image: PATH → JAVA_HOME → /usr/local /opt с проверкой GraalVM 25+
NATIVE ?= $(or \
    $(shell command -v native-image 2>/dev/null), \
    $(shell [ -f "$(JAVA_HOME)/lib/svm/bin/native-image" ] && echo "$(JAVA_HOME)/lib/svm/bin/native-image"), \
    $(shell BIN=$$(find /usr /usr/local /opt -name native-image -type f 2>/dev/null | head -1); \
             if [ -n "$$BIN" ] && $$BIN --version 2>/dev/null | grep -q 'GraalVM 2[5-9]'; then echo "$$BIN"; fi) \
)

.PHONY: netty jetty undertow tomcat springboot test all compile compile-sb clean \
        test-integration test-concurrent test-stress test-undertow-stress test-keymanager test-int-all \
        gost-curl gost-curl-jar gost-curl-native test-server pfx-server

compile:
	$(MVN) compile $(Q) -am

compile-sb: compile
	$(MVN) compile $(Q) -am -Pspringboot

netty:
	@$(MVN) install exec:java $(Q) -am $(SKIP) \
		-Dexec.mainClass="$(CLS).netty.NettyEchoServer" $(FILTER)

jetty:
	@$(MVN) install exec:java $(Q) -am $(SKIP) \
		-Dexec.mainClass="$(CLS).jetty.JettyEchoServer" $(FILTER)

undertow:
	@$(MVN) install exec:java $(Q) -am $(SKIP) \
		-Dexec.mainClass="$(CLS).undertow.UndertowEchoServer" $(FILTER)

tomcat:
	@$(MVN) install exec:java $(Q) -am $(SKIP) \
		-Dexec.mainClass="$(CLS).tomcat.TomcatEchoServer" $(FILTER)

all:
	@for ex in netty jetty undertow tomcat; do \
		echo "=== $$ex ==="; \
		$(MAKE) $$ex; \
	done

springboot:
	$(MVN) -q -Pspringboot spring-boot:run $(FILTER)

test:
	$(MVN) test $(Q) -Pspringboot -am

test-integration:
	$(MVN) test $(Q) -am -Dgroups="integration" -Dsurefire.excludedGroups=

test-concurrent:
	$(MVN) test $(Q) -am -Dtest="ConcurrentHandshakeTest" -Dsurefire.failIfNoSpecifiedTests=false -Dsurefire.excludedGroups=

test-stress:
	$(MVN) test $(Q) -am -Dtest="JsseStressTest#stressTest" -Dsurefire.failIfNoSpecifiedTests=false -Dsurefire.excludedGroups= $(ARGS)

test-undertow-stress:
	$(MVN) test $(Q) -am -Dtest="UndertowStressTest#stressTest" -Dsurefire.failIfNoSpecifiedTests=false -Dsurefire.excludedGroups= $(ARGS)

test-keymanager:
	cd ../../ && $(MVN) test $(Q) -pl crypto-gost-jsse -am -Dtest="GostX509KeyManagerConcurrencyTest" -Dsurefire.failIfNoSpecifiedTests=false -Dsurefire.excludedGroups=

test-int-all:
	cd ../../ && $(MVN) test $(Q) -pl crypto-gost-jsse,examples/jsse -am \
		-Dgroups="integration" -Dsurefire.excludedGroups=

pfx-server:
	@$(MVN) install exec:java $(Q) -am $(SKIP) \
		-Dexec.mainClass="$(CLS).PfxServerExample" \
		-Dexec.args="$(ARGS)" $(FILTER)

gost-curl:
	@$(MVN) install exec:java $(Q) -am $(SKIP) \
		-Dexec.mainClass="$(CLS).GostCurl" \
		-Dexec.args="$(ARGS)" $(FILTER)

# cборка gost-curl в виде jar
gost-curl-jar:
	@$(MVN) package -q -am $(SKIP)
	@echo "Fat JAR: target/gost-curl.jar"
	@java -jar target/gost-curl.jar --help 2>&1 | head -3

# cборка gost-curl в виде jar в виде бинарного исполняемого файла с помощью GraalVM
gost-curl-native: gost-curl-jar
	@$(NATIVE) --no-fallback \
		--enable-all-security-services \
		--initialize-at-run-time=java.security.SecureRandom \
		-jar target/gost-curl.jar \
		-o ../../gost-curl 2>&1 | grep -E 'Build artifacts|Finished|Error'
	@ls -lh ../../gost-curl 2>/dev/null && echo "Native binary: gost-curl" || echo "Build failed"

# Запуск тестового сервера с ГОСТ криптографией для проверки gost-curl и других интеграций.
test-server:
	@$(MVN) install exec:java $(Q) -am $(SKIP) \
		-Dexec.mainClass="$(CLS).GostCurlTestServer" $(FILTER)

clean:
	rm -rf target
