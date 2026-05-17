MVN ?= mvn
Q   = -q
CLS = org.rssys.gost.jsse.examples
SKIP = -DskipTests -Dmaven.javadoc.skip=true
FILTER = 2>&1 | grep -v 'warn\|WARN'

.PHONY: netty jetty undertow tomcat springboot test all compile compile-sb clean \
        test-integration test-concurrent test-stress test-undertow-stress test-keymanager test-int-all

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
	$(MVN) test $(Q) -am

test-concurrent:
	$(MVN) test $(Q) -am -Dtest="ConcurrentHandshakeTest" -Dsurefire.failIfNoSpecifiedTests=false

test-stress:
	$(MVN) test $(Q) -am -Dtest="JsseStressTest#stressTest" -Dsurefire.failIfNoSpecifiedTests=false $(ARGS)

test-undertow-stress:
	$(MVN) test $(Q) -am -Dtest="UndertowStressTest#stressTest" -Dsurefire.failIfNoSpecifiedTests=false $(ARGS)

test-keymanager:
	cd ../../ && $(MVN) test $(Q) -pl crypto-gost-jsse -am -Dtest="GostX509KeyManagerConcurrencyTest" -Dsurefire.failIfNoSpecifiedTests=false

test-int-all:
	cd ../../ && $(MVN) test $(Q) -pl crypto-gost-jsse,examples/jsse -am \
		-Dgroups="integration" -DexcludedGroups=""

clean:
	$(MVN) clean $(Q)
