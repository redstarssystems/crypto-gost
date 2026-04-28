ROOT      := $(realpath $(dir $(lastword $(MAKEFILE_LIST)))/../..)
BENCH_DIR := $(realpath $(dir $(lastword $(MAKEFILE_LIST))))
RES_DIR   := $(BENCH_DIR)/results
JAR       := $(BENCH_DIR)/target/benchmarks.jar
JAVA      ?= java
LC_ALL    ?= C
JAVA_OPTS ?= --add-opens java.base/java.lang=ALL-UNNAMED \
             --add-opens java.base/java.util=ALL-UNNAMED \
             --add-opens java.base/java.io=ALL-UNNAMED \
             --add-opens java.base/java.text=ALL-UNNAMED \
             --add-opens java.base/jdk.internal.misc=ALL-UNNAMED

.PHONY: all build cross-validate cross-validate-openssl clean

all: build cross-validate

# ---------------------------------------------------------------
# Сборка: корневой проект -> bench uber-jar
# ---------------------------------------------------------------
build: $(JAR)

$(JAR):
	cd $(ROOT) && mvn install -DskipTests -q
	cd $(BENCH_DIR) && mvn -f pom.xml package -q

# ---------------------------------------------------------------
# Кросс-валидация: crypto-gost <-> BouncyCastle 1.83
# ---------------------------------------------------------------
cross-validate: $(JAR)
	mkdir -p $(RES_DIR)
	@printf '\n\033[1;36m══════════════════════════════════════════════════\033[0m\n'
	@printf '\033[1;36m  \u041A\u0440\u043E\u0441\u0441-\u0432\u0430\u043B\u0438\u0434\u0430\u0446\u0438\u044F: crypto-gost \u2194 BC 1.83\033[0m\n'
	@printf '\033[1;36m  \u041A\u043B\u044E\u0447\u0438: \u0413\u041E\u0421\u0422 \u0420 34.10-2012\033[0m\n'
	@printf '\033[1;36m══════════════════════════════════════════════════\033[0m\n'
	cd $(BENCH_DIR) && $(JAVA) $(JAVA_OPTS) \
	    -cp target/benchmarks.jar org.rssys.bench.KeyCrossValidation \
	    | tee $(RES_DIR)/cross-validate.log

# ---------------------------------------------------------------
# Кросс-валидация: crypto-gost <-> OpenSSL (asn1parse)
# ---------------------------------------------------------------
cross-validate-openssl: $(JAR)
	@printf '\n\033[1;36m══════════════════════════════════════════════════\033[0m\n'
	@printf '\033[1;36m  \u041A\u0440\u043E\u0441\u0441-\u0432\u0430\u043B\u0438\u0434\u0430\u0446\u0438\u044F: crypto-gost \u2194 OpenSSL\033[0m\n'
	@printf '\033[1;36m  DER-\u0441\u0442\u0440\u0443\u043A\u0442\u0443\u0440\u0430 \u043A\u043B\u044E\u0447\u0435\u0439\033[0m\n'
	@printf '\033[1;36m══════════════════════════════════════════════════\033[0m\n'
	cd $(BENCH_DIR) && ./cross-validate-openssl.sh

# ---------------------------------------------------------------
# Очистка
# ---------------------------------------------------------------
clean:
	rm -rf $(RES_DIR) $(BENCH_DIR)/target
