ROOT      := $(realpath $(dir $(lastword $(MAKEFILE_LIST)))/../..)
BENCH_DIR := $(realpath $(dir $(lastword $(MAKEFILE_LIST))))
DATA      := $(BENCH_DIR)/data
JAR       := $(BENCH_DIR)/target/crl-bench.jar
JAVA21    ?= /usr/lib/jvm/java-21-openjdk/bin/java
JAVA25    ?= /usr/lib/jvm/java-25-openjdk/bin/java
# Куча генерации: CRL на 4 млн записей строится в памяти построителем
GEN_HEAP  ?= 7g
RUN       = $(JAVA21) -XX:+UseG1GC -XX:-HeapDumpOnOutOfMemoryError -XX:ErrorFile=$(DATA)/hs_err_%p.log -cp $(JAR) org.rssys.bench.crl.CrlBench

# Размеры «0,8 млн» (800 000), «2 млн», «4 млн»; empty - CRL без записей (измерение подписи)
.PHONY: all deps build gen control grid clean

all: deps build gen grid

# Зависимости собираются и устанавливаются заранее: иначе бенчмарк возьмёт устаревшие
# артефакты из ~/.m2 (цель пишет в ~/.m2)
deps:
	cd $(ROOT) && mvn -q install -DskipTests -pl crypto-gost-core,crypto-gost-pkix,crypto-gost-tls13,crypto-gost-jsse -am

build:
	cd $(BENCH_DIR) && mvn -q package -DskipTests

gen: build
	mkdir -p $(DATA)
	$(JAVA21) -Xmx$(GEN_HEAP) -cp $(JAR) org.rssys.bench.crl.CrlBench gen $(DATA) empty 0
	$(JAVA21) -Xmx$(GEN_HEAP) -cp $(JAR) org.rssys.bench.crl.CrlBench gen $(DATA) 800k 800000
	$(JAVA21) -Xmx$(GEN_HEAP) -cp $(JAR) org.rssys.bench.crl.CrlBench gen $(DATA) 2m 2000000
	$(JAVA21) -Xmx$(GEN_HEAP) -cp $(JAR) org.rssys.bench.crl.CrlBench gen $(DATA) 4m 4000000

# Контроль на настоящем CRL: пути передаются параметрами, в репозитории их нет.
#   make control FNS_CRL=/путь/fns.crl FNS_CRT=/путь/fns-issuer.crt
control: build
	@if [ -z "$(FNS_CRL)" ] || [ -z "$(FNS_CRT)" ]; then \
	    echo "КОНТРОЛЬ НЕ ВЫПОЛНЕН: не заданы FNS_CRL и FNS_CRT"; exit 0; \
	fi
	mkdir -p $(DATA)
	{ sha256sum $(FNS_CRL); \
	  $(JAVA21) -Xms4g -Xmx4g -XX:+UseG1GC -cp $(JAR) org.rssys.bench.crl.CrlBench control $(DATA) $(FNS_CRL) $(FNS_CRT); \
	} 2>&1 | tee $(DATA)/control.txt

grid: build
	$(JAVA21) -Xmx512m -cp $(JAR) org.rssys.bench.crl.CrlBench grid $(DATA) $(JAR) $(JAVA21) $(JAVA25)

clean:
	rm -rf target
