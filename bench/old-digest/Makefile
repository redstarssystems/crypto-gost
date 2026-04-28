ROOT      := $(realpath $(dir $(lastword $(MAKEFILE_LIST)))/../..)
BENCH_DIR := $(realpath $(dir $(lastword $(MAKEFILE_LIST))))
DATA_DIR  := $(BENCH_DIR)/data
RES_DIR   := $(BENCH_DIR)/results
JAR       := $(BENCH_DIR)/target/benchmarks.jar
JAVA      ?= java
LC_ALL    ?= C
JAVA_OPTS ?= --add-opens java.base/java.lang=ALL-UNNAMED \
             --add-opens java.base/java.util=ALL-UNNAMED \
             --add-opens java.base/java.io=ALL-UNNAMED \
             --add-opens java.base/java.text=ALL-UNNAMED \
             --add-opens java.base/jdk.internal.misc=ALL-UNNAMED

DATA_FILES := $(DATA_DIR)/data-1k.bin $(DATA_DIR)/data-10k.bin \
              $(DATA_DIR)/data-100k.bin $(DATA_DIR)/data-1m.bin \
              $(DATA_DIR)/data-10m.bin

.PHONY: all data build bench bench-gost bench-bc verify cross-validate-openssl plot clean

all: data build bench plot

# ---------------------------------------------------------------
# Генерация тестовых данных
# ---------------------------------------------------------------
data: $(DATA_FILES)

$(DATA_DIR)/data-1k.bin:
	mkdir -p $(DATA_DIR)
	dd if=/dev/urandom of=$@ bs=1024 count=1 2>/dev/null

$(DATA_DIR)/data-10k.bin:
	mkdir -p $(DATA_DIR)
	dd if=/dev/urandom of=$@ bs=1024 count=10 2>/dev/null

$(DATA_DIR)/data-100k.bin:
	mkdir -p $(DATA_DIR)
	dd if=/dev/urandom of=$@ bs=1024 count=100 2>/dev/null

$(DATA_DIR)/data-1m.bin:
	mkdir -p $(DATA_DIR)
	dd if=/dev/urandom of=$@ bs=1048576 count=1 2>/dev/null

$(DATA_DIR)/data-10m.bin:
	mkdir -p $(DATA_DIR)
	dd if=/dev/urandom of=$@ bs=1048576 count=10 2>/dev/null

# ---------------------------------------------------------------
# Сборка: корневой проект → bench uber-jar
# ---------------------------------------------------------------
build: $(JAR)

$(JAR):
	cd $(ROOT) && mvn install -DskipTests -q
	cd $(BENCH_DIR) && mvn -f pom.xml package -q

# ---------------------------------------------------------------
# Запуск бенчмарка: crypto-gost
# ---------------------------------------------------------------
bench-gost: data $(JAR)
	mkdir -p $(RES_DIR)
	@printf '\n\033[1;36m══════════════════════════════════════════════════\033[0m\n'
	@printf '\033[1;36m  crypto-gost v0.1.0...\033[0m\n'
	@printf '\033[1;36m══════════════════════════════════════════════════\033[0m\n'
	cd $(BENCH_DIR) && LC_ALL=$(LC_ALL) $(JAVA) $(JAVA_OPTS) -jar $(JAR) \
	    '.*CryptoGost' \
	    -rf csv -rff results/bench-gost.csv \
	    -o results/bench-gost.log
	@printf '\n\033[1;33m═══════════════════════════════════════════════════════════\033[0m\n'
	@printf '\033[1;33m  Результаты crypto-gost:\033[0m\n'
	@printf '\033[1;33m═══════════════════════════════════════════════════════════\033[0m\n'
	@printf '  %-12s %12s %12s\n' "Размер, б" "Score, MB/s" "Error, MB/s"
	@printf '  %-12s %12s %12s\n' "----------" "-----------" "-----------"
	cd $(BENCH_DIR) && awk -F',' 'NR>1{size=$$NF;gsub(/\r/,"",size);gsub(/"/,"",size);score=$$5;gsub(/"/,"",score);err=$$6;gsub(/"/,"",err);if(size=="1k")b=1024;else if(size=="10k")b=10240;else if(size=="100k")b=102400;else if(size=="1m")b=1048576;else if(size=="10m")b=10485760;printf "%d\t%.2f\t%.2f\n",b,score*b/1e6,err*b/1e6}' results/bench-gost.csv | sort -n | tee results/data-gost.tsv | awk '{printf "  %-8s %12.2f %12.2f\n",$$1" b",$$2,$$3}'

# ---------------------------------------------------------------
# Запуск бенчмарка: BouncyCastle 1.83
# ---------------------------------------------------------------
bench-bc: data $(JAR)
	mkdir -p $(RES_DIR)
	@printf '\n\033[1;36m══════════════════════════════════════════════════\033[0m\n'
	@printf '\033[1;36m  BouncyCastle 1.83...\033[0m\n'
	@printf '\033[1;36m══════════════════════════════════════════════════\033[0m\n'
	cd $(BENCH_DIR) && LC_ALL=$(LC_ALL) $(JAVA) $(JAVA_OPTS) -jar $(JAR) \
	    '.*BouncyCastle' \
	    -rf csv -rff results/bench-bc.csv \
	    -o results/bench-bc.log
	@printf '\n\033[1;33m═══════════════════════════════════════════════════════════\033[0m\n'
	@printf '\033[1;33m  Результаты BouncyCastle 1.83:\033[0m\n'
	@printf '\033[1;33m═══════════════════════════════════════════════════════════\033[0m\n'
	@printf '  %-12s %12s %12s\n' "Размер, б" "Score, MB/s" "Error, MB/s"
	@printf '  %-12s %12s %12s\n' "----------" "-----------" "-----------"
	cd $(BENCH_DIR) && awk -F',' 'NR>1{size=$$NF;gsub(/\r/,"",size);gsub(/"/,"",size);score=$$5;gsub(/"/,"",score);err=$$6;gsub(/"/,"",err);if(size=="1k")b=1024;else if(size=="10k")b=10240;else if(size=="100k")b=102400;else if(size=="1m")b=1048576;else if(size=="10m")b=10485760;printf "%d\t%.2f\t%.2f\n",b,score*b/1e6,err*b/1e6}' results/bench-bc.csv | sort -n | tee results/data-bc.tsv | awk '{printf "  %-8s %12.2f %12.2f\n",$$1" b",$$2,$$3}'

# ---------------------------------------------------------------
# Запуск бенчмарка: оба
# ---------------------------------------------------------------
bench: bench-gost bench-bc
	@printf '\n\033[1;33m═══════════════════════════════════════════════════════════════\033[0m\n'
	@printf '\033[1;33m  Сводка:\033[0m\n'
	@printf '\033[1;33m═══════════════════════════════════════════════════════════════\033[0m\n'
	@printf '  %-12s %12s %12s\n' "Размер, б" "crypto-gost" "BC 1.83"
	@printf '  %-12s %12s %12s\n' "----------" "-----------" "--------"
	@paste results/data-gost.tsv results/data-bc.tsv | \
	    awk '{printf "  %-8s %8.1f MB/s %8.1f MB/s\n",$$1" b",$$2,$$5}'

# ---------------------------------------------------------------
# Верификация: сравнение хешей crypto-gost и BouncyCastle
# ---------------------------------------------------------------
verify: data
	@cd $(ROOT) && mvn install -DskipTests -q
	@cd $(BENCH_DIR) && mvn -f pom.xml compile -q
	@mkdir -p $(RES_DIR)
	@cd $(BENCH_DIR) && $(JAVA) -cp "target/classes:$$(mvn -f pom.xml dependency:build-classpath -q -Dmdep.outputFile=/dev/stdout 2>/dev/null)" org.rssys.bench.HashVerify | tee $(RES_DIR)/verify.log

# ---------------------------------------------------------------
# Кросс-валидация: crypto-gost <-> OpenSSL
# ---------------------------------------------------------------
cross-validate-openssl: $(JAR)
	@printf '\033[1;36m══════════════════════════════════════════════════\033[0m\n'
	@printf '\033[1;36m  Кросс-валидация хешей: crypto-gost <-> OpenSSL\033[0m\n'
	@printf '\033[1;36m══════════════════════════════════════════════════\033[0m\n'
	cd $(BENCH_DIR) && ./cross-validate-openssl.sh

# ---------------------------------------------------------------
# График (gnuplot)
# ---------------------------------------------------------------
plot:
	@if [ ! -f $(RES_DIR)/data-gost.tsv ] || [ ! -f $(RES_DIR)/data-bc.tsv ]; then \
	    printf '\033[1;31m✗ Нет данных. Запусти make bench-gost и make bench-bc.\033[0m\n'; \
	    exit 1; \
	fi
	@if command -v gnuplot >/dev/null 2>&1; then \
	    cd $(BENCH_DIR) && gnuplot plot.gp; \
	    printf '\n\033[1;32m✓ График сохранён: results/streebog256-throughput.png\033[0m\n'; \
	else \
	    printf '\n\033[1;31m✗ gnuplot не установлен.\033[0m\n'; \
	    printf '  Установите:  sudo apt install gnuplot  (или brew install gnuplot)\n'; \
	fi

# ---------------------------------------------------------------
# Очистка
# ---------------------------------------------------------------
clean:
	rm -rf $(DATA_DIR) $(RES_DIR) $(BENCH_DIR)/target
