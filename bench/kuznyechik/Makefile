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

# Версия читается из pom.xml
VERSION    := $(shell cd $(BENCH_DIR) && mvn help:evaluate -Dexpression=project.version -q -DforceStdout 2>/dev/null || echo "unknown")

DATA_FILES := $(DATA_DIR)/data-1k.bin $(DATA_DIR)/data-10k.bin \
              $(DATA_DIR)/data-100k.bin $(DATA_DIR)/data-1m.bin

# Парсит CSV JMH: score и error переводятся из ops/s → MB/s
# Формат TSV: bytes  score_mb  error_mb
PARSE_AWK  = size=$$NF;gsub(/\r/,"",size);gsub(/"/,"",size);score=$$5;gsub(/"/,"",score);err=$$6;gsub(/"/,"",err);if(size=="1k")b=1024;else if(size=="10k")b=10240;else if(size=="100k")b=102400;else if(size=="1m")b=1048576;printf "%d\t%.2f\t%.2f\n",b,score*b/1e6,err*b/1e6

# Объединяет два TSV-файла (gost + bc) в 4-колоночный файл для gnuplot с error bars
# Формат: label  gost_score  gost_err  bc_score  bc_err
MERGE_AWK  = {b=$$1; if(b==1024)l="1K"; else if(b==10240)l="10K"; else if(b==102400)l="100K"; else if(b==1048576)l="1M"; else l=b; printf "%s\t%.2f\t%.2f\t%.2f\t%.2f\n", l, $$2, $$3, $$5, $$6}

.PHONY: all data build bench bench-gost bench-bc plot plot-ctr plot-cfb cross-validate cross-validate-openssl clean

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

# ---------------------------------------------------------------
# Сборка: корневой проект → bench uber-jar
# ---------------------------------------------------------------
build: $(JAR)

$(JAR):
	cd $(ROOT) && mvn install -DskipTests -q
	cd $(BENCH_DIR) && mvn -f pom.xml package -q

# ---------------------------------------------------------------
# Запуск бенчмарка: crypto-gost (CTR + CFB)
# ---------------------------------------------------------------
bench-gost: data $(JAR)
	mkdir -p $(RES_DIR)
	@printf '\n\033[1;36m══════════════════════════════════════════════════\033[0m\n'
	@printf '\033[1;36m  crypto-gost v$(VERSION) — CTR, CFB\033[0m\n'
	@printf '\033[1;36m══════════════════════════════════════════════════\033[0m\n'
	cd $(BENCH_DIR) && LC_ALL=$(LC_ALL) $(JAVA) $(JAVA_OPTS) -jar $(JAR) \
	    '.*(ctrGost|cfbGost)' \
	    -rf csv -rff results/bench-gost.csv \
	    -o results/bench-gost.log
	@printf '\n\033[1;33m═══════════════════════════════════════════════════════════\033[0m\n'
	@printf '\033[1;33m  CTR crypto-gost v$(VERSION):\033[0m\n'
	@printf '\033[1;33m═══════════════════════════════════════════════════════════\033[0m\n'
	@printf '  %-12s %12s %12s\n' "Размер, б" "Score, MB/s" "Error, MB/s"
	@printf '  %-12s %12s %12s\n' "----------" "-----------" "-----------"
	cd $(BENCH_DIR) && awk -F',' 'NR>1 && index($$1,"ctrGost")>0 {$(PARSE_AWK)}' results/bench-gost.csv | sort -n | tee results/data-ctr-gost.tsv | awk '{printf "  %-8s %12.2f %12.2f\n",$$1" b",$$2,$$3}'
	@printf '\n\033[1;33m═══════════════════════════════════════════════════════════\033[0m\n'
	@printf '\033[1;33m  CFB crypto-gost v$(VERSION):\033[0m\n'
	@printf '\033[1;33m═══════════════════════════════════════════════════════════\033[0m\n'
	@printf '  %-12s %12s %12s\n' "Размер, б" "Score, MB/s" "Error, MB/s"
	@printf '  %-12s %12s %12s\n' "----------" "-----------" "-----------"
	cd $(BENCH_DIR) && awk -F',' 'NR>1 && index($$1,"cfbGost")>0 {$(PARSE_AWK)}' results/bench-gost.csv | sort -n | tee results/data-cfb-gost.tsv | awk '{printf "  %-8s %12.2f %12.2f\n",$$1" b",$$2,$$3}'

# ---------------------------------------------------------------
# Запуск бенчмарка: BouncyCastle 1.83 (CTR + CFB)
# ---------------------------------------------------------------
bench-bc: data $(JAR)
	mkdir -p $(RES_DIR)
	@printf '\n\033[1;36m══════════════════════════════════════════════════\033[0m\n'
	@printf '\033[1;36m  BouncyCastle 1.83 — CTR, CFB (vs crypto-gost v$(VERSION))\033[0m\n'
	@printf '\033[1;36m══════════════════════════════════════════════════\033[0m\n'
	cd $(BENCH_DIR) && LC_ALL=$(LC_ALL) $(JAVA) $(JAVA_OPTS) -jar $(JAR) \
	    '.*(ctrBc|cfbBc)' \
	    -rf csv -rff results/bench-bc.csv \
	    -o results/bench-bc.log
	@printf '\n\033[1;33m═══════════════════════════════════════════════════════════\033[0m\n'
	@printf '\033[1;33m  CTR BouncyCastle:\033[0m\n'
	@printf '\033[1;33m═══════════════════════════════════════════════════════════\033[0m\n'
	@printf '  %-12s %12s %12s\n' "Размер, б" "Score, MB/s" "Error, MB/s"
	@printf '  %-12s %12s %12s\n' "----------" "-----------" "-----------"
	cd $(BENCH_DIR) && awk -F',' 'NR>1 && index($$1,"ctrBc")>0 {$(PARSE_AWK)}' results/bench-bc.csv | sort -n | tee results/data-ctr-bc.tsv | awk '{printf "  %-8s %12.2f %12.2f\n",$$1" b",$$2,$$3}'
	@printf '\n\033[1;33m═══════════════════════════════════════════════════════════\033[0m\n'
	@printf '\033[1;33m  CFB BouncyCastle:\033[0m\n'
	@printf '\033[1;33m═══════════════════════════════════════════════════════════\033[0m\n'
	@printf '  %-12s %12s %12s\n' "Размер, б" "Score, MB/s" "Error, MB/s"
	@printf '  %-12s %12s %12s\n' "----------" "-----------" "-----------"
	cd $(BENCH_DIR) && awk -F',' 'NR>1 && index($$1,"cfbBc")>0 {$(PARSE_AWK)}' results/bench-bc.csv | sort -n | tee results/data-cfb-bc.tsv | awk '{printf "  %-8s %12.2f %12.2f\n",$$1" b",$$2,$$3}'

# ---------------------------------------------------------------
# Запуск бенчмарка: оба + сводка
# ---------------------------------------------------------------
bench: bench-gost bench-bc
	@printf '\n\033[1;33m═══════════════════════════════════════════════════════════════\033[0m\n'
	@printf '\033[1;33m  Сводка CTR:\033[0m\n'
	@printf '\033[1;33m═══════════════════════════════════════════════════════════════\033[0m\n'
	@printf '  %-12s %12s %12s\n' "Размер, б" "crypto-gost" "BC 1.83"
	@printf '  %-12s %12s %12s\n' "----------" "-----------" "--------"
	@paste results/data-ctr-gost.tsv results/data-ctr-bc.tsv | \
	    awk '{printf "  %-8s %8.1f MB/s %8.1f MB/s\n",$$1" b",$$2,$$5}'
	@printf '\n\033[1;33m═══════════════════════════════════════════════════════════════\033[0m\n'
	@printf '\033[1;33m  Сводка CFB:\033[0m\n'
	@printf '\033[1;33m═══════════════════════════════════════════════════════════════\033[0m\n'
	@printf '  %-12s %12s %12s\n' "Размер, б" "crypto-gost" "BC 1.83"
	@printf '  %-12s %12s %12s\n' "----------" "-----------" "--------"
	@paste results/data-cfb-gost.tsv results/data-cfb-bc.tsv | \
	    awk '{printf "  %-8s %8.1f MB/s %8.1f MB/s\n",$$1" b",$$2,$$5}'

# ---------------------------------------------------------------
# Графики (gnuplot)
# ---------------------------------------------------------------
plot: plot-ctr plot-cfb

plot-ctr:
	@if [ ! -f $(RES_DIR)/data-ctr-gost.tsv ] || [ ! -f $(RES_DIR)/data-ctr-bc.tsv ]; then \
	    printf '\033[1;31mНет данных CTR. Запусти make bench-gost и make bench-bc.\033[0m\n'; \
	    exit 1; \
	fi
	@paste $(RES_DIR)/data-ctr-gost.tsv $(RES_DIR)/data-ctr-bc.tsv | \
	    awk '$(MERGE_AWK)' > $(RES_DIR)/_data-ctr.tsv
	@if command -v gnuplot >/dev/null 2>&1; then \
	    cd $(BENCH_DIR) && gnuplot plot-ctr.gp; \
	    printf '\033[1;32mГрафик: results/kuznyechik-ctr-throughput.png\033[0m\n'; \
	else \
	    printf '\033[1;31mgnuplot не установлен.\033[0m\n'; \
	fi

plot-cfb:
	@if [ ! -f $(RES_DIR)/data-cfb-gost.tsv ] || [ ! -f $(RES_DIR)/data-cfb-bc.tsv ]; then \
	    printf '\033[1;31mНет данных CFB. Запусти make bench-gost и make bench-bc.\033[0m\n'; \
	    exit 1; \
	fi
	@paste $(RES_DIR)/data-cfb-gost.tsv $(RES_DIR)/data-cfb-bc.tsv | \
	    awk '$(MERGE_AWK)' > $(RES_DIR)/_data-cfb.tsv
	@if command -v gnuplot >/dev/null 2>&1; then \
	    cd $(BENCH_DIR) && gnuplot plot-cfb.gp; \
	    printf '\033[1;32mГрафик: results/kuznyechik-cfb-throughput.png\033[0m\n'; \
	else \
	    printf '\033[1;31mgnuplot не установлен.\033[0m\n'; \
	fi

# ---------------------------------------------------------------
# Кросс-валидация: crypto-gost <-> BouncyCastle 1.83
# ---------------------------------------------------------------
cross-validate: $(JAR)
	mkdir -p $(RES_DIR)
	@printf '\n\033[1;36m══════════════════════════════════════════════════\033[0m\n'
	@printf '\033[1;36m  Кросс-валидация: crypto-gost <-> BC 1.83\033[0m\n'
	@printf '\033[1;36m══════════════════════════════════════════════════\033[0m\n'
	cd $(BENCH_DIR) && $(JAVA) $(JAVA_OPTS) \
	    -cp target/benchmarks.jar org.rssys.bench.KuznyechikCrossValidation \
	    | tee $(RES_DIR)/cross-validate.log

# ---------------------------------------------------------------
# Кросс-валидация: crypto-gost <-> OpenSSL
# ---------------------------------------------------------------
cross-validate-openssl: $(JAR)
	@printf '\n\033[1;36m══════════════════════════════════════════════════\033[0m\n'
	@printf '\033[1;36m  Кросс-валидация: crypto-gost <-> OpenSSL\033[0m\n'
	@printf '\033[1;36m══════════════════════════════════════════════════\033[0m\n'
	cd $(BENCH_DIR) && ./cross-validate-openssl.sh

# ---------------------------------------------------------------
# Очистка
# ---------------------------------------------------------------
clean:
	rm -rf $(DATA_DIR) $(RES_DIR) $(BENCH_DIR)/target
