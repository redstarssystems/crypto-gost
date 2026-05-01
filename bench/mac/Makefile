ROOT      := $(realpath $(dir $(lastword $(MAKEFILE_LIST)))/../..)
BENCH_DIR := $(realpath $(dir $(lastword $(MAKEFILE_LIST))))
RES_DIR   := $(BENCH_DIR)/results
VERSION   := $(shell cd $(ROOT) && mvn help:evaluate -Dexpression=project.version -q -DforceStdout 2>/dev/null || echo "unknown")
JAR       := $(BENCH_DIR)/target/benchmarks.jar
JAVA      ?= java
LC_ALL    ?= C
JAVA_OPTS ?= --add-opens java.base/java.lang=ALL-UNNAMED \
             --add-opens java.base/java.util=ALL-UNNAMED \
             --add-opens java.base/java.io=ALL-UNNAMED \
             --add-opens java.base/java.text=ALL-UNNAMED \
             --add-opens java.base/jdk.internal.misc=ALL-UNNAMED

PARSE_AWK = size=$$NF;gsub(/\r/,"",size);gsub(/"/,"",size);score=$$5;gsub(/"/,"",score);err=$$6;gsub(/"/,"",err);b=size+0;printf "%d\t%.2f\t%.2f\n",b,score,err

.PHONY: all build bench bench-gost bench-bc plot plot-cmac plot-hmac256 plot-hmac512 cross-validate cross-validate-openssl clean

all: build bench plot

build: $(JAR)

$(JAR):
	cd $(ROOT) && mvn install -DskipTests -q
	cd $(BENCH_DIR) && mvn -f pom.xml package -q

bench-gost: $(JAR)
	mkdir -p $(RES_DIR)
	@printf '\n\033[1;36m══════════════════════════════════════════════════\033[0m\n'
	@printf '\033[1;36m  crypto-gost v$(VERSION) — CMAC, HMAC-256, HMAC-512\033[0m\n'
	@printf '\033[1;36m══════════════════════════════════════════════════\033[0m\n'
	cd $(BENCH_DIR) && LC_ALL=$(LC_ALL) $(JAVA) $(JAVA_OPTS) -jar $(JAR) \
	    '.*Gost' \
	    -rf csv -rff results/bench-gost.csv \
	    -o results/bench-gost.log
	@printf '\n\033[1;33m═══════════════════════════════════════════════════════════\033[0m\n'
	@printf '\033[1;33m  CMAC crypto-gost:\033[0m\n'
	@printf '\033[1;33m═══════════════════════════════════════════════════════════\033[0m\n'
	@printf '  %-12s %12s %12s\n' "Размер, б" "Score, ops/s" "Error, ops/s"
	@printf '  %-12s %12s %12s\n' "----------" "-----------" "-----------"
	cd $(BENCH_DIR) && awk -F',' 'NR>1 && index($$1,"cmacGost")>0 {$(PARSE_AWK)}' results/bench-gost.csv | sort -n | tee results/data-cmac-gost.tsv | awk '{printf "  %-10s %10.0f %12.0f\n",$$1" b",$$2,$$3}'
	@printf '\n\033[1;33m═══════════════════════════════════════════════════════════\033[0m\n'
	@printf '\033[1;33m  HMAC-256 crypto-gost:\033[0m\n'
	@printf '\033[1;33m═══════════════════════════════════════════════════════════\033[0m\n'
	@printf '  %-12s %12s %12s\n' "Размер, б" "Score, ops/s" "Error, ops/s"
	@printf '  %-12s %12s %12s\n' "----------" "-----------" "-----------"
	cd $(BENCH_DIR) && awk -F',' 'NR>1 && index($$1,"hmac256Gost")>0 {$(PARSE_AWK)}' results/bench-gost.csv | sort -n | tee results/data-hmac256-gost.tsv | awk '{printf "  %-10s %10.0f %12.0f\n",$$1" b",$$2,$$3}'
	@printf '\n\033[1;33m═══════════════════════════════════════════════════════════\033[0m\n'
	@printf '\033[1;33m  HMAC-512 crypto-gost:\033[0m\n'
	@printf '\033[1;33m═══════════════════════════════════════════════════════════\033[0m\n'
	@printf '  %-12s %12s %12s\n' "Размер, б" "Score, ops/s" "Error, ops/s"
	@printf '  %-12s %12s %12s\n' "----------" "-----------" "-----------"
	cd $(BENCH_DIR) && awk -F',' 'NR>1 && index($$1,"hmac512Gost")>0 {$(PARSE_AWK)}' results/bench-gost.csv | sort -n | tee results/data-hmac512-gost.tsv | awk '{printf "  %-10s %10.0f %12.0f\n",$$1" b",$$2,$$3}'

bench-bc: $(JAR)
	mkdir -p $(RES_DIR)
	@printf '\n\033[1;36m══════════════════════════════════════════════════\033[0m\n'
	@printf '\033[1;36m  BouncyCastle 1.83 — CMAC, HMAC-256, HMAC-512\033[0m\n'
	@printf '\033[1;36m══════════════════════════════════════════════════\033[0m\n'
	cd $(BENCH_DIR) && LC_ALL=$(LC_ALL) $(JAVA) $(JAVA_OPTS) -jar $(JAR) \
	    '.*Bc' \
	    -rf csv -rff results/bench-bc.csv \
	    -o results/bench-bc.log
	@printf '\n\033[1;33m═══════════════════════════════════════════════════════════\033[0m\n'
	@printf '\033[1;33m  CMAC BouncyCastle:\033[0m\n'
	@printf '\033[1;33m═══════════════════════════════════════════════════════════\033[0m\n'
	@printf '  %-12s %12s %12s\n' "Размер, б" "Score, ops/s" "Error, ops/s"
	@printf '  %-12s %12s %12s\n' "----------" "-----------" "-----------"
	cd $(BENCH_DIR) && awk -F',' 'NR>1 && index($$1,"cmacBc")>0 {$(PARSE_AWK)}' results/bench-bc.csv | sort -n | tee results/data-cmac-bc.tsv | awk '{printf "  %-10s %10.0f %12.0f\n",$$1" b",$$2,$$3}'
	@printf '\n\033[1;33m═══════════════════════════════════════════════════════════\033[0m\n'
	@printf '\033[1;33m  HMAC-256 BouncyCastle:\033[0m\n'
	@printf '\033[1;33m═══════════════════════════════════════════════════════════\033[0m\n'
	@printf '  %-12s %12s %12s\n' "Размер, б" "Score, ops/s" "Error, ops/s"
	@printf '  %-12s %12s %12s\n' "----------" "-----------" "-----------"
	cd $(BENCH_DIR) && awk -F',' 'NR>1 && index($$1,"hmac256Bc")>0 {$(PARSE_AWK)}' results/bench-bc.csv | sort -n | tee results/data-hmac256-bc.tsv | awk '{printf "  %-10s %10.0f %12.0f\n",$$1" b",$$2,$$3}'
	@printf '\n\033[1;33m═══════════════════════════════════════════════════════════\033[0m\n'
	@printf '\033[1;33m  HMAC-512 BouncyCastle:\033[0m\n'
	@printf '\033[1;33m═══════════════════════════════════════════════════════════\033[0m\n'
	@printf '  %-12s %12s %12s\n' "Размер, б" "Score, ops/s" "Error, ops/s"
	@printf '  %-12s %12s %12s\n' "----------" "-----------" "-----------"
	cd $(BENCH_DIR) && awk -F',' 'NR>1 && index($$1,"hmac512Bc")>0 {$(PARSE_AWK)}' results/bench-bc.csv | sort -n | tee results/data-hmac512-bc.tsv | awk '{printf "  %-10s %10.0f %12.0f\n",$$1" b",$$2,$$3}'

bench: bench-gost bench-bc
	@printf '\n\033[1;33m═══════════════════════════════════════════════════════════════\033[0m\n'
	@printf '\033[1;33m  Сводка CMAC:\033[0m\n'
	@printf '\033[1;33m═══════════════════════════════════════════════════════════════\033[0m\n'
	@printf '  %-12s %16s %16s\n' "Размер, б" "crypto-gost" "BC 1.83"
	@printf '  %-12s %16s %16s\n' "----------" "-----------" "--------"
	@paste results/data-cmac-gost.tsv results/data-cmac-bc.tsv | \
	    awk '{printf "  %-8s %9.0f ops/s %9.0f ops/s\n",$$1" b",$$2,$$5}'
	@printf '\n\033[1;33m═══════════════════════════════════════════════════════════════\033[0m\n'
	@printf '\033[1;33m  Сводка HMAC-256:\033[0m\n'
	@printf '\033[1;33m═══════════════════════════════════════════════════════════════\033[0m\n'
	@printf '  %-12s %16s %16s\n' "Размер, б" "crypto-gost" "BC 1.83"
	@printf '  %-12s %16s %16s\n' "----------" "-----------" "--------"
	@paste results/data-hmac256-gost.tsv results/data-hmac256-bc.tsv | \
	    awk '{printf "  %-8s %9.0f ops/s %9.0f ops/s\n",$$1" b",$$2,$$5}'
	@printf '\n\033[1;33m═══════════════════════════════════════════════════════════════\033[0m\n'
	@printf '\033[1;33m  Сводка HMAC-512:\033[0m\n'
	@printf '\033[1;33m═══════════════════════════════════════════════════════════════\033[0m\n'
	@printf '  %-12s %16s %16s\n' "Размер, б" "crypto-gost" "BC 1.83"
	@printf '  %-12s %16s %16s\n' "----------" "-----------" "--------"
	@paste results/data-hmac512-gost.tsv results/data-hmac512-bc.tsv | \
	    awk '{printf "  %-8s %9.0f ops/s %9.0f ops/s\n",$$1" b",$$2,$$5}'

# ---------------------------------------------------------------
# Графики (gnuplot)
# ---------------------------------------------------------------
plot: plot-cmac plot-hmac256 plot-hmac512

plot-cmac:
	@if [ ! -f $(RES_DIR)/data-cmac-gost.tsv ] || [ ! -f $(RES_DIR)/data-cmac-bc.tsv ]; then \
	    printf '\033[1;31mНет данных CMAC. Запусти make bench-gost и make bench-bc.\033[0m\n'; \
	    exit 1; \
	fi
	@if command -v gnuplot >/dev/null 2>&1; then \
	    cd $(BENCH_DIR) && gnuplot plot-cmac.gp; \
	    printf '\033[1;32mГрафик: results/cmac-throughput.png\033[0m\n'; \
	else \
	    printf '\033[1;31mgnuplot не установлен. Установи:  sudo apt install gnuplot\033[0m\n'; \
	fi

plot-hmac256:
	@if [ ! -f $(RES_DIR)/data-hmac256-gost.tsv ] || [ ! -f $(RES_DIR)/data-hmac256-bc.tsv ]; then \
	    printf '\033[1;31mНет данных HMAC-256. Запусти make bench-gost и make bench-bc.\033[0m\n'; \
	    exit 1; \
	fi
	@if command -v gnuplot >/dev/null 2>&1; then \
	    cd $(BENCH_DIR) && gnuplot plot-hmac256.gp; \
	    printf '\033[1;32mГрафик: results/hmac256-throughput.png\033[0m\n'; \
	else \
	    printf '\033[1;31mgnuplot не установлен. Установи:  sudo apt install gnuplot\033[0m\n'; \
	fi

plot-hmac512:
	@if [ ! -f $(RES_DIR)/data-hmac512-gost.tsv ] || [ ! -f $(RES_DIR)/data-hmac512-bc.tsv ]; then \
	    printf '\033[1;31mНет данных HMAC-512. Запусти make bench-gost и make bench-bc.\033[0m\n'; \
	    exit 1; \
	fi
	@if command -v gnuplot >/dev/null 2>&1; then \
	    cd $(BENCH_DIR) && gnuplot plot-hmac512.gp; \
	    printf '\033[1;32mГрафик: results/hmac512-throughput.png\033[0m\n'; \
	else \
	    printf '\033[1;31mgnuplot не установлен. Установи:  sudo apt install gnuplot\033[0m\n'; \
	fi

# ---------------------------------------------------------------
# Кросс-валидация: crypto-gost ↔ BouncyCastle 1.83
# ---------------------------------------------------------------
cross-validate: $(JAR)
	@printf '\033[1;36m══════════════════════════════════════════════════\033[0m\n'
	@printf '\033[1;36m  crypto-gost v$(VERSION) — CMAC, HMAC-256, HMAC-512\033[0m\n'
	@printf '\033[1;36m══════════════════════════════════════════════════\033[0m\n'
	@printf '\033[1;36m  Кросс-валидация: crypto-gost ↔ BC 1.83\033[0m\n'
	@printf '\033[1;36m══════════════════════════════════════════════════\033[0m\n'
	mkdir -p $(RES_DIR)
	cd $(BENCH_DIR) && $(JAVA) $(JAVA_OPTS) \
	    -cp target/benchmarks.jar org.rssys.bench.MacCrossValidation \
	    | tee results/cross-validate-bc.log

# ---------------------------------------------------------------
# Кросс-валидация: crypto-gost ↔ OpenSSL 3.x (ГОСТ-провайдер)
# ---------------------------------------------------------------
cross-validate-openssl: $(JAR)
	@printf '\033[1;36m══════════════════════════════════════════════════\033[0m\n'
	@printf '\033[1;36m  crypto-gost v$(VERSION) — CMAC, HMAC-256, HMAC-512\033[0m\n'
	@printf '\033[1;36m══════════════════════════════════════════════════\033[0m\n'
	@printf '\033[1;36m  Кросс-валидация: crypto-gost ↔ OpenSSL\033[0m\n'
	@printf '\033[1;36m══════════════════════════════════════════════════\033[0m\n'
	mkdir -p $(RES_DIR)
	cd $(BENCH_DIR) && bash cross-validate-openssl.sh \
	    | tee results/cross-validate-openssl.log

# ---------------------------------------------------------------
# Очистка
# ---------------------------------------------------------------
clean:
	rm -rf $(RES_DIR) $(BENCH_DIR)/target
