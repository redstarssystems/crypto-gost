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

# Версия читается из pom.xml — не прибита гвоздями
VERSION   := $(shell cd $(ROOT) && mvn help:evaluate -Dexpression=project.version -q -DforceStdout 2>/dev/null || echo "unknown")

# Парсит CSV JMH: извлекает score и error в ops/s
# Формат TSV: score_ops  error_ops
PARSE_AWK  = score=$$5;gsub(/\"/,"",score);err=$$6;gsub(/\"/,"",err);printf "%.2f\t%.2f\n",score,err

# Объединяет два TSV (gost + bc) в 4-колоночный файл для gnuplot с error bars
# Формат: label  gost_score  gost_err  bc_score  bc_err
MERGE_AWK_SIGN   = {printf "sign\t%s\t%s\t%s\t%s\n",   $$1, $$2, $$3, $$4}
MERGE_AWK_VERIFY = {printf "verify\t%s\t%s\t%s\t%s\n", $$1, $$2, $$3, $$4}

.PHONY: all build \
        bench-gost-256 bench-bc-256 bench-256 \
        bench-gost-512 bench-bc-512 bench-512 \
        bench-all \
        plot plot-512 clean

all: build bench-256 plot

# ---------------------------------------------------------------
# Сборка: корневой проект → bench uber-jar
# ---------------------------------------------------------------
build: $(JAR)

$(JAR):
	cd $(ROOT) && mvn install -DskipTests -q
	cd $(BENCH_DIR) && mvn -f pom.xml package -q

# ---------------------------------------------------------------
# Бенчмарк 256-бит: crypto-gost
# ---------------------------------------------------------------
bench-gost-256: $(JAR)
	mkdir -p $(RES_DIR)
	@printf '\n\033[1;36m══════════════════════════════════════════════════\033[0m\n'
	@printf '\033[1;36m  crypto-gost v$(VERSION) — подпись ECGOST-256 (CryptoPro-A)\033[0m\n'
	@printf '\033[1;36m══════════════════════════════════════════════════\033[0m\n'
	cd $(BENCH_DIR) && LC_ALL=$(LC_ALL) $(JAVA) $(JAVA_OPTS) -jar $(JAR) \
	    'SignatureBench\.(sign|verify)Gost' \
	    -p bits=256 \
	    -rf csv -rff results/bench-gost.csv \
	    -o results/bench-gost.log
	@printf '\n\033[1;33m  Sign crypto-gost 256:\033[0m\n'
	@printf '  %-14s %12s\n' "Score, ops/s" "Error, ops/s"
	@printf '  %-14s %12s\n' "------------" "------------"
	cd $(BENCH_DIR) && awk -F',' 'NR>1 && index($$1,"signGost")>0 {$(PARSE_AWK)}' results/bench-gost.csv \
	    | tee results/data-sign-gost.tsv \
	    | awk '{printf "  %12.1f  %12.1f\n",$$1,$$2}'
	@printf '\n\033[1;33m  Verify crypto-gost 256:\033[0m\n'
	@printf '  %-14s %12s\n' "Score, ops/s" "Error, ops/s"
	@printf '  %-14s %12s\n' "------------" "------------"
	cd $(BENCH_DIR) && awk -F',' 'NR>1 && index($$1,"verifyGost")>0 {$(PARSE_AWK)}' results/bench-gost.csv \
	    | tee results/data-verify-gost.tsv \
	    | awk '{printf "  %12.1f  %12.1f\n",$$1,$$2}'

# ---------------------------------------------------------------
# Бенчмарк 256-бит: BouncyCastle 1.83
# ---------------------------------------------------------------
bench-bc-256: $(JAR)
	mkdir -p $(RES_DIR)
	@printf '\n\033[1;36m══════════════════════════════════════════════════\033[0m\n'
	@printf '\033[1;36m  BouncyCastle 1.83 — подпись ECGOST-256 (vs crypto-gost v$(VERSION))\033[0m\n'
	@printf '\033[1;36m══════════════════════════════════════════════════\033[0m\n'
	cd $(BENCH_DIR) && LC_ALL=$(LC_ALL) $(JAVA) $(JAVA_OPTS) -jar $(JAR) \
	    'SignatureBench\.(sign|verify)Bc' \
	    -p bits=256 \
	    -rf csv -rff results/bench-bc.csv \
	    -o results/bench-bc.log
	@printf '\n\033[1;33m  Sign BouncyCastle 256:\033[0m\n'
	@printf '  %-14s %12s\n' "Score, ops/s" "Error, ops/s"
	@printf '  %-14s %12s\n' "------------" "------------"
	cd $(BENCH_DIR) && awk -F',' 'NR>1 && index($$1,"signBc")>0 {$(PARSE_AWK)}' results/bench-bc.csv \
	    | tee results/data-sign-bc.tsv \
	    | awk '{printf "  %12.1f  %12.1f\n",$$1,$$2}'
	@printf '\n\033[1;33m  Verify BouncyCastle 256:\033[0m\n'
	@printf '  %-14s %12s\n' "Score, ops/s" "Error, ops/s"
	@printf '  %-14s %12s\n' "------------" "------------"
	cd $(BENCH_DIR) && awk -F',' 'NR>1 && index($$1,"verifyBc")>0 {$(PARSE_AWK)}' results/bench-bc.csv \
	    | tee results/data-verify-bc.tsv \
	    | awk '{printf "  %12.1f  %12.1f\n",$$1,$$2}'

# ---------------------------------------------------------------
# Сводка 256-бит
# ---------------------------------------------------------------
bench-256: bench-gost-256 bench-bc-256
	@printf '\n\033[1;33m═══════════════════════════════════════════════════════════════\033[0m\n'
	@printf '\033[1;33m  Сводка (ECGOST-256, CryptoPro-A): crypto-gost v$(VERSION) vs BC 1.83\033[0m\n'
	@printf '\033[1;33m═══════════════════════════════════════════════════════════════\033[0m\n'
	@printf '  %-10s %16s %16s\n' "Операция" "crypto-gost" "BC 1.83"
	@printf '  %-10s %16s %16s\n' "--------" "-----------" "-------"
	@paste results/data-sign-gost.tsv results/data-sign-bc.tsv | \
	    awk '{printf "  %-10s %12.0f ops/s %12.0f ops/s\n","sign",$$1,$$3}'
	@paste results/data-verify-gost.tsv results/data-verify-bc.tsv | \
	    awk '{printf "  %-10s %12.0f ops/s %12.0f ops/s\n","verify",$$1,$$3}'

# ---------------------------------------------------------------
# Бенчмарк 512-бит: crypto-gost
# ---------------------------------------------------------------
bench-gost-512: $(JAR)
	mkdir -p $(RES_DIR)
	@printf '\n\033[1;36m══════════════════════════════════════════════════\033[0m\n'
	@printf '\033[1;36m  crypto-gost v$(VERSION) — подпись ECGOST-512 (TC26-A-512)\033[0m\n'
	@printf '\033[1;36m══════════════════════════════════════════════════\033[0m\n'
	cd $(BENCH_DIR) && LC_ALL=$(LC_ALL) $(JAVA) $(JAVA_OPTS) -jar $(JAR) \
	    'SignatureBench\.(sign|verify)Gost' \
	    -p bits=512 \
	    -rf csv -rff results/bench-gost-512.csv \
	    -o results/bench-gost-512.log
	@printf '\n\033[1;33m  Sign crypto-gost 512:\033[0m\n'
	@printf '  %-14s %12s\n' "Score, ops/s" "Error, ops/s"
	@printf '  %-14s %12s\n' "------------" "------------"
	cd $(BENCH_DIR) && awk -F',' 'NR>1 && index($$1,"signGost")>0 {$(PARSE_AWK)}' results/bench-gost-512.csv \
	    | tee results/data-sign-gost-512.tsv \
	    | awk '{printf "  %12.1f  %12.1f\n",$$1,$$2}'
	@printf '\n\033[1;33m  Verify crypto-gost 512:\033[0m\n'
	@printf '  %-14s %12s\n' "Score, ops/s" "Error, ops/s"
	@printf '  %-14s %12s\n' "------------" "------------"
	cd $(BENCH_DIR) && awk -F',' 'NR>1 && index($$1,"verifyGost")>0 {$(PARSE_AWK)}' results/bench-gost-512.csv \
	    | tee results/data-verify-gost-512.tsv \
	    | awk '{printf "  %12.1f  %12.1f\n",$$1,$$2}'

# ---------------------------------------------------------------
# Бенчмарк 512-бит: BouncyCastle 1.83
# ---------------------------------------------------------------
bench-bc-512: $(JAR)
	mkdir -p $(RES_DIR)
	@printf '\n\033[1;36m══════════════════════════════════════════════════\033[0m\n'
	@printf '\033[1;36m  BouncyCastle 1.83 — подпись ECGOST-512 (vs crypto-gost v$(VERSION))\033[0m\n'
	@printf '\033[1;36m══════════════════════════════════════════════════\033[0m\n'
	cd $(BENCH_DIR) && LC_ALL=$(LC_ALL) $(JAVA) $(JAVA_OPTS) -jar $(JAR) \
	    'SignatureBench\.(sign|verify)Bc' \
	    -p bits=512 \
	    -rf csv -rff results/bench-bc-512.csv \
	    -o results/bench-bc-512.log
	@printf '\n\033[1;33m  Sign BouncyCastle 512:\033[0m\n'
	@printf '  %-14s %12s\n' "Score, ops/s" "Error, ops/s"
	@printf '  %-14s %12s\n' "------------" "------------"
	cd $(BENCH_DIR) && awk -F',' 'NR>1 && index($$1,"signBc")>0 {$(PARSE_AWK)}' results/bench-bc-512.csv \
	    | tee results/data-sign-bc-512.tsv \
	    | awk '{printf "  %12.1f  %12.1f\n",$$1,$$2}'
	@printf '\n\033[1;33m  Verify BouncyCastle 512:\033[0m\n'
	@printf '  %-14s %12s\n' "Score, ops/s" "Error, ops/s"
	@printf '  %-14s %12s\n' "------------" "------------"
	cd $(BENCH_DIR) && awk -F',' 'NR>1 && index($$1,"verifyBc")>0 {$(PARSE_AWK)}' results/bench-bc-512.csv \
	    | tee results/data-verify-bc-512.tsv \
	    | awk '{printf "  %12.1f  %12.1f\n",$$1,$$2}'

# ---------------------------------------------------------------
# Сводка 512-бит
# ---------------------------------------------------------------
bench-512: bench-gost-512 bench-bc-512
	@printf '\n\033[1;33m═══════════════════════════════════════════════════════════════\033[0m\n'
	@printf '\033[1;33m  Сводка (ECGOST-512, TC26-A-512): crypto-gost v$(VERSION) vs BC 1.83\033[0m\n'
	@printf '\033[1;33m═══════════════════════════════════════════════════════════════\033[0m\n'
	@printf '  %-10s %16s %16s\n' "Операция" "crypto-gost" "BC 1.83"
	@printf '  %-10s %16s %16s\n' "--------" "-----------" "-------"
	@paste results/data-sign-gost-512.tsv results/data-sign-bc-512.tsv | \
	    awk '{printf "  %-10s %12.0f ops/s %12.0f ops/s\n","sign",$$1,$$3}'
	@paste results/data-verify-gost-512.tsv results/data-verify-bc-512.tsv | \
	    awk '{printf "  %-10s %12.0f ops/s %12.0f ops/s\n","verify",$$1,$$3}'

# ---------------------------------------------------------------
# Все бенчмарки
# ---------------------------------------------------------------
bench-all: bench-256 bench-512

# ---------------------------------------------------------------
# Графики 256-бит (gnuplot)
# ---------------------------------------------------------------
plot:
	@if [ ! -f $(RES_DIR)/data-sign-gost.tsv ]   || [ ! -f $(RES_DIR)/data-sign-bc.tsv ] || \
	    [ ! -f $(RES_DIR)/data-verify-gost.tsv ] || [ ! -f $(RES_DIR)/data-verify-bc.tsv ]; then \
	    printf '\033[1;31mНет данных 256-бит. Запусти make bench-256.\033[0m\n'; \
	    exit 1; \
	fi
	@paste $(RES_DIR)/data-sign-gost.tsv   $(RES_DIR)/data-sign-bc.tsv   | awk '$(MERGE_AWK_SIGN)'   > $(RES_DIR)/_data.tsv
	@paste $(RES_DIR)/data-verify-gost.tsv $(RES_DIR)/data-verify-bc.tsv | awk '$(MERGE_AWK_VERIFY)' >> $(RES_DIR)/_data.tsv
	@if command -v gnuplot >/dev/null 2>&1; then \
	    cd $(BENCH_DIR) && gnuplot plot.gp; \
	    printf '\033[1;32mГрафик: results/ecgost256-throughput.png\033[0m\n'; \
	else \
	    printf '\033[1;31mgnuplot не установлен.\033[0m\n'; \
	fi

# ---------------------------------------------------------------
# Графики 512-бит (gnuplot)
# ---------------------------------------------------------------
plot-512:
	@if [ ! -f $(RES_DIR)/data-sign-gost-512.tsv ]   || [ ! -f $(RES_DIR)/data-sign-bc-512.tsv ] || \
	    [ ! -f $(RES_DIR)/data-verify-gost-512.tsv ] || [ ! -f $(RES_DIR)/data-verify-bc-512.tsv ]; then \
	    printf '\033[1;31mНет данных 512-бит. Запусти make bench-512.\033[0m\n'; \
	    exit 1; \
	fi
	@paste $(RES_DIR)/data-sign-gost-512.tsv   $(RES_DIR)/data-sign-bc-512.tsv   | awk '$(MERGE_AWK_SIGN)'   > $(RES_DIR)/_data-512.tsv
	@paste $(RES_DIR)/data-verify-gost-512.tsv $(RES_DIR)/data-verify-bc-512.tsv | awk '$(MERGE_AWK_VERIFY)' >> $(RES_DIR)/_data-512.tsv
	@if command -v gnuplot >/dev/null 2>&1; then \
	    cd $(BENCH_DIR) && gnuplot plot-512.gp; \
	    printf '\033[1;32mГрафик: results/ecgost512-throughput.png\033[0m\n'; \
	else \
	    printf '\033[1;31mgnuplot не установлен.\033[0m\n'; \
	fi

# ---------------------------------------------------------------
# Очистка
# ---------------------------------------------------------------
clean:
	rm -rf $(RES_DIR) $(BENCH_DIR)/target
