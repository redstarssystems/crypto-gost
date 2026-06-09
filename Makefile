SHELL := /bin/bash

.PHONY: clean doc test test-stress-tlssession test-stress-tlssession-mixed fuzz fuzz-all

ROOT := $(realpath $(dir $(lastword $(MAKEFILE_LIST))))

DUR ?= 300
# Количество параллельных фаззинг-процессов. 1 job ≈ 2GB RSS.
# На 32GB: JOBS=8, на 16GB: JOBS=4, на 8GB: JOBS=2
JOBS ?= 3
MODULES_FUZZ := core tls13 jsse

# Авто-определение FQN fuzz-классов в каждом модуле
FUZZ_CLASSES_core  := $(shell find crypto-gost-core/src/test/java  -name '*FuzzTest.java' | sed 's|.*/java/||; s|\.java$$||; s|/|.|g')
FUZZ_CLASSES_tls13 := $(shell find crypto-gost-tls13/src/test/java -name '*FuzzTest.java' | sed 's|.*/java/||; s|\.java$$||; s|/|.|g')
FUZZ_CLASSES_jsse  := $(shell find crypto-gost-jsse/src/test/java  -name '*FuzzTest.java' | sed 's|.*/java/||; s|\.java$$||; s|/|.|g')

# То же что и mvn test (запуск всех unit-тестов), но с подсчетом их общего количества в конце
test:
	@ret=0; \
	mvn test $(MVN_ARGS) || ret=$$?; \
	total=$$(find */target -name '*.txt' -path '*/surefire-reports/*' \
		-exec grep -h 'Tests run:' {} + 2>/dev/null | \
		awk '{s+=$$3} END {print s+0}'); \
	if [ -n "$$total" ] && [ "$$total" -gt 0 ]; then \
		echo "---"; \
		echo "Total tests across all modules: $$total"; \
	fi; \
	exit $$ret

# Однопоточный throughput TlsSession (Kuznyechik-MGM-Streebog-256)
# Длительность: 5 прогонов × ~20 с ≈ 100 с
test-stress-tlssession:
	mvn test -q -pl crypto-gost-tls13 -am \
		-Dtest="org.rssys.gost.tls13.stress.TlsSessionStreamTest" \
		-Dsurefire.excludedGroups= \
		-Dsurefire.failIfNoSpecifiedTests=false $(ARGS)

# Стресс-тест TlsSession: 4 профиля нагрузки, 5 минут
test-stress-tlssession-mixed:
	mvn test -q -pl crypto-gost-tls13 -am \
		-Dtest="org.rssys.gost.tls13.stress.TlsSessionStressTest#stressTest" \
		-Dsurefire.excludedGroups= \
		-Dsurefire.failIfNoSpecifiedTests=false $(ARGS)

# Фаззинг одного модуля: однократная компиляция, затем xargs -P параллельных JVM.
# DUR  — секунд на каждый @FuzzTest класс (default 300).
# JOBS — параллельных JVM; 1 job ≈ 2GB RSS (default 3).
# Использование: make fuzz MODULE=core DUR=3600 [JOBS=4]
fuzz:
	@classes="$(FUZZ_CLASSES_$(MODULE))"; \
	if [ -z "$$classes" ]; then echo "ERROR: no fuzz classes for MODULE=$(MODULE)"; exit 1; fi; \
	echo "Compiling $(MODULE) once..."; \
	mvn test-compile -pl crypto-gost-$(MODULE) -am -q $(MVN_ARGS); \
	echo "Fuzzing $(MODULE): $$(echo $$classes | wc -w) classes, $(JOBS) parallel, $(DUR)s each..."; \
	rm -f /tmp/fuzz-exit-$(MODULE)-*; \
	for class in $$classes; do echo $$class; done | \
	xargs -P $(JOBS) -I {} sh -c ' \
		log=fuzz-$(MODULE)-$$(echo {} | tr "." "-").log; \
		timeout $(DUR) mvn test -pl crypto-gost-$(MODULE) \
			--no-transfer-progress -Pfuzz -Dtest={} \
			-Dexec.skip=true $(MVN_ARGS) > $$log 2>&1; \
		ec=$$?; \
		echo $$ec > /tmp/fuzz-exit-$(MODULE)-$$(echo {} | tr "." "-"); \
		if [ $$ec -eq 124 ] || [ $$ec -eq 0 ]; then \
			echo "OK: {}"; \
		else \
			echo "FAIL: {} (exit $$ec) — see $$log"; \
		fi'; \
	total_fail=0; \
	for f in /tmp/fuzz-exit-$(MODULE)-*; do \
		[ -f "$$f" ] || continue; \
		ec=$$(cat "$$f"); \
		if [ "$$ec" -ne 0 ] && [ "$$ec" -ne 124 ]; then \
			total_fail=$$((total_fail + 1)); \
		fi; \
	done; \
	rm -f /tmp/fuzz-exit-$(MODULE)-*; \
	exit $$total_fail

# Все три модуля последовательно, классы внутри каждого — параллельно (JOBS JVM).
# RSS под контролем: не более JOBS JVM одновременно.
# Использование: make fuzz-all DUR=3600 [JOBS=4]
fuzz-all:
	@total_fail=0; \
	for m in $(MODULES_FUZZ); do \
		$(MAKE) fuzz MODULE=$$m DUR=$(DUR) JOBS=$(JOBS) MVN_ARGS="$(MVN_ARGS)"; \
		ec=$$?; \
		if [ $$ec -ne 0 ]; then \
			echo "FAIL: module $$m ($$ec classes failed)"; \
			total_fail=$$((total_fail + 1)); \
		else \
			echo "OK: module $$m"; \
		fi; \
	done; \
	exit $$total_fail

clean:
	cd $(ROOT) && mvn clean -q
	$(MAKE) -s -C bench clean
	$(MAKE) -s -C examples clean
	$(MAKE) -s -C x-validation-tests clean
	# Фаззинг-артефакты (cifuzz корпус, crash-файлы)
	rm -rf $(ROOT)/crypto-gost-core/.cifuzz-corpus \
	       $(ROOT)/crypto-gost-jsse/.cifuzz-corpus \
	       $(ROOT)/crypto-gost-tls13/.cifuzz-corpus
	find $(ROOT) -path '*/fuzz*/crash-*' -delete 2>/dev/null
	@echo "All modules cleaned."

doc:
	@for adoc in $$(find $(ROOT) -name '*.adoc' -not -path '*/target/*' -not -path '*/.git/*'); do \
	    dir=$$(dirname $$adoc); \
	    base=$$(basename $$adoc .adoc); \
	    printf '  %s\n' "$$(echo $$adoc | sed 's|$(ROOT)/||')"; \
	    cd $$dir && asciidoc -b docbook "$$base.adoc" \
	        && pandoc -f docbook -t markdown_strict "$$base.xml" -o "$$base.md" \
	        && rm -f "$$base.xml"; \
	done
	@echo "All .adoc -> .md done."