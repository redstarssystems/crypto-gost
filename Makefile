SHELL := /bin/bash

.PHONY: clean doc format test crossval crossval-cades crossval-full cryptopro-root-install cryptopro-root-remove cryptopro-root-status test-stress-tlssession test-stress-tlssession-mixed fuzz fuzz-all android

ROOT := $(realpath $(dir $(lastword $(MAKEFILE_LIST))))

DUR ?= 300
# Количество параллельных фаззинг-процессов. 1 job ≈ 2GB RSS.
# На 32GB: JOBS=8, на 16GB: JOBS=4, на 8GB: JOBS=2
JOBS ?= 3
MODULES_FUZZ := core tls13 jsse pkix

# Авто-определение FQN fuzz-классов в каждом модуле
FUZZ_CLASSES_core  := $(shell find crypto-gost-core/src/test/java  -name '*FuzzTest.java' | sed 's|.*/java/||; s|\.java$$||; s|/|.|g')
FUZZ_CLASSES_tls13 := $(shell find crypto-gost-tls13/src/test/java -name '*FuzzTest.java' | sed 's|.*/java/||; s|\.java$$||; s|/|.|g')
FUZZ_CLASSES_jsse  := $(shell find crypto-gost-jsse/src/test/java  -name '*FuzzTest.java' | sed 's|.*/java/||; s|\.java$$||; s|/|.|g')
FUZZ_CLASSES_pkix  := $(shell find crypto-gost-pkix/src/test/java  -name '*FuzzTest.java' | sed 's|.*/java/||; s|\.java$$||; s|/|.|g')

# Форматирование Java-кода через Spotless (Google Java Format, стиль AOSP)
format:
	mvn spotless:apply

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

# Кросс-валидация с внешними реализациями (OpenSSL, КриптоПро и др.). Тесты, создающие контейнеры
# КриптоПро, по умолчанию пропускаются: генерация ключа может открыть окно датчика случайных
# чисел (нужно двигать мышью). Использование: make crossval [MVN_ARGS=...]
# -Dcrossval.openssl.requireGostMac=true: на этой машине обязана быть сборка OpenSSL с ГОСТ MAC в PKCS#12;
# без неё проверки PKCS#12 ушли бы в пропуск, а прогон остался бы зелёным
crossval:
	mvn -Pcrossval test -Dexec.skip=true -Dcrossval.openssl.requireGostMac=true $(MVN_ARGS)

# CAdES-проверки КриптоПро с полной цепочкой (-cadesbes/-cadest/-xlongtype1). На время прогона
# в доверенное хранилище uRoot ставится тестовый корень (его ключ лежит в репозитории) и после
# прогона снимается. Нужен доступ к графической сессии (DISPLAY и XAUTHORITY): без него установка
# корня невозможна. Только на машине разработчика, не на боевых машинах.
crossval-cades:
	mvn -Pcrossval -pl x-validation-tests/cadest -am test -Dexec.skip=true \
		-Dcrossval.cryptopro.trustRoot=true -Dtest='CryptoproCAdES*' \
		-Dsurefire.failIfNoSpecifiedTests=false $(MVN_ARGS)

# То же, но с контейнерами КриптоПро. Запускать, когда вы у машины: КриптоПро может
# показать окно «поводите мышью» (перед релизом). Также ставит и снимает тестовый корень в uRoot
# (см. crossval-cades).
crossval-full: crossval-cades
	mvn -Pcrossval test -Dexec.skip=true -Dcrossval.openssl.requireGostMac=true -Dcrossval.cryptopro.containers=true $(MVN_ARGS)

# Операторская установка тестового корня в uRoot (для ручных сценариев вне тестов, например
# генерации вектора). Без явного согласия отказывает: make cryptopro-root-install ROOT_ARGS=--yes
cryptopro-root-install:
	$(call run_root_tool,install $(ROOT_ARGS))

# Аварийная очистка: удаляет тестовый корень из uRoot, если прогон убили и корень остался.
# Удаляет только сертификат с нашим DER; при нескольких сертификатах с тем же keyid ничего не
# удаляет и печатает подсказку (удалить все: make cryptopro-root-remove ROOT_ARGS=--force). Корень
# живого прогона не трогает никогда; снять и его можно только явным ROOT_ARGS=--force-live. Код выхода
# ненулевой, если хоть одна метка не убрана.
cryptopro-root-remove:
	$(call run_root_tool,remove $(ROOT_ARGS))

cryptopro-root-status:
	$(call run_root_tool,status)

# Собирает cadest с зависимостями и запускает операторскую команду CryptoproRootTool. Файл
# classpath пишется в target/ каждого модуля реактора, поэтому результат не зависит от порядка
# модулей; берётся файл cadest (его зависимости из реактора - target/classes, а не устаревшие jar)
define run_root_tool
	@mvn -q -Pcrossval -pl x-validation-tests/cadest -am -DskipTests -Dexec.skip=true \
		test-compile dependency:build-classpath \
		-Dmdep.outputFile=target/root-tool.classpath \
		-Dmdep.includeScope=test
	@java -cp "$$(cat $(ROOT)/x-validation-tests/cadest/target/root-tool.classpath):$(ROOT)/x-validation-tests/cadest/target/test-classes:$(ROOT)/x-validation-tests/cadest/target/classes" \
		org.rssys.gost.crossval.cadest.CryptoproRootTool $(1)
endef

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

# Собрать Android AAR для всех модулей
android:
	./gradlew assembleRelease --no-daemon $(ARGS)

clean:
	find $(ROOT) -type d -name target -exec rm -rf {} + 2>/dev/null
	find $(ROOT) -type d -name build -exec rm -rf {} + 2>/dev/null
	rm -rf $(ROOT)/.gradle
	rm -f $(ROOT)/.flattened-pom.xml
	find $(ROOT) -name 'dependency-reduced-pom.xml' -delete 2>/dev/null
	rm -f $(ROOT)/*.log $(ROOT)/*.orig
	$(MAKE) -s -C bench clean
	$(MAKE) -s -C examples clean
	$(MAKE) -s -C x-validation-tests clean
	# Фаззинг-артефакты (cifuzz корпус, crash-файлы)
	rm -rf $(ROOT)/crypto-gost-core/.cifuzz-corpus \
	       $(ROOT)/crypto-gost-jsse/.cifuzz-corpus \
	       $(ROOT)/crypto-gost-tls13/.cifuzz-corpus \
	       $(ROOT)/crypto-gost-pkix/.cifuzz-corpus
	find $(ROOT) -name 'crash-*' -delete 2>/dev/null
	find $(ROOT)/bench/results -name '*.log' -delete 2>/dev/null
	find $(ROOT) -name '.flattened-pom.xml' -delete 2>/dev/null
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