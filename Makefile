.PHONY: clean doc test test-stress-tlssession test-stress-tlssession-mixed

ROOT := $(realpath $(dir $(lastword $(MAKEFILE_LIST))))

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
