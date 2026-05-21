ROOT := $(realpath $(dir $(lastword $(MAKEFILE_LIST))))
REVISION := $(shell grep '<revision>' $(ROOT)/pom.xml | head -1 | \
            sed 's/.*<revision>\(.*\)<\/revision>.*/\1/')

.PHONY: clean doc version test

version:
	@mkdir -p $(ROOT)/.mvn
	@printf -- '-Drevision=%s\n' "$(REVISION)" > $(ROOT)/.mvn/maven.config
	@printf '  .mvn/maven.config: revision=%s\n' "$(REVISION)"

# То же что и mvn test (запуск всех unit-тестов), но с подсчетом их общего количества в конце

test: version
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

clean: version
	cd $(ROOT) && mvn clean -q
	$(MAKE) -s -C bench clean
	$(MAKE) -s -C examples clean
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
