ROOT := $(realpath $(dir $(lastword $(MAKEFILE_LIST))))
REVISION := $(shell grep '<revision>' $(ROOT)/pom.xml | head -1 | \
            sed 's/.*<revision>\(.*\)<\/revision>.*/\1/')

.PHONY: clean doc version

version:
	@mkdir -p $(ROOT)/.mvn
	@printf -- '-Drevision=%s\n' "$(REVISION)" > $(ROOT)/.mvn/maven.config
	@printf '  .mvn/maven.config: revision=%s\n' "$(REVISION)"

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
