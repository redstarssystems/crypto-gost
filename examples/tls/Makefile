MVN ?= mvn
Q   = -q
SKIP = -DskipTests -Dmaven.javadoc.skip=true
FILTER = 2>&1 | grep -v 'warn\|WARN'
CLS = org.rssys.gost.tls13.examples

.PHONY: clean pfx-export

clean:
	rm -rf target

pfx-export:
	@$(MVN) install exec:java $(Q) -am $(SKIP) \
		-Dexec.mainClass="$(CLS).PfxExportExample" \
		-Dexec.args="$(ARGS)" $(FILTER)
