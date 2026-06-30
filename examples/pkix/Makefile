MVN ?= mvn
Q   = -q
CLS = org.rssys.gost.pkix.examples
SKIP = -DskipTests -Dmaven.javadoc.skip=true
FILTER = 2>&1 | grep -v 'warn\|WARN'

.PHONY: clean run

clean:
	rm -rf target

run:
	@$(MVN) install exec:java $(Q) -am $(SKIP) \
		-Dexec.mainClass="$(CLS).PkixDemo" $(FILTER)
