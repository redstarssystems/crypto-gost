ROOT      := $(realpath $(dir $(lastword $(MAKEFILE_LIST)))/../..)
BENCH_DIR := $(realpath $(dir $(lastword $(MAKEFILE_LIST))))
JAR       := $(BENCH_DIR)/target/benchmarks.jar
JAVA      ?= java
LC_ALL    ?= C
JAVA_OPTS ?= --add-opens java.base/java.lang=ALL-UNNAMED \
             --add-opens java.base/java.util=ALL-UNNAMED \
             --add-opens java.base/java.io=ALL-UNNAMED \
             --add-opens java.base/java.text=ALL-UNNAMED \
             --add-opens java.base/jdk.internal.misc=ALL-UNNAMED

.PHONY: all build clean

all: build

# ---------------------------------------------------------------
# Сборка: корневой проект -> bench uber-jar
# ---------------------------------------------------------------
build: $(JAR)

$(JAR):
	cd $(ROOT) && mvn install -DskipTests -q
	cd $(BENCH_DIR) && mvn -f pom.xml package -q

# ---------------------------------------------------------------
# Очистка
# ---------------------------------------------------------------
clean:
	rm -rf $(BENCH_DIR)/target
