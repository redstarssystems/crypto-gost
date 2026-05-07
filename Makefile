ROOT := $(realpath $(dir $(lastword $(MAKEFILE_LIST))))

.PHONY: clean

clean:
	cd $(ROOT) && mvn clean -q
	$(MAKE) -s -C bench clean
	@echo "All modules cleaned."
