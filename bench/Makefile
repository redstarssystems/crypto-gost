SUB_DIRS := keys kuznyechik mac signature

.PHONY: clean

clean:
	@for dir in $(SUB_DIRS); do \
	    $(MAKE) -s -C $$dir clean; \
	done
	@echo "All bench directories cleaned."
