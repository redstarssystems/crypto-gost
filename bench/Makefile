SUB_DIRS := jsse keys kuznyechik mac signature old-digest tls

.PHONY: clean

clean:
	@for dir in $(SUB_DIRS); do \
	    $(MAKE) -s -C $$dir clean; \
	done
	@echo "All bench directories cleaned."
