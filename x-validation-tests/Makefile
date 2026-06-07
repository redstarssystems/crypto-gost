SUB_DIRS := kuznyechik digest-mac sign keys pkcs12 jsse jsse-server tls13

.PHONY: clean

clean:
	@for dir in $(SUB_DIRS); do \
	    $(MAKE) -s -C $$dir clean; \
	done
	@echo "Все директории x-validation-tests очищены."
