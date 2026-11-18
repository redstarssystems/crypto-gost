SUB_DIRS := kuznyechik digest-mac sign keys pkcs12 jsse jsse-server http2 tls13 cms csr cert crl ocsp cadest cadesc cryptopro

.PHONY: clean

clean:
	@for dir in $(SUB_DIRS); do \
	    $(MAKE) -s -C $$dir clean; \
	done
	@echo "Все директории x-validation-tests очищены."
