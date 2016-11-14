all:
	@$(MAKE) $(CURDIR)/bin/Debug/asm-info.exe
	@$(MAKE) install

$(CURDIR)/bin/Debug/asm-info.exe:
	@xbuild /nologo /verbosity:quiet

install: $(HOME)/bin/asm-info

$(HOME)/bin/asm-info:
	@echo "#!/bin/bash -e" > $@
	@echo "" >> $@
	@echo 'mono --debug $(CURDIR)/bin/Debug/asm-info.exe "$$@"' >> $@
	@chmod +x $@
	@echo Created $@

.PHONY: $(HOME)/bin/asm-info
