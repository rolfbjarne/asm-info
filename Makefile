all install: $(CURDIR)/bin/Debug/asm-info.exe $(HOME)/bin/asm-info

$(CURDIR)/bin/Debug/asm-info.exe: $(wildcard *.cs */*.cs)
	@msbuild /nologo /verbosity:quiet /r

$(HOME)/bin/asm-info: Makefile
	@echo "#!/bin/bash -e" > $@
	@echo "" >> $@
	@echo 'mono --debug $(CURDIR)/bin/Debug/asm-info.exe "$$@"' >> $@
	@chmod +x $@
	@echo Created $@
