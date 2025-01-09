ASM_INFO=$(CURDIR)/bin/Release/native/asm-info

all install: $(ASM_INFO) $(HOME)/bin/asm-info

$(ASM_INFO): $(wildcard *.cs */*.cs)
	@dotnet publish /nologo /verbosity:quiet /p:PublishAot=true

$(HOME)/bin/asm-info: Makefile
	@echo "#!/bin/bash -e" > $@
	@echo "" >> $@
	@echo "$(abspath $(ASM_INFO))" '"$$@"' >> $@
	@chmod +x $@
	@echo Created $@
