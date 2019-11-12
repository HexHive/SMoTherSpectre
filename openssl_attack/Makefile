CORE0=1
CORE1=5

.phony: all
all: attack victim orchestrator

openssl/libcrypto.a: openssl
	cd openssl && ./Configure no-shared linux-x86_64
	make -C openssl build_libs -j

attack_base: src/skeleton.c src/pmc.c src/pmc.h src/synch.h src/synch.c openssl/libcrypto.a Makefile
	gcc -fno-stack-protector -g -DUSE_PMC -DATTACKER src/skeleton.c openssl/libcrypto.a src/pmc.c src/synch.c \
		-o attack_base -lrt -lpthread -ldl -Iopenssl/include -Iopenssl/crypto -Isrc -Wl,--section-start=.text=0x40000

victim_base: src/skeleton.c src/pmc.c src/pmc.h src/synch.h src/synch.c openssl/libcrypto.a Makefile
	gcc -fno-stack-protector -g -DUSE_PMC            src/skeleton.c openssl/libcrypto.a src/pmc.c src/synch.c \
		-o victim_base -lrt -lpthread -ldl -Iopenssl/include -Iopenssl/crypto -Isrc -Wl,--section-start=.text=0x40000

attack: attack_base src/inject_gadget.py
	./src/inject_gadget.py a
	chmod u+x attack

victim: victim_base src/inject_gadget.py
	./src/inject_gadget.py v
	chmod u+x victim

orchestrator: src/orchestrator.c src/synch.c
	gcc -g src/orchestrator.c src/synch.c -DCORE0=${CORE0} -DCORE1=${CORE1} -lpthread -lrt -o orchestrator
	
.phony: clean
clean: 
	rm -f attack victim orchestrator
	rm -drf attack_base victim_base
	rm -f *.csv
	rm -f *.png
	make -C openssl clean
