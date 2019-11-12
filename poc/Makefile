CORE0=1 # change here to set your core ids for pinning
CORE1=3 # change here to set your core ids for pinning

.PHONY: clean all check_offsets

all: attack victim orchestrator

clean:
	rm -f attack victim orchestrator *.csv

attack: attacker.c skeleton.c pmc.c pmc.h util.h macros.h synch.h
	gcc-4.8 -static -g -O0 ${WITH} -DATTACKER -DNSAMPLES=${NSAMPLES} -DTHRESHOLD=${THRESHOLD} -DUSE_PMC=${USE_PMC} skeleton.c pmc.c -o attack -specs musl-gcc.specs

victim: victim.c   skeleton.c pmc.c pmc.h util.h macros.h synch.h
	gcc-4.8 -static -g -O0 ${WITH}            -DNSAMPLES=${NSAMPLES} -DTHRESHOLD=${THRESHOLD} -DUSE_PMC=${USE_PMC} skeleton.c pmc.c -o victim -specs musl-gcc.specs

orchestrator: orchestrator.c synch.h
	gcc-4.8 -g -O0 -DCORE0=${CORE0} -DCORE1=${CORE1} orchestrator.c -lpthread -lrt -o orchestrator

check_offsets:
	objdump -d attack | egrep '(JUMP|BEG|TARGET|SPECULATE|END).*>:'
	objdump -d victim | egrep '(JUMP|BEG|TARGET|SPECULATE|END).*>:'