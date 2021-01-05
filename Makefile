CC=gcc
CFLAGS=-Wall

make:
	$(CC) -ggdb -L/usr/lib/ -lrtr -o bgpsecpg/bgpsecpg lib/bgpsec_structs.h bgpsecpg/bgpsecpg.c
	$(CC) -ggdb -L/usr/lib/ -lrtr -o tests/test_bgpsec_structs lib/bgpsec_structs.h lib/bgpsec_structs.c tests/test_bgpsec_structs.c
	$(CC) -ggdb -L/usr/lib/ -lrtr -o tests/test_generators lib/generators.h lib/generators.c tests/test_generators.c

clean:
	rm -f bgpsecpg/bgpsecpg
	rm -f tests/test_bgpsec_structs
	rm -f tests/test_generators

test:
	./tests/test_bgpsec_structs
	./tests/test_generators
