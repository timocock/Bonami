# makefile for AmigaOS 4.x

CC = vc
CFLAGS = -c99 -O2 -D__USE_INLINE__ -D__USE_BASETYPE__
LDFLAGS = -lamiga -lbonami

all: test_bonami

test_bonami: test_bonami.o
	$(CC) -o $@ $^ $(LDFLAGS)

test_bonami.o: test_bonami.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f test_bonami test_bonami.o 