CC=gcc
CFLAGS=-Wall -Werror -c
STD=c99

all: collections

# create static library
collections: vector.o
	ar rc libCOLLECTIONS.a vector.o
	ranlib libCOLLECTIONS.a

vector.o: vector.c
	$(CC) $(CFLAGS) -std=$(STD) vector.c

clean:
	rm -f *.o *.so *.a

