#Modify this to point to the PJSIP location.
PJBASE=/home/user/Downloads/pjproject-2.12

include $(PJBASE)/build.mak

CC      = $(PJ_CC)
LDFLAGS = $(PJ_LDFLAGS)
LDLIBS  = $(PJ_LDLIBS)
CFLAGS  = $(PJ_CFLAGS)
CPPFLAGS= ${CFLAGS}


all: sbc

sbc: sbc.o
	$(CC) sbc.o -o sbc -L./vector -lCOLLECTIONS $(LDFLAGS) $(LDLIBS)

sbc.o: sbc.c
	$(CC) -c -g $(CFLAGS) sbc.c

clean:
	rm -f sbc *.o *.so *.a
