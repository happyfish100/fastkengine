.SUFFIXES: .c .lo

COMPILE = $(CC)  -Wall -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -g -O1 -DDEBUG_FLAG -fPIC
INC_PATH = -I/usr/include -I/usr/local/include -I..
LIB_PATH =  -lfastcommon 
TARGET_LIB = /usr/local/lib

ALL_HEADERS = ../common/fken_proto.h fken_client.h
ALL_LIBS = libfkenclient.so

all: $(ALL_LIBS)

libfkenclient.so: ../common/fken_proto.lo fken_client.lo
	cc -shared -o $@ $^ $(LIB_PATH)

.lo:
	$(COMPILE) -o $@ $<  $(SHARED_OBJS) $(LIB_PATH) $(INC_PATH)
.c:
	$(COMPILE) -o $@ $<  $(ALL_OBJS) $(LIB_PATH) $(INC_PATH)
.c.lo:
	$(COMPILE) -c -o $@ $<  $(INC_PATH)
install:
	mkdir -p $(TARGET_LIB)
	mkdir -p /usr/local/lib
	mkdir -p /usr/local/include/fastken

	install -m 755 $(ALL_LIBS) $(TARGET_LIB)
	cp -f $(ALL_HEADERS) /usr/local/include/fastken/

	if [ ! -e /usr/lib/libfkenclient.so ]; then ln -s $(TARGET_LIB)/libfkenclient.so /usr/lib/libfkenclient.so; fi
clean:
	rm -f *.lo $(ALL_LIBS) $(ALL_PRGS)

