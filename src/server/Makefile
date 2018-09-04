.SUFFIXES: .c .o

COMPILE = $(CC)  -Wall -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -g -O2 -DDEBUG_FLAG
INC_PATH = -I/usr/local/include -I..
LIB_PATH =  -lfastcommon -lserverframe
TARGET_PATH = /usr/bin
CONFIG_PATH = $(TARGET_CONF_PATH)

ALL_OBJS = wordsegment.o similar_words.o

ALL_PRGS = fastkengined

all: $(ALL_PRGS)

$(ALL_PRGS): $(ALL_OBJS)

.o:
	$(COMPILE) -o $@ $<  $(LIB_PATH) $(INC_PATH)
.c:
	$(COMPILE) -o $@ $<  $(ALL_OBJS) $(LIB_PATH) $(INC_PATH)
.c.o:
	$(COMPILE) -c -o $@ $<  $(INC_PATH)

install:
	mkdir -p $(TARGET_PATH)
	cp -f $(ALL_PRGS) $(TARGET_PATH)
clean:
	rm -f *.o $(ALL_OBJS) $(ALL_PRGS)
