# 
# Copyright (c) 2014 Lithouse, Inc
#

PROG = HAP
C_FILES   := $(wildcard src/*.c) 
CPP_FILES := $(wildcard src/*.cpp)
OBJ_FILES := $(addprefix obj/,$(notdir $(CPP_FILES:.cpp=.o) $(C_FILES:.c=.o)))

TOP = ../..
CIVETWEB_LIB = libcivetweb.a

CFLAGS = -I$(TOP)/include $(COPT) -std=c++0x
LIBS = /usr/local/lib/libsrp.a -lpthread -lssl -lcrypto -lhogweed -lnettle -lgmp lib/ed25519.o lib/curve25519-donna.a lib/poly1305-donna.o -mbits

include $(TOP)/resources/Makefile.in-os


ifeq ($(TARGET_OS),LINUX) 
	LIBS += -ldl
endif

all: $(PROG)

$(PROG): lib/$(CIVETWEB_LIB) $(OBJ_FILES)
	$(CXX) $(LDFLAGS) -o $@ $^ lib/$(CIVETWEB_LIB) $(LIBS)

#$(PROG): $(OBJ_FILES)
#	$(CXX) $(LDFLAGS) -o $@ $^ lib/$(CIVETWEB_LIB) $(LIBS)

lib/$(CIVETWEB_LIB):
	$(MAKE) -C $(TOP) clean lib WITH_CPP=1
	cp $(TOP)/$(CIVETWEB_LIB) lib/

obj/%.o: src/%.cpp
	$(CXX) $(CFLAGS) -c -o $@ $<

obj/%.o: src/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f lib/$(CIVETWEB_LIB) $(PROG)
#	rm -f $(PROG) $(OBJ_FILES)

.PHONY: all clean
