# 
# Copyright (c) 2014 Lithouse, Inc
#

PROG = HAP
CPP_FILES := $(wildcard src/*.cpp)
OBJ_FILES := $(addprefix obj/,$(notdir $(CPP_FILES:.cpp=.o)))

TOP = ../..
CIVETWEB_LIB = libcivetweb.a

CFLAGS = -I$(TOP)/include $(COPT) -std=c++0x
LIBS = /usr/local/lib/libsrp.a -lpthread -lssl -lcrypto -lhogweed -lnettle -lgmp

include $(TOP)/resources/Makefile.in-os


ifeq ($(TARGET_OS),LINUX) 
	LIBS += -ldl
endif

all: $(PROG)

$(PROG): $(CIVETWEB_LIB) $(OBJ_FILES)
	$(CXX) $(LDFLAGS) -o $@ $^ $(CIVETWEB_LIB) $(LIBS)

$(CIVETWEB_LIB):
	$(MAKE) -C $(TOP) clean lib WITH_CPP=1
	cp $(TOP)/$(CIVETWEB_LIB) .

obj/%.o: src/%.cpp
	$(CXX) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(CIVETWEB_LIB) $(PROG) $(OBJ_FILES)

.PHONY: all clean
