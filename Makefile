# Set paths for Homebrew (adjust if using non-default brew prefix)
BREW_PREFIX := /opt/homebrew
OPENSSL_PREFIX := $(BREW_PREFIX)/opt/openssl@3

INCLUDE_DIRS := -I$(BREW_PREFIX)/include -I$(OPENSSL_PREFIX)/include
LIB_DIRS     := -L$(BREW_PREFIX)/lib -L$(OPENSSL_PREFIX)/lib

SOURCES := $(wildcard *.c src/**/*.c *.cpp src/**/*.cpp)
OBJECTS := $(SOURCES:.c=.o)
OBJECTS := $(OBJECTS:.cpp=.o)
HEADERS := $(wildcard *.h include/*.h)

COMMON   := -std=gnu99 -O2 -Wall -Wformat=2 -Wno-format-nonliteral -DNDEBUG
CFLAGS   := $(CFLAGS) $(COMMON) $(INCLUDE_DIRS)
CXXFLAGS := $(CXXFLAGS) $(COMMON) $(INCLUDE_DIRS)
CC       := gcc
CXX      := g++
LD       := $(CC)
LDFLAGS  := $(LDFLAGS) $(LIB_DIRS)
LDADD    := -lpthread -lcrypto -lgmp $(shell pkg-config --libs gtk+-3.0)
INCLUDE  := $(shell pkg-config --cflags gtk+-3.0)

TARGETS := chat dh-example

IMPL := chat.o
ifdef skel
IMPL := $(IMPL:.o=-skel.o)
endif

.PHONY : all
all : $(TARGETS)

debug : CFLAGS += -g3 -UNDEBUG -O0
debug : CXXFLAGS += -g3 -UNDEBUG -O0
debug : all
.PHONY : debug

chat : $(IMPL) dh.o keys.o util.o
	$(LD) $(LDFLAGS) -o $@ $^ $(LDADD)

dh-example : dh-example.o dh.o keys.o util.o
	$(LD) $(LDFLAGS) -o $@ $^ $(LDADD)

%.o : %.cpp $(HEADERS)
	$(CXX) $(DEFS) $(INCLUDE) $(CXXFLAGS) -c $< -o $@

%.o : %.c $(HEADERS)
	$(CC) $(DEFS) $(INCLUDE) $(CFLAGS) -c $< -o $@

.PHONY : clean
clean :
	rm -f $(TARGETS) $(OBJECTS)

test_sign: test_sign.o dh.o util.o keys.o
	$(LD) $(LDFLAGS) -o $@ $^ $(LDADD)

