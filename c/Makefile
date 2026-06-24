# ADP native C verifier.
#
# Crypto: libsodium. A prebuilt MinGW build is vendored under vendor/libsodium so
# the harness is self-contained on Windows; on a system with libsodium installed,
# override SODIUM_INC / SODIUM_LIB or just rely on -lsodium from the default paths.

CC      ?= gcc
CSTD    ?= -std=c11
CFLAGS  ?= -Wall -Wextra $(CSTD) -O2

# Vendored libsodium (MinGW). Override on systems with a packaged libsodium:
#   make SODIUM_INC= SODIUM_LIB= LDLIBS=-lsodium
SODIUM_INC ?= -Ivendor/libsodium/include
SODIUM_LIB ?= -Lvendor/libsodium/lib
LDLIBS     ?= -lsodium

INCLUDES = $(SODIUM_INC)
LDFLAGS  = $(SODIUM_LIB)

OBJS = agent_disclosure.o cJSON.o conformance_test.o
BIN  = conformance_test

.PHONY: all test clean

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(LDFLAGS) $(LDLIBS)

agent_disclosure.o: agent_disclosure.c agent_disclosure.h cJSON.h
	$(CC) $(CFLAGS) $(INCLUDES) -c agent_disclosure.c -o $@

cJSON.o: cJSON.c cJSON.h
	$(CC) $(CFLAGS) -c cJSON.c -o $@

conformance_test.o: conformance_test.c agent_disclosure.h cJSON.h
	$(CC) $(CFLAGS) $(INCLUDES) -c conformance_test.c -o $@

test: $(BIN)
	./$(BIN)

clean:
	rm -f $(OBJS) $(BIN) $(BIN).exe
