# esp-engine build. Override CC for cross builds, e.g.
#   make CC=aarch64-linux-gnu-gcc BUILD=build/aarch64 kat
CC      ?= cc
BUILD   ?= build/native
CFLAGS  ?= -O2 -g
override CFLAGS += -std=c11 -D_GNU_SOURCE -Wall -Wextra -Wshadow -Iinclude
LDFLAGS ?=

LIB_SRC := src/aes.c src/gcm.c src/replay.c src/esp.c src/ffi.c
LIB_OBJ := $(LIB_SRC:src/%.c=$(BUILD)/%.o)

.PHONY: all kat lib tools bench test clean
all: lib kat tools bench

$(BUILD)/%.o: src/%.c include/*.h | $(BUILD)
	$(CC) $(CFLAGS) -fPIC -c $< -o $@

$(BUILD):
	mkdir -p $@

lib: $(BUILD)/libesp.a $(BUILD)/libesp.so
$(BUILD)/libesp.a: $(LIB_OBJ)
	$(AR) rcs $@ $^
$(BUILD)/libesp.so: $(LIB_OBJ)
	$(CC) -shared $(LDFLAGS) $^ -o $@

kat: $(BUILD)/test_kat
$(BUILD)/test_kat: tests/test_kat.c $(BUILD)/libesp.a
	$(CC) $(CFLAGS) $< $(BUILD)/libesp.a $(LDFLAGS) -o $@

tools: $(BUILD)/espd
$(BUILD)/espd: tools/espd.c $(BUILD)/libesp.a
	$(CC) $(CFLAGS) $< $(BUILD)/libesp.a $(LDFLAGS) -o $@

bench: $(BUILD)/espbench
$(BUILD)/espbench: bench/espbench.c $(BUILD)/libesp.a
	$(CC) $(CFLAGS) $< $(BUILD)/libesp.a $(LDFLAGS) -lpthread -o $@

test: kat lib
	$(BUILD)/test_kat
	ESP_LIB=$(BUILD)/libesp.so python3 -m pytest -q tests

clean:
	rm -rf build

# The whole pytest suite against an ASan + UBSan build of the library.
asan:
	$(MAKE) BUILD=build/asan CFLAGS="-O1 -g -fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address,undefined" lib kat
	build/asan/test_kat
	ESP_LIB=build/asan/libesp.so ESP_IMPLS=table,hw ASAN_OPTIONS=detect_leaks=0 \
	  LD_PRELOAD="$$($(CC) -print-file-name=libasan.so) $$($(CC) -print-file-name=libubsan.so)" \
	  python3 -m pytest -q -p no:cacheprovider --ignore=tests/test_netns.py tests
# (netns tests are skipped here: LD_PRELOAD would inject ASan into ip/tcpdump/ping too)

# libFuzzer on the inbound path (needs clang), FUZZ_TIME seconds.
FUZZ_TIME ?= 60
fuzz:
	mkdir -p build/fuzz/corpus
	clang -g -O1 -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined \
	  -std=c11 -D_GNU_SOURCE -Iinclude tests/fuzz_decap.c src/aes.c src/gcm.c src/replay.c src/esp.c \
	  -o build/fuzz/fuzz_decap
	build/fuzz/fuzz_decap -max_total_time=$(FUZZ_TIME) -max_len=2048 -print_final_stats=1 build/fuzz/corpus

# Cross-compile the KAT suite and run it under QEMU user-mode.
cross:
	$(MAKE) CC=aarch64-linux-gnu-gcc AR=aarch64-linux-gnu-ar BUILD=build/aarch64 kat
	qemu-aarch64 -L /usr/aarch64-linux-gnu build/aarch64/test_kat
	$(MAKE) CC=riscv64-linux-gnu-gcc AR=riscv64-linux-gnu-ar BUILD=build/riscv64 kat
	qemu-riscv64 -L /usr/riscv64-linux-gnu build/riscv64/test_kat

.PHONY: asan fuzz cross
