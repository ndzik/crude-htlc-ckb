TARGET := riscv64-unknown-elf
CC := $(TARGET)-gcc
LD := $(TARGET)-gcc
OBJCOPY := $(TARGET)-objcopy
CFLAGS := -O3 -Ideps/ckb -Ideps/blake2b -Ideps/molecule -I build -Wall -Werror -Wno-nonnull-compare -Wno-unused-function -g
CFLAGSD := -O0 -Ideps/ckb -Ideps/blake2b -Ideps/molecule -I build -Wall -Werror -Wno-nonnull-compare -Wno-unused-function -g
LDFLAGS := -Wl,-static -fdata-sections -ffunction-sections -Wl,--gc-sections
PROTOCOL_HEADER := protocol.h
PROTOCOL_VERSION := d75e4c56ffa40e17fd2fe477da3f98c5578edcd1

# sudo docker run --rm -it -v `pwd`:/code nervos/ckb-riscv-gnu-toolchain:xenial-full-20191209 bash
htlc-contract: htlc.c ${PROTOCOL_HEADER}
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<
	$(OBJCOPY) --only-keep-debug $@ $(subst specs/cells,build,$@.debug)
	$(OBJCOPY) --strip-debug --strip-all $@

htlc-debug: htlc.c ${PROTOCOL_HEADER}
	$(CC) $(CFLAGSD) $(LDFLAGS) -o $@ $<
