

ARCH ?= riscv64


MODE ?= debug
FS_IMG := ./sdcard-rv.img

ifeq ($(ARCH), riscv64)
TARGET := riscv64gc-unknown-none-elf

KERNEL_ELF := target/$(TARGET)/$(MODE)/os

KERNEL_BIN := $(KERNEL_ELF).bin

DISASM_TMP := target/$(TARGET)/$(MODE)/asm
QEMU_EXEC := qemu-system-riscv64 \
	-machine virt \
	-kernel $(KERNEL_ELF) \
	-m 1024M \
	-nographic \
	-smp 1 \
	-bios default \
	-drive file=sdcard-rv.img,if=none,format=raw,id=x0 \
	-device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0 \
	-no-reboot \
	-device virtio-net-device,netdev=net \
	-netdev user,id=net \
	-rtc base=utc \
	-drive file=../disk.img,if=none,format=raw,id=x1 \
	-device virtio-blk-device,drive=x1,bus=virtio-mmio-bus.1
QEMU_EXEC_GDB := qemu-system-riscv64 \
	-machine virt \
	-kernel $(KERNEL_ELF) \
	-m 1024M \
	-nographic \
	-smp 1 \
	-bios default \
	-drive file=sdcard-rv.img,if=none,format=raw,id=x0 \
	-device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0 \
	-no-reboot \
	-device virtio-net-device,netdev=net \
	-netdev user,id=net \
	-rtc base=utc \
	-drive file=../disk.img,if=none,format=raw,id=x1 \
	-device virtio-blk-device,drive=x1,bus=virtio-mmio-bus.1 \
    -s -S 
# Binutils
OBJDUMP := rust-objdump --arch-name=riscv64
OBJCOPY := rust-objcopy --binary-architecture=riscv64
else ifeq ($(ARCH), loongarch64)
TARGET := loongarch64-unknown-none
KERNEL_ELF := target/$(TARGET)/$(MODE)/os

KERNEL_BIN := $(KERNEL_ELF).bin

DISASM_TMP := target/$(TARGET)/$(MODE)/asm
QEMU_EXEC := qemu-system-loongarch64 \
	-kernel $(KERNEL_ELF) \
	-m 1G \
	-nographic \
	-smp 1 \
	-drive file=sdcard-la.img,if=none,format=raw,id=x0 \
	-device virtio-blk-pci,drive=x0 \
	-drive file=../disk-la.img,if=none,format=raw,id=x1 \
	-device virtio-blk-pci,drive=x1 \
	-no-reboot \
	-device virtio-net-pci,netdev=net0 \
	-netdev user,id=net0 \
	-rtc base=utc
QEMU_EXEC_GDB := qemu-system-loongarch64 \
	-kernel $(KERNEL_ELF) \
	-m 1G \
	-nographic \
	-smp 1 \
	-drive file=sdcard-la.img,if=none,format=raw,id=x0 \
	-device virtio-blk-pci,drive=x0 \
	-drive file=../disk-la.img,if=none,format=raw,id=x1 \
	-device virtio-blk-pci,drive=x1 \
	-no-reboot \
	-device virtio-net-pci,netdev=net0 \
	-netdev user,id=net0 \
	-rtc base=utc \
    -s -S 
# Binutils
OBJDUMP := rust-objdump --arch-name=loongarch64
OBJCOPY := rust-objcopy --binary-architecture=loongarch64
else
$(error Unsupported ARCH: $(ARCH))
endif

#FS_IMG := ./fs.img

APPS := ../user/src/bin/*
OFFLINE :=

# BOARD
BOARD := qemu
SBI ?= rustsbi
BOOTLOADER := ../bootloader/$(SBI)-$(BOARD).bin

# KERNEL ENTRY
KERNEL_ENTRY_PA := 0x80200000



# Building mode argument
ifeq ($(MODE), release)
	MODE_ARG := --release
endif

# 测试参数
CHAPTER ?= $(shell git rev-parse --abbrev-ref HEAD | sed -E 's/ch([0-9])/\1/')
TEST ?= 6
BASE ?= 1
# Disassembly
DISASM ?= -x

build:  $(KERNEL_BIN) 


$(KERNEL_BIN): kernel
	@$(OBJCOPY) $(KERNEL_ELF) --strip-all -O binary $@
kernel:
	@echo Platform: $(BOARD)
	@cargo build $(MODE_ARG) --target $(TARGET)
clean:
	@cargo clean

disasm: kernel
	@$(OBJDUMP) $(DISASM) $(KERNEL_ELF) | less

disasm-vim: kernel
	@$(OBJDUMP) $(DISASM) $(KERNEL_ELF) > $(DISASM_TMP)
	@vim $(DISASM_TMP)
	@rm $(DISASM_TMP)

run: run-inner

run-inner: build
	 $(QEMU_EXEC)

gdbserver: build
	 $(QEMU_EXEC_GDB)
		

ifeq ($(ARCH), riscv64)
GDB_PATH := /usr/local/bin/riscv64-unknown-elf-gdb

gdb := $(GDB_PATH)


gdbclient:
	@$(gdb) -ex 'file $(KERNEL_ELF)' -ex 'set arch riscv64' -ex 'target remote localhost:1234'

else ifeq ($(ARCH), loongarch64)
GDB_PATH := /opt/gdb-loongarch64/bin/loongarch64-linux-gnu-gdb
gdb := $(GDB_PATH)
gdbclient:
	@$(gdb) -ex 'file $(KERNEL_ELF)' -ex 'set arch Loongarch64' -ex 'target remote localhost:1234'

else
$(error Unsupported ARCH: $(ARCH))
endif

.PHONY: build env kernel clean disasm disasm-vim run-inner fs-img gdbserver gdbclient
