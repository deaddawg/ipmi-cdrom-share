ARCH      = x86_64
EFIINC    = /usr/include/efi
EFILIB    = /usr/lib
GNUEFI    = /usr/lib

CFLAGS    = -I$(EFIINC) -I$(EFIINC)/$(ARCH) -I$(EFIINC)/protocol \
            -fno-stack-protector -fpic -fshort-wchar -mno-red-zone \
            -DEFI_FUNCTION_WRAPPER -Wall -Wextra
LDFLAGS   = -nostdlib -znocombreloc -T /usr/lib/elf_$(ARCH)_efi.lds \
            -shared -Bsymbolic -L$(EFILIB) -L$(GNUEFI) \
            /usr/lib/crt0-efi-$(ARCH).o

all: testiso.iso

cdtest.o: cdtest.c
	gcc $(CFLAGS) -c -o $@ $<

cdtest.so: cdtest.o
	ld $(LDFLAGS) $< -o $@ -lefi -lgnuefi

cdtest.efi: cdtest.so
	objcopy -j .text -j .sdata -j .data -j .rodata \
	        -j .dynamic -j .dynsym \
	        -j .rel -j .rela -j .reloc --target=efi-app-$(ARCH) $< $@

# Create ISO with EFI binary in both ISO9660 filesystem AND FAT boot image
testiso.iso: cdtest.efi
	mkdir -p iso_root/EFI/BOOT
	cp cdtest.efi iso_root/EFI/BOOT/BOOTX64.EFI
	dd if=/dev/zero of=iso_root/efi.img bs=1M count=256
	mformat -i iso_root/efi.img -F ::
	mmd -i iso_root/efi.img ::/EFI ::/EFI/BOOT
	mcopy -i iso_root/efi.img cdtest.efi ::/EFI/BOOT/BOOTX64.EFI
	xorriso -as mkisofs \
	  -o $@ \
	  -e efi.img \
	  -no-emul-boot \
	  -isohybrid-gpt-basdat \
	  iso_root
	rm -rf iso_root

clean:
	rm -f cdtest.o cdtest.so cdtest.efi testiso.iso
	rm -rf iso_root
