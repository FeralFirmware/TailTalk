ELF = target/thumbv6m-none-eabi/release/inktalk
UF2 = inktalk.uf2

.PHONY: all flash clean test

all: $(UF2)

$(UF2): $(ELF)
	elf2uf2-rs $< $@

$(ELF): FORCE
	cargo build --release

flash: $(UF2)
	picotool load -u -v -x -t uf2 $<

test:
	cargo test --target x86_64-unknown-linux-gnu -p localtalk

clean:
	cargo clean
	rm -f $(UF2)

FORCE:
