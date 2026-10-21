# Build all C guests: make -C guest   (needs Homebrew llvm + lld)
EXAMPLES := fib sha256 balance mul

all clean:
	@for e in $(EXAMPLES); do $(MAKE) -C $$e $@ || exit 1; done

.PHONY: all clean
