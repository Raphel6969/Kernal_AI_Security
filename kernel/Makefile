# Makefile for eBPF programs
# Compiles execve_hook.c to execve_hook.o for loading with BCC

# Compiler flags
CLANG ?= clang
LLC ?= llc
OPT ?= opt

# Kernel headers - auto-detect common paths
KERNEL_VERSION := $(shell uname -r)
KERNEL_INCLUDE := /usr/include
KERNEL_SRC := /usr/src/linux-headers-6.8.0-111

# Detect WSL2
IS_WSL2 := $(shell grep -qi "microsoft" /proc/version 2>/dev/null && echo "yes" || echo "no")

# Output directory
OUTPUT := .output

# Source and output files
SRC := execve_hook.c
OBJ := $(OUTPUT)/execve_hook.o

# LLVM flags for eBPF - only used on native Linux
LLVM_CFLAGS := -O2 -target bpf \
	-D__KERNEL__ -D__BPF_TRACING__ \
	-D__BPF_CORE__ \
	-I$(KERNEL_SRC)/include \
	-I$(KERNEL_SRC)/include/uapi \
	-I$(KERNEL_INCLUDE)

# Default target
all: $(OBJ)

# On WSL2, skip compilation (BCC will compile inline)
ifeq ($(IS_WSL2),yes)
$(OBJ):
	@echo "ℹ️  WSL2 detected - skipping eBPF pre-compilation"
	@echo "   BCC will compile the program inline when Python runs"
	@echo "   This is fully supported and preferred on WSL2"
	@mkdir -p $(OUTPUT)
	@touch $(OBJ)
else

# Create output directory
$(OUTPUT):
	mkdir -p $(OUTPUT)

# Compile C to LLVM IR
$(OUTPUT)/%.ll: %.c | $(OUTPUT)
	$(CLANG) $(LLVM_CFLAGS) -c $< -o $@

# Compile LLVM IR to eBPF object
$(OUTPUT)/%.o: $(OUTPUT)/%.ll | $(OUTPUT)
	$(LLC) -march=bpf -filetype=obj -o $@ $<

# Alternative: Direct compile (clang 10+)
$(OUTPUT)/%.o: %.c | $(OUTPUT)
	$(CLANG) $(LLVM_CFLAGS) -c $< -o $@

endif

# Clean build artifacts
clean:
	rm -rf $(OUTPUT)

# Help target
help:
	@echo "eBPF Build System"
	@echo "================="
	@echo "Targets:"
	@echo "  all     - Compile execve_hook.c to execve_hook.o"
	@echo "  clean   - Remove build artifacts"
	@echo "  check   - Verify eBPF tools installed"
	@echo ""
	@echo "Architecture:"
	@echo "  execve_hook.c   - Kernel-space: captures PID/UID/GID/command at execve"
	@echo "  (Python psutil) - User-space:   enriches event with process RSS & system RAM%"
	@echo "  Memory profiling is handled post-ring-buffer in Python (see backend/agent/main.py)"
	@echo ""
	@echo "Environment:"
	@echo "  CLANG   - Clang compiler (default: clang)"
	@echo "  LLC     - LLC compiler (default: llc)"
	@echo ""
	@echo "Output:"
	@echo "  $(OBJ)"

# Check dependencies
check:
	@echo "Checking eBPF build tools..."
	@echo ""
	@echo "Compilers:"
	@command -v $(CLANG) >/dev/null 2>&1 || { echo "❌ clang not found"; exit 1; }
	@command -v $(LLC) >/dev/null 2>&1 || { echo "❌ llc not found"; exit 1; }
	@echo "✓ clang: $$($(CLANG) --version | head -1)"
	@echo "✓ llc: $$($(LLC) --version | head -1)"
	@echo ""
	@echo "System:"
	@echo "✓ Kernel: $$(uname -r)"
	@IS_WSL=$$(grep -qi "microsoft" /proc/version 2>/dev/null && echo "yes" || echo "no"); \
	if [ "$$IS_WSL" = "yes" ]; then \
		echo "⚠️  WSL2 detected - using BCC inline compilation"; \
	fi
	@echo ""
	@echo "Kernel Headers:"
	@if [ -f "/usr/include/linux/sched.h" ]; then \
		echo "✓ /usr/include/linux/sched.h"; \
	else \
		echo "❌ /usr/include/linux/sched.h not found"; \
		exit 1; \
	fi
	@echo ""
	@echo "Python BCC:"
	@python3 -c "from bcc import BPF; print('✓ BCC installed')" || { echo "❌ BCC not installed"; exit 1; }
	@echo ""
	@echo "ℹ️  Note: WSL2 may not have all kernel headers available."
	@echo "   BCC will use inline compilation instead, which is fully supported."

.PHONY: all clean check help
