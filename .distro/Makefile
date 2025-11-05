# Makefile for packaging Cocoon TPM crates as Fedora packages
#
# This Makefile automates the process of:
# 1. Running `cargo package` for each sub-crate
# 2. Generating Fedora spec files using rust2rpm


FEDORA_RELEASE=42

# Workspace root directory
WORKSPACE_ROOT := ..

# Target directory for cargo packages
PACKAGE_DIR := $(WORKSPACE_ROOT)/target/package

# List of crates (directory names in the workspace)
CRATES := \
	cocoonfs-cli \
	crypto \
	storage \
	tpm2-interface \
	utils-async \
	utils-common

# excluded:
# bssl-bare-sys \
# bssl-bare-sys-target-integration \

# Function to extract version from Cargo.toml
# Usage: $(call get-version,crate-dir-name)
get-version = $(shell grep '^version' $(WORKSPACE_ROOT)/$(1)/Cargo.toml | head -1 | sed 's/.*"\(.*\)".*/\1/')

# Function to extract package name from Cargo.toml
# Usage: $(call get-package-name,crate-dir-name)
get-package-name = $(shell grep '^name' $(WORKSPACE_ROOT)/$(1)/Cargo.toml | head -1 | sed 's/.*"\(.*\)".*/\1/')

# Generate .crate file path for a given crate directory
# Usage: $(call get-crate-file,crate-dir-name)
get-crate-file = $(PACKAGE_DIR)/$(call get-package-name,$(1))-$(call get-version,$(1)).crate

# Generate spec file name for a given crate directory
# Usage: $(call get-spec-file,crate-dir-name)
get-spec-file = rust-$(call get-package-name,$(1)).spec

# Build explicit lists of all .crate files and .spec files
CRATE_FILES := $(foreach crate,$(CRATES),$(call get-crate-file,$(crate)))
SPEC_FILES := $(foreach crate,$(CRATES),$(call get-spec-file,$(crate)))

# Generate .srpm target name for a given crate directory
# Usage: $(call get-srpm-target,crate-dir-name)
get-srpm-target = $(call get-package-name,$(1)).srpm

# Generate .rpm target name for a given crate directory
# Usage: $(call get-rpm-target,crate-dir-name)
get-rpm-target = $(call get-package-name,$(1)).rpm

# Generate .copr target name for a given crate directory
# Usage: $(call get-copr-target,crate-dir-name)
get-copr-target = $(call get-package-name,$(1)).copr

# Generate actual SRPM filename for a given crate directory
# Usage: $(call get-srpm-file,crate-dir-name)
# Format: rust-<package>-<version>-1.fc<release>.src.rpm
get-srpm-file = rust-$(call get-package-name,$(1))-$(call get-version,$(1))-1.fc$(FEDORA_RELEASE).src.rpm

# Build list of SRPM, RPM, and COPR phony targets
SRPM_TARGETS := $(foreach crate,$(CRATES),$(call get-srpm-target,$(crate)))
RPM_TARGETS := $(foreach crate,$(CRATES),$(call get-rpm-target,$(crate)))
COPR_TARGETS := $(foreach crate,$(CRATES),$(call get-copr-target,$(crate)))

# Build list of actual SRPM filenames
SRPM_FILES := $(foreach crate,$(CRATES),$(call get-srpm-file,$(crate)))

# Mock configuration
MOCK_CONFIG := fedora-$(FEDORA_RELEASE)-x86_64
MOCK_REPO := https://download.copr.fedorainfracloud.org/results/%40virtmaint-sig/sev-snp-coconut/fedora-$(FEDORA_RELEASE)-x86_64/
RESULT_DIR := $(PWD)

# Copr configuration
COPR_PROJECT := @virtmaint-sig/sev-snp-coconut

# Create mapping variables for secondary expansion
# These map from package names to crate directories, crate files, and versions
# Also create reverse mapping from .crate file paths to crate directories
# And mapping from crate directory name to spec file, SRPM target, RPM target, and COPR target
$(foreach crate,$(CRATES),\
  $(eval PKG_TO_DIR_$(call get-package-name,$(crate)) := $(crate))\
  $(eval PKG_TO_CRATE_$(call get-package-name,$(crate)) := $(call get-crate-file,$(crate)))\
  $(eval PKG_TO_VERSION_$(call get-package-name,$(crate)) := $(call get-version,$(crate)))\
  $(eval PKG_TO_SPEC_$(call get-package-name,$(crate)) := $(call get-spec-file,$(crate)))\
  $(eval PKG_TO_SRPM_FILE_$(call get-package-name,$(crate)) := $(call get-srpm-file,$(crate)))\
  $(eval CRATE_FILE_TO_DIR_$(call get-crate-file,$(crate)) := $(crate))\
  $(eval CRATE_FILE_TO_PKG_$(call get-crate-file,$(crate)) := $(call get-package-name,$(crate)))\
  $(eval DIR_TO_SPEC_$(crate) := $(call get-spec-file,$(crate)))\
  $(eval DIR_TO_SRPM_$(crate) := $(call get-srpm-target,$(crate)))\
  $(eval DIR_TO_RPM_$(crate) := $(call get-rpm-target,$(crate)))\
  $(eval DIR_TO_COPR_$(crate) := $(call get-copr-target,$(crate))))

# Default target: generate all spec files
.PHONY: all
all: $(SPEC_FILES)

# Build all source RPMs
.PHONY: srpms
srpms: $(SRPM_TARGETS)

# Build all binary RPMs
.PHONY: rpms
rpms: $(RPM_TARGETS)

# Upload and build all packages in Copr
.PHONY: coprs
coprs: $(COPR_TARGETS)

# Enable secondary expansion for rules below
.SECONDEXPANSION:

# Rule: .crate files depend on their Cargo.toml
# Uses reverse mapping from .crate file path to crate directory
$(CRATE_FILES): $$(WORKSPACE_ROOT)/$$(CRATE_FILE_TO_DIR_$$@)/Cargo.toml
	@echo "Packaging $(CRATE_FILE_TO_DIR_$@) (version $(call get-version,$(CRATE_FILE_TO_DIR_$@)))..."
	cd $(WORKSPACE_ROOT) && cargo package -p $(CRATE_FILE_TO_PKG_$@) --allow-dirty
	@echo "Created: $@"

# Pattern rule: .spec files depend on their .crate files
# The % captures the package name, and we use the mapping to find the .crate file
$(SPEC_FILES): rust-%.spec: $$(PKG_TO_CRATE_%)
	@echo "Generating spec file for $*..."
	rust2rpm -s -a -t fedora --path $<
	cp $< .
	@echo "Generated: $@"

# Pattern rule: .srpm targets depend on their spec files and .crate files
# The % captures the package name
.PHONY: $(SRPM_TARGETS)
$(SRPM_TARGETS): %.srpm: $$(PKG_TO_SPEC_%) $$(PKG_TO_CRATE_%)
	@echo "Building source RPM for $*..."
	@# Copy .crate file to current directory if not already there
	@cp -u $(PKG_TO_CRATE_$*) . 2>/dev/null || true
	@# Build the source RPM using mock
	mock -r $(MOCK_CONFIG) \
		--addrepo=$(MOCK_REPO) \
		--buildsrpm \
		--spec $(PKG_TO_SPEC_$*) \
		--sources $(PWD) \
		--resultdir $(PWD)
	@echo "Built SRPM for $*"

# Pattern rule: .rpm targets depend on their .srpm targets
# The % captures the package name
# Uses mock chain build which handles dependencies via local repo
.PHONY: $(RPM_TARGETS)
$(RPM_TARGETS): %.rpm: %.srpm
	@echo "Building binary RPM for $*..."
	@# Build the binary RPM using mock with chain build
	mock -r $(MOCK_CONFIG) \
		--addrepo=$(MOCK_REPO) \
		--localrepo=$(RESULT_DIR) \
		--continue \
		--chain $(PKG_TO_SRPM_FILE_$*)
	@echo "Built RPM for $*"

# Pattern rule: .copr targets depend on their SRPM files
# The % captures the package name
# Uploads SRPM to Copr and builds there
.PHONY: $(COPR_TARGETS)
$(COPR_TARGETS): %.copr: $$(PKG_TO_SRPM_FILE_%)
	@echo "Uploading and building SRPM in Copr for $*..."
	@# Upload and build the SRPM in Copr
	copr-cli build $(COPR_PROJECT) $(PKG_TO_SRPM_FILE_$*)
	@echo "Submitted Copr build for $*"

# Convenience phony targets for each crate name
# These allow running "make crypto" instead of "make rust-cocoon-tpm-crypto.spec"
.PHONY: $(CRATES)
$(CRATES): $$(DIR_TO_SPEC_$$@)

# Clean generated files
.PHONY: clean
clean:
	rm -f rust-*.spec *.src.rpm *.rpm *.log

# Clean everything including .crate files copied locally
.PHONY: clean-all
clean-all: clean
	rm -f *.crate

# Clean both generated files and packaged .crate files in workspace
.PHONY: distclean
distclean: clean-all
	rm -rf $(PACKAGE_DIR)

# Print information about crates
.PHONY: info
info:
	@echo "Cocoon TPM Crates:"
	@echo "=================="
	@$(foreach crate,$(CRATES), \
		echo "  $(crate):"; \
		echo "    Package:    $(call get-package-name,$(crate))"; \
		echo "    Version:    $(call get-version,$(crate))"; \
		echo "    Crate:      $(call get-crate-file,$(crate))"; \
		echo "    Spec:       $(call get-spec-file,$(crate))"; \
		echo "    SRPM file:  $(call get-srpm-file,$(crate))"; \
		echo "    SRPM build: $(call get-srpm-target,$(crate))"; \
		echo "    RPM build:  $(call get-rpm-target,$(crate))"; \
		echo "    Copr build: $(call get-copr-target,$(crate))"; \
		echo "";)
	@echo ""
	@echo "All .crate files:"
	@echo "================="
	@echo "$(CRATE_FILES)" | tr ' ' '\n'
	@echo ""
	@echo "All .spec files:"
	@echo "================"
	@echo "$(SPEC_FILES)" | tr ' ' '\n'
	@echo ""
	@echo "All SRPM files:"
	@echo "==============="
	@echo "$(SRPM_FILES)" | tr ' ' '\n'
	@echo ""
	@echo "All SRPM build targets:"
	@echo "======================="
	@echo "$(SRPM_TARGETS)" | tr ' ' '\n'
	@echo ""
	@echo "All RPM build targets:"
	@echo "======================"
	@echo "$(RPM_TARGETS)" | tr ' ' '\n'
	@echo ""
	@echo "All Copr build targets:"
	@echo "======================="
	@echo "$(COPR_TARGETS)" | tr ' ' '\n'
	@echo ""
	@echo "Mock configuration:"
	@echo "==================="
	@echo "  Config:     $(MOCK_CONFIG)"
	@echo "  Repo:       $(MOCK_REPO)"
	@echo "  Result dir: $(RESULT_DIR)"
	@echo ""
	@echo "Copr configuration:"
	@echo "==================="
	@echo "  Project:    $(COPR_PROJECT)"

# Show just the file lists (concise view)
.PHONY: list-files
list-files:
	@echo "CRATE_FILES:"
	@echo "$(CRATE_FILES)" | tr ' ' '\n'
	@echo ""
	@echo "SPEC_FILES:"
	@echo "$(SPEC_FILES)" | tr ' ' '\n'
	@echo ""
	@echo "SRPM_FILES:"
	@echo "$(SRPM_FILES)" | tr ' ' '\n'
	@echo ""
	@echo "SRPM_TARGETS:"
	@echo "$(SRPM_TARGETS)" | tr ' ' '\n'
	@echo ""
	@echo "RPM_TARGETS:"
	@echo "$(RPM_TARGETS)" | tr ' ' '\n'
	@echo ""
	@echo "COPR_TARGETS:"
	@echo "$(COPR_TARGETS)" | tr ' ' '\n'

# Help target
.PHONY: help
help:
	@echo "Cocoon TPM Fedora Packaging Makefile"
	@echo "====================================="
	@echo ""
	@echo "Targets:"
	@echo "  all                  - Generate all spec files (default)"
	@echo "  srpms                - Build all source RPMs"
	@echo "  rpms                 - Build all binary RPMs (chain build)"
	@echo "  coprs                - Upload and build all packages in Copr"
	@echo "  <crate-name>         - Generate spec file for a specific crate"
	@echo "                         (e.g., 'make crypto', 'make utils-common')"
	@echo "  <package-name>.srpm  - Build source RPM for a specific package"
	@echo "                         (e.g., 'make cocoon-tpm-crypto.srpm')"
	@echo "  <package-name>.rpm   - Build binary RPM for a specific package"
	@echo "                         (e.g., 'make cocoon-tpm-crypto.rpm')"
	@echo "  <package-name>.copr  - Upload and build package in Copr"
	@echo "                         (e.g., 'make cocoon-tpm-crypto.copr')"
	@echo "  info                 - Display detailed information about all crates"
	@echo "  list-files           - Show all file and target lists"
	@echo "  clean                - Remove generated spec files, SRPMs, and RPMs"
	@echo "  clean-all            - Remove spec files, SRPMs, RPMs, and local .crate files"
	@echo "  distclean            - Remove everything including workspace .crate files"
	@echo "  help                 - Display this help message"
	@echo ""
	@echo "Available crates:"
	@echo "  $(CRATES)"
	@echo ""
	@echo "Example usage:"
	@echo "  make                                # Generate all spec files"
	@echo "  make crypto                         # Generate spec file for crypto crate"
	@echo "  make cocoon-tpm-crypto.srpm         # Build SRPM for crypto crate"
	@echo "  make cocoon-tpm-crypto.rpm          # Build binary RPM for crypto crate"
	@echo "  make cocoon-tpm-crypto.copr         # Upload and build in Copr"
	@echo "  make srpms                          # Build all SRPMs"
	@echo "  make rpms                           # Build all binary RPMs"
	@echo "  make coprs                          # Build all packages in Copr"
	@echo "  make info                           # Show detailed version information"
	@echo "  make list-files                     # Show all file paths and targets"
	@echo ""
	@echo "Configuration:"
	@echo "  FEDORA_RELEASE = $(FEDORA_RELEASE)"
	@echo "  MOCK_CONFIG    = $(MOCK_CONFIG)"
	@echo "  COPR_PROJECT   = $(COPR_PROJECT)"
	@echo ""
	@echo "Note: Binary RPM builds use mock --chain with --localrepo to handle"
	@echo "      dependencies between crates in the workspace."
