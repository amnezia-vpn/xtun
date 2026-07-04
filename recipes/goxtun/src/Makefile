BUILD_DIR = build
LIB_NAME = libgoxtun

GOOS_linux = linux
GOOS_android = android
GOOS_windows = windows
GOOS_macos = darwin
GOOS_ios = ios

GOARCH_x86 = 386
GOARCH_x86_64 = amd64
GOARCH_amd64 = amd64
GOARCH_arm64 = arm64
GOARCH_aarch64 = arm64
GOARCH_armv8 = arm64

ifneq ($(shell which cmd 2>/dev/null),)
	OS ?= windows
endif

is_windows :=
is_apple :=
ifeq ($(OS),windows)
	is_windows := yes
else ifeq ($(OS),macos)
	is_apple := yes
	SDK := macosx
	ARCHS ?= x86_64 arm64
else ifeq ($(OS),ios)
	is_apple = yes
	SDK := iphoneos
	ARCHS ?= arm64
endif

GOOS_DEFINE = $(if $(OS),GOOS=$(GOOS_$(OS)),)
GOARCH_DEFINE = $(if $(ARCH),GOARCH=$(GOARCH_$(ARCH)),)
CGO_CFLAGS_DEFINE = $(if $(CFLAGS),CGO_CFLAGS=$(CFLAGS),)
CGO_LDFLAGS_DEFINE = $(if $(LDFLAGS),CGO_LDFLAGS=$(LDFLAGS),)

ifneq ($(SDK),)
	CFLAGS += -isysroot $(shell xcrun --sdk $(SDK) --show-sdk-path)
endif

ifdef is_windows

shared: $(BUILD_DIR)/$(LIB_NAME).lib

$(BUILD_DIR)/$(LIB_NAME).lib: $(BUILD_DIR)/$(LIB_NAME).dll
	cd $(BUILD_DIR) && gendef $<
	cd $(BUILD_DIR) && dlltool -d $(BUILD_DIR)/$(LIB_NAME).def -l $@ -D $<
	rm $(BUILD_DIR)/$(LIB_DEF)

$(BUILD_DIR)/$(LIB_NAME).dll:
	@mkdir -p $(BUILD_DIR)
	$(GOARCH_DEFINE) $(GOOS_DEFINE) $(CGO_CFLAGS_DEFINE) $(CGO_LDFLAGS_DEFINE) CGO_ENABLED=1 go build -ldflags=-w -o $@ -buildmode=c-shared

else ifdef is_apple

archive: $(BUILD_DIR)/$(LIB_NAME).a
shared: $(BUILD_DIR)/$(LIB_NAME).dylib

define $(LIB_NAME)-singlearch
CFLAGS_$(1) = $(CFLAGS) -arch $(1)
LDFLAGS_$(1) = $(LDFLAGS) -arch $(1)
$(BUILD_DIR)/$(LIB_NAME)-$(1).a:
	@mkdir -p $(BUILD_DIR)
	$(GOARCH_DEFINE) $(GOOS_DEFINE) CGO_LDFLAGS="$$(LDFLAGS_$(1))" CGO_CFLAGS="$$(CFLAGS_$(1))" CGO_ENABLED=1 go build -ldflags=-w -o $$@ -buildmode=c-archive
$(BUILD_DIR)/$(LIB_NAME)-$(1).dylib:
	@mkdir -p $(BUILD_DIR)
	$(GOARCH_DEFINE) $(GOOS_DEFINE) CGO_LDFLAGS="$$(LDFLAGS_$(1))" CGO_CFLAGS="$$(CFLAGS_$(1))" CGO_ENABLED=1 go build -ldflags=-w -o $$@ -buildmode=c-shared
endef
$(foreach ARCH,$(ARCHS),$(eval $(call $(LIB_NAME)-singlearch,$(ARCH))))

$(BUILD_DIR)/$(LIB_NAME).a: $(foreach ARCH,$(ARCHS),$(BUILD_DIR)/$(LIB_NAME)-$(ARCH).a)
	lipo -create -output $@ $^
	cp $(BUILD_DIR)/$(LIB_NAME)-$(firstword $(ARCHS)).h $(BUILD_DIR)/$(LIB_NAME).h

$(BUILD_DIR)/$(LIB_NAME).dylib: $(foreach ARCH,$(ARCHS),$(BUILD_DIR)/$(LIB_NAME)-$(ARCH).dylib)
	lipo -create -output $@ $^
	cp $(BUILD_DIR)/$(LIB_NAME)-$(firstword $(ARCHS)).h $(BUILD_DIR)/$(LIB_NAME).h

else

archive: $(BUILD_DIR)/$(LIB_NAME).a
shared: $(BUILD_DIR)/$(LIB_NAME).so

$(BUILD_DIR)/$(LIB_NAME).a:
	@mkdir -p $(BUILD_DIR)
	$(GOARCH_DEFINE) $(GOOS_DEFINE) $(CGO_CFLAGS_DEFINE) $(CGO_LDFLAGS_DEFINE) CGO_ENABLED=1 go build -ldflags=-w -o $@ -buildmode=c-archive
$(BUILD_DIR)/$(LIB_NAME).so:
	@mkdir -p $(BUILD_DIR)
	$(GOARCH_DEFINE) $(GOOS_DEFINE) $(CGO_CFLAGS_DEFINE) $(CGO_LDFLAGS_DEFINE) CGO_ENABLED=1 go build -ldflags=-w -o $@ -buildmode=c-shared

endif

PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
