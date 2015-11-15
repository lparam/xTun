MAJOR = 0
MINOR = 2
PATCH = 1
NAME = xTun

ifdef O
ifeq ("$(origin O)", "command line")
BUILD_DIR := $(O)
endif
endif

ifneq ($(BUILD_DIR),)
saved-output := $(BUILD_DIR)

# Attempt to create a output directory.
$(shell [ -d ${BUILD_DIR} ] || mkdir -p ${BUILD_DIR})

# Verify if it was successful.
BUILD_DIR := $(shell cd $(BUILD_DIR) && /bin/pwd)
$(if $(BUILD_DIR),,$(error output directory "$(saved-output)" does not exist))
endif # ifneq ($(BUILD_DIR),)

INSTALL_DIR := /usr/local/bin

OBJTREE	:= $(if $(BUILD_DIR),$(BUILD_DIR),$(CURDIR))
SRCTREE	:= $(CURDIR)
export SRCTREE OBJTREE

#########################################################################

ifdef HOST
CROSS_COMPILE = $(HOST)-
endif

# for OpenWrt
ifdef CROSS
CROSS_COMPILE = $(CROSS)
HOST = $(patsubst %-,%,$(CROSS_COMPILE))
endif

ifneq (,$(findstring openwrt,$(CROSS_COMPILE)))
OPENWRT = 1
endif

ifdef CROSS_COMPILE
CPPFLAGS = -DCROSS_COMPILE
endif

CFLAGS = \
	-Os	\
	-g \
	-std=gnu99 \
	-Wall \
	$(PLATFORM_CFLAGS)

CFLAGS += -fomit-frame-pointer -fdata-sections -ffunction-sections

ifneq (,$(findstring android,$(CROSS_COMPILE)))
CPPFLAGS += -DANDROID
# CFLAGS += -pie -fPIE
ANDROID = 1
endif

ifneq (,$(findstring mingw32,$(CROSS_COMPILE)))
MINGW32 = 1
endif

EXTRA_CFLAGS =

#########################################################################

CPPFLAGS += -Isrc
CPPFLAGS += -I3rd/libuv/include -I3rd/libsodium/src/libsodium/include
ifneq ($(OBJTREE),$(SRCTREE))
CPPFLAGS += -I3rd/libsodium/src/libsodium/include/sodium
CPPFLAGS += -I$(OBJTREE)/3rd/libsodium/src/libsodium/include
endif

SHARED = -fPIC --shared

LDFLAGS = -Wl,--gc-sections

ifdef ANDROID
LDFLAGS += -pie -fPIE
else
	ifndef MINGW32
		LIBS += -lrt
	endif
endif

LIBS += $(OBJTREE)/3rd/libuv/.libs/libuv.a $(OBJTREE)/3rd/libsodium/src/libsodium/.libs/libsodium.a

ifdef MINGW32
LIBS += -lws2_32 -lpsapi -liphlpapi -luserenv
else
LIBS += -pthread -ldl
endif

LDFLAGS += $(LIBS)

XTUN=$(OBJTREE)/xTun
XTUN_STATIC=$(OBJTREE)/libxTun.a
XTUN_SHARED=$(OBJTREE)/libxTun.so

#########################################################################
include $(SRCTREE)/config.mk
#########################################################################

all: libuv libsodium $(XTUN)
android: libuv libsodium $(XTUN_STATIC)
share: libuv libsodium $(XTUN_SHARED)

3rd/libuv/autogen.sh:
	$(Q)git submodule update --init

$(OBJTREE)/3rd/libuv/Makefile: | 3rd/libuv/autogen.sh
	$(Q)mkdir -p $(OBJTREE)/3rd/libuv
	$(Q)cd 3rd/libuv && ./autogen.sh
	$(Q)cd $(OBJTREE)/3rd/libuv && $(SRCTREE)/3rd/libuv/configure --host=$(HOST) LDFLAGS= && $(MAKE)

libuv: $(OBJTREE)/3rd/libuv/Makefile

3rd/libsodium/autogen.sh:
	$(Q)git submodule update --init

$(OBJTREE)/3rd/libsodium/Makefile: | 3rd/libsodium/autogen.sh
	$(Q)mkdir -p $(OBJTREE)/3rd/libsodium
	$(Q)cd 3rd/libsodium && ./autogen.sh
	$(Q)cd $(OBJTREE)/3rd/libsodium && $(SRCTREE)/3rd/libsodium/configure --host=$(HOST) LDFLAGS= && $(MAKE)

libsodium: $(OBJTREE)/3rd/libsodium/Makefile

$(XTUN): \
	$(OBJTREE)/src/util.o \
	$(OBJTREE)/src/logger.o \
	$(OBJTREE)/src/daemon.o \
	$(OBJTREE)/src/signal.o \
	$(OBJTREE)/src/crypto.o \
	$(OBJTREE)/src/tun.o \
	$(OBJTREE)/src/main.o
	$(LINK) $^ -o $@ $(LDFLAGS)

$(XTUN_STATIC): \
	$(OBJTREE)/src/util.o \
	$(OBJTREE)/src/logger.o \
	$(OBJTREE)/src/crypto.o \
	$(OBJTREE)/src/android.o \
	$(OBJTREE)/src/tun.o
	$(BUILD_AR) rcu $@ $^
	$(BUILD_RANLIB) $@

$(XTUN_SHARED): \
	src/util.o \
	src/logger.o \
	src/crypto.o \
	src/tun.o
	$(LINK) $^ $(OBJTREE)/3rd/libuv/.libs/libuv.a $(OBJTREE)/3rd/libsodium/src/libsodium/.libs/libsodium.a -o $@ -shared

clean:
	@find $(OBJTREE)/src -type f \
	\( -name '*.o' -o -name '*~' \
	-o -name '*.tmp' \) -print \
	| xargs rm -f
	@rm -f $(XTUN) $(XTUN_STATIC) $(XTUN_SHARED)

distclean: clean
ifeq ($(OBJTREE)/3rd/libsodium/Makefile, $(wildcard $(OBJTREE)/3rd/libsodium/Makefile))
	$(Q)cd $(OBJTREE)/3rd/libsodium && make distclean
endif
ifeq ($(OBJTREE)/3rd/libuv/Makefile, $(wildcard $(OBJTREE)/3rd/libuv/Makefile))
	$(Q)cd $(OBJTREE)/3rd/libuv && make distclean
endif

ifndef CROSS_COMPILE
install:
	$(Q)$(STRIP) --strip-unneeded xTun && cp xTun $(INSTALL_DIR)
else
install:
endif
