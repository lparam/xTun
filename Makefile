#
# (C) Copyright 2000-2015
# Ken <ken.i18n@gmail.com>
#

MAJOR = 0
MINOR = 1
PATCH = 0
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

OBJTREE		:= $(if $(BUILD_DIR),$(BUILD_DIR),$(CURDIR))
SRCTREE		:= $(CURDIR)
export SRCTREE OBJTREE

#########################################################################

ifdef HOST
CROSS_COMPILE = $(HOST)-
endif

# for OpenWrt
ifdef CROSS
CROSS_COMPILE = $(CROSS)
HOST = $(patsubst %-,%,$(CROSS_COMPILE))
ifneq (,$(findstring openwrt,$(CROSS_COMPILE)))
OPENWRT = 1
endif
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
CFLAGS += -pie -fPIE
ANDROID = 1
endif

ifneq (,$(findstring mingw32,$(CROSS_COMPILE)))
MINGW32 = 1
endif

EXTRA_CFLAGS =

#########################################################################

CPPFLAGS += -Isrc
CPPFLAGS += -I3rd/libuv/include -I3rd/libsodium/src/libsodium/include

LDFLAGS = -Wl,--gc-sections

ifdef ANDROID
LDFLAGS += -pie -fPIE
else
	ifndef MINGW32
		LIBS += -lrt
	endif
endif

LIBS += 3rd/libuv/.libs/libuv.a 3rd/libsodium/src/libsodium/.libs/libsodium.a

ifdef MINGW32
LIBS += -lws2_32 -lpsapi -liphlpapi -luserenv
else
LIBS += -pthread -ldl
endif

LDFLAGS += $(LIBS)

#########################################################################
include $(SRCTREE)/config.mk
#########################################################################

all: libuv libsodium xTun

3rd/libuv/autogen.sh:
	$(Q)git submodule update --init

3rd/libuv/Makefile: | 3rd/libuv/autogen.sh
	$(Q)cd 3rd/libuv && ./autogen.sh && ./configure --host=$(HOST) LDFLAGS= && $(MAKE)

libuv: 3rd/libuv/Makefile

3rd/libsodium/autogen.sh:
	$(Q)git submodule update --init

3rd/libsodium/Makefile: | 3rd/libsodium/autogen.sh
	$(Q)cd 3rd/libsodium && ./autogen.sh && ./configure --host=$(HOST) LDFLAGS= && $(MAKE)

libsodium: 3rd/libsodium/Makefile

xTun: \
	src/util.o \
	src/logger.o \
	src/daemon.o \
	src/signal.o \
	src/crypto.o \
	src/tun.o \
	src/main.o
	$(LINK) $^ -o $(OBJTREE)/$@ $(LDFLAGS)

clean:
	@find $(OBJTREE)/src -type f \
	\( -name '*.bak' -o -name '*~' \
	-o -name '*.o' -o -name '*.tmp' \) -print \
	| xargs rm -f
	@rm -f xTun

distclean: clean
	$(Q)cd 3rd/libsodium && make distclean
	$(Q)cd 3rd/libuv && make distclean

ifndef CROSS_COMPILE
install:
	$(Q)$(STRIP) --strip-unneeded xtund && cp xtund $(INSTALL_DIR)
else
install:
endif
