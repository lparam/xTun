ifneq ($(OBJTREE),$(SRCTREE))
ifeq ($(CURDIR),$(SRCTREE))
dir :=
else
dir := $(subst $(SRCTREE)/,,$(CURDIR))
endif
obj := $(if $(dir),$(OBJTREE)/$(dir)/,$(OBJTREE)/)
src := $(if $(dir),$(SRCTREE)/$(dir)/,$(SRCTREE)/)
$(shell mkdir -p $(obj))
else
# current object directory
obj :=
src :=
endif

#########################################################################

#
# Include the make variables (CC, etc...)
#
ifndef AS
AS = $(CROSS_COMPILE)as
endif

ifndef CC
CC = $(CROSS_COMPILE)gcc
endif

ifndef LD
LD = $(CROSS_COMPILE)ld
endif

CPP	= $(CC) -E

ifndef AR
AR = $(CROSS_COMPILE)ar
endif

ifndef NM
NM	= $(CROSS_COMPILE)nm
endif

ifndef STRIP
STRIP = $(CROSS_COMPILE)strip
endif

ifndef OBJCOPY
OBJCOPY = $(CROSS_COMPILE)objcopy
endif

ifndef OBJDUMP
OBJDUMP = $(CROSS_COMPILE)objdump
endif

ifndef RANLIB
RANLIB = $(CROSS_COMPILE)ranlib
endif

#########################################################################

export CROSS_COMPILE \
	AS LD CC CPP AR NM STRIP OBJCOPY OBJDUMP MAKE

#########################################################################

MAKEFLAGS += -rR --no-print-directory

ifndef V
  Q = @
endif

FINAL_CFLAGS = $(CPPFLAGS) $(CFLAGS) $(EXTRA_CFLAGS)
FINAL_LDFLAGS =

CCC=$(QUIET_CC)$(CC) $(FINAL_CFLAGS)
LINK=$(QUIET_LINK)$(CC)$(FINAL_LDFLAGS)
BUILD_AR=$(QUIET_AR)$(AR)
BUILD_RANLIB=$(QUIET_RANLIB)$(RANLIB)
INSTALL=$(QUIET_INSTALL)

CCCOLOR="\033[34m"
LINKCOLOR="\033[34;1m"
SRCCOLOR="\033[33m"
BINCOLOR="\033[32;1m"
MAKECOLOR="\033[32;1m"
ECHOCOLOR="\033[32;1m"
ENDCOLOR="\033[0m"

ifndef V
QUIET_CC = @printf '    %b %b\n' $(CCCOLOR)CC$(ENDCOLOR) $(SRCCOLOR)$(subst $(OBJTREE)/,,$@)$(ENDCOLOR) 1>&2;
QUIET_LINK = @printf '    %b %b\n' $(LINKCOLOR)LINK$(ENDCOLOR) $(BINCOLOR)$(subst $(OBJTREE)/,,$@)$(ENDCOLOR) 1>&2;
QUIET_AR = @printf '    %b %b\n' $(LINKCOLOR)AR$(ENDCOLOR) $(BINCOLOR)$(subst $(OBJTREE)/,,$@)$(ENDCOLOR) 1>&2;
QUIET_RANLIB = @printf '    %b %b\n' $(LINKCOLOR)RANLIB$(ENDCOLOR) $(BINCOLOR)$(subst $(OBJTREE)/,,$@)$(ENDCOLOR) 1>&2;
QUIET_INSTALL = @printf '    %b %b\n' $(LINKCOLOR)INSTALL$(ENDCOLOR) $(BINCOLOR)$@$(ENDCOLOR) 1>&2;
QUIET_STRIP_OPTION = > /dev/null
endif

ifneq ($(OBJTREE),$(SRCTREE))
define nicename
@echo $(subst $(OBJTREE)/,,$1)
endef
else
define nicename
@echo $(subst $(OBJTREE)/,,$(CURDIR)/$1)
endef
endif

ifneq ($(OBJTREE),$(SRCTREE))
cobj = $(subst $(OBJTREE)/,,$@)
else
cobj = $(subst $(OBJTREE)/,,$(CURDIR)/$@)
endif

%.o: %.c
	$(shell [ -d $(dir $(OBJTREE)/$@) ] || mkdir -p $(dir $@))
	$(CCC) -c $< -o $(obj)$@

$(obj)%.o: %.c
	$(shell [ -d $(dir $(OBJTREE)/$@) ] || mkdir -p $(dir $@))
	$(CCC) -c $< -o $@
