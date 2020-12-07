#==========================================================
# Makefile of project wgnet
#==========================================================

# Basic system
C_COMPILE = 
RFS_ROOT=
DFLAGS =
NAME = wgnet
OPT ?= -O0
GCC_PREFIX = 

# Setup output parameters
PATH_TARGET = 
EXE = $(NAME)
PATH_OBJ    = bin/
CC = $(C_COMPILE)gcc
CXX = $(C_COMPILE)g++
STRIP = $(C_COMPILE)strip

CFLAGS = -Wall -Wno-unused-function -Wno-unused-variable  -Wno-unused-but-set-variable
CFLAGS += -Wno-unused-label
#CFLAGS += -Wno-pointer-to-int-cast -Wno-switch -ffunction-sections -fdata-sections
CFLAGS += -g $(OPT)

#DFLAGS += -DDEBUG

# Directories and files
######################################################
DIRS = ./ wireguard/

SRC_FILES = $(shell find . -name '*.c')
CXX_SRC_FILES = $(shell find . -name '*.cpp')
OBJ_FILES = $(subst ./,$(PATH_OBJ),$(patsubst %.c,%.o,$(SRC_FILES)))
CXX_OBJ_FILES = $(subst ./,$(PATH_OBJ),$(patsubst %.cpp,%.o,$(CXX_SRC_FILES)))

# Defaults
######################################################
# Need to include headers for libraries
INCLUDE  = -I . 
INCLUDE += -I $(RFS_ROOT)/usr/include/

INCLUDE += $(foreach dir,$(DIRS),-I $(dir))

# Need to link in libs
LIBS = 
LIBS += -L $(RFS_ROOT)/usr/lib/

# Use libs
LDFLAGS = 
#LDFLAGS += -lrt -lm -lpthread
LDFLAGS += -lconfuse

LNFLAGS = -Wl,--gc-sections

# Sections and rules
######################################################

# Remove SILENT to see the build cmd
.SILENT:

.PHONY: all all-pre all-post
all: all-pre $(EXE) all-post

all-pre:
	echo "-- Building $(EXE) --"
	echo "GCC: $(CC)"
	mkdir -p $(foreach dir,$(DIRS),$(PATH_OBJ)$(dir))
	
all-post:
#	echo "Done..."

$(EXE):  $(OBJ_FILES)
	echo "  LNK $@"
	$(CC) $(LNFLAGS) -s -o $(PATH_TARGET)$@ $(foreach dir,$(DIRS),$(PATH_OBJ)$(dir)*.o) $(LIBS) $(LDFLAGS)

$(PATH_OBJ)%.o:%.c
	echo "  CC  $@"
	$(CC) $(CFLAGS) $(INCLUDE) $(DFLAGS) -c -o $@ $<

$(PATH_OBJ)%.o:%.cpp
	echo "  CXX $@"
	$(CXX) $(CFLAGS) $(CXXFLAGS) $(INCLUDE) $(DFLAGS) -c -o $@ $<

new: clean all

clean:
	echo "  RM .o"
	rm -rf $(EXE)
	rm -rf $(PATH_OBJ)
	rm -f $(PATH_TARGET)$(OUTLIB) 

