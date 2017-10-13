CC := g++
CFLAGS := -fPIC
LDFLAGS = -lpthread

INC_DIR_COMMON := ../common/inc
INC_DIR_ENCODER := ./inc
SRC_DIR := ./src
OBJ_DIR := $(SRC_DIR)/obj

INSTALL_LIB_PATH := ../target
LIB_TARGET_STATIC := librtpencoder.a
LIB_TARGET_SHARE := librtpencoder.so

CFLAGS += -I$(INC_DIR_COMMON) -I$(INC_DIR_ENCODER)

SOURCE = $(wildcard $(SRC_DIR)/*.cpp)
SOURCER = $(notdir $(SOURCE))
OBJS = $(patsubst %.cpp,%.o,$(SOURCER))

OBJS := $(foreach X,$(OBJS),$(OBJ_DIR)/$(X))
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	$(CC) $(CFLAGS) $(LDFLAGS) -c -o $@ $<

all: $(LIB_TARGET_STATIC) $(LIB_TARGET_SHARE)

$(LIB_TARGET_STATIC):$(OBJS)
	ar cr $@ $(OBJS)
	install -m 0755 $(LIB_TARGET_STATIC) $(INSTALL_LIB_PATH)
	rm -rf $(LIB_TARGET_STATIC)

$(LIB_TARGET_SHARE):$(OBJS)
	g++ -shared -o $@ $(OBJS)
	install -m 0755 $(LIB_TARGET_SHARE) $(INSTALL_LIB_PATH)
	rm -rf $(LIB_TARGET_SHARE)

.PHONY:clean
clean:
	rm -rf $(OBJ_DIR)
	rm -rf $(INSTALL_LIB_PATH)/$(LIB_TARGET_STATIC)  
	rm -rf $(INSTALL_LIB_PATH)/$(LIB_TARGET_SHARE)  
