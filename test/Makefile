CC := g++
CFLAGS := -fPIC

INC_DIR_COMMON := ../common/inc
INC_DIR_ENCODER := ../rtpencoder/inc
SRC_DIR := ./src
OBJ_DIR := $(SRC_DIR)/obj

TARGET_DIR := ../target
TARGET := rtpencoder
INSTALL_LIB_PATH := $(TARGET_DIR)
ENCODER_LIB := librtpencoder.a
EXT_LIB := -lpthread
  
CFLAGS += -I$(INC_DIR_COMMON) -I$(INC_DIR_ENCODER)
    
SOURCE = $(wildcard $(SRC_DIR)/*.cpp)
SOURCER = $(notdir $(SOURCE))
OBJS = $(patsubst %.cpp,%.o,$(SOURCER))
OBJS := $(foreach X,$(OBJS),$(OBJ_DIR)/$(X))
  
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	$(CC) $(CFLAGS) -c -o $@ $<

$(TARGET):$(OBJS)
	$(CC) -o $(TARGET_DIR)/$(TARGET) $(OBJS) \
		$(INSTALL_LIB_PATH)/$(ENCODER_LIB) $(EXT_LIB)

.PHONY:clean
clean:
	rm -rf $(OBJ_DIR)
