CC = vc
CFLAGS = -c -O2 -D__AMIGA__ -D__USE_INLINE__ -I./include
LDFLAGS = -lamiga -lauto

SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin

SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

.PHONY: all clean

all: $(BIN_DIR)/bonamid

$(BIN_DIR)/bonamid: $(OBJS)
	@mkdir -p $(BIN_DIR)
	$(CC) -o $@ $^ $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR) 