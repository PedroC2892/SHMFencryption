CC = gcc
CFLAGS = -Wall -Wextra -Iinclude -Isrc -DPACKAGE=\"SmallHMFencryption\" -DVERSION=\"1.0.0\"
LIBS = -lsodium

SRC_DIR = src
CONFIG_DIR = config
BIN = shmfe

OBJS = $(SRC_DIR)/main.o $(SRC_DIR)/crypto.o $(SRC_DIR)/cmdline.o

.PHONY: all clean

all: $(BIN)

$(BIN): $(OBJS)
	@echo "Linking $(BIN)..."
	$(CC) $(OBJS) -o $(BIN) $(LIBS)

$(SRC_DIR)/cmdline.c $(SRC_DIR)/cmdline.h: $(CONFIG_DIR)/cmdline.ggo
	@echo "Generating CLI parser..."
	gengetopt --input=$(CONFIG_DIR)/cmdline.ggo --output-dir=$(SRC_DIR) --file-name=cmdline

$(SRC_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(SRC_DIR)/main.o: $(SRC_DIR)/cmdline.h
$(SRC_DIR)/crypto.o: $(SRC_DIR)/cmdline.h

clean:
	@echo "Cleaning up..."
	rm -f $(SRC_DIR)/*.o $(BIN) $(SRC_DIR)/cmdline.c $(SRC_DIR)/cmdline.h
