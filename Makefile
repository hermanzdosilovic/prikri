CC = gcc
CFLAGS = -std=c99 -Wall -Wextra -Wnull-dereference -Werror -Wfatal-errors -pedantic -pedantic-errors
LDFLAGS = -lcrypto
THIRD_PARTY_HEADERS_DIR = ThirdParty/Include
TARGET = prikri
SRC = Src/Main.c Src/Password.c Src/ByteBuffer.c Src/KDF.c Src/AES.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS) -I$(THIRD_PARTY_HEADERS_DIR)

clean:
	rm -f $(TARGET)

.PHONY: all clean
