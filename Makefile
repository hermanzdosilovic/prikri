CC = gcc
CFLAGS = -std=c99 -Wall -Wextra -Wnull-dereference -Werror -Wfatal-errors -pedantic -pedantic-errors
LDFLAGS = -lcrypto
TARGET = prikri
SRC = Src/Main.c Src/ProgramArguments.c Src/Usage.c Src/Password.c Src/ByteBuffer.c Src/KDF.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
