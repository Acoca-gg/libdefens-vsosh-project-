CC = gcc
CFLAGS = -shared -fPIC -Wall -Wextra -O2
LDFLAGS = -ldl
TARGET = libdefense.so
SOURCES = libdefense_1.2.0.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET) *.o
