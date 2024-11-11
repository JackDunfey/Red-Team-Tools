# all: arp_router sniff

# arp_router: arp_router.c
# 	gcc arp_router.c -o arp_router

# sniff: arp-listen.c
# 	gcc arp-listen.c -o arp_listen

# Compiler and flags
CC = gcc
CFLAGS = -Wall -g -O2

# Libraries and paths
LIBS = -lnet
INCLUDES = -I/usr/include

# Target executable
TARGET = arp_router

# Source files
SRC = arp_router.c
OBJ = $(SRC:.c=.o)

# All target
all: $(TARGET)

# Linking the executable
$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $(TARGET) $(LIBS)

# Compiling the object files
%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Clean target
clean:
	rm -f $(OBJ) $(TARGET)

# Phony targets
.PHONY: all clean
