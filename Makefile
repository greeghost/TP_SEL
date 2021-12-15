# Indiquer quel compilateur est à utiliser
CC       ?= gcc

# Spécifier les options du compilateur
CFLAGS   ?= -W -Wall -Wextra -pedantic

BINARIES ?= challenge1 challenge2 toto

all: clean $(BINARIES)

challenge1: toto
	$(CC) $(CFLAGS) -o challenge1 tp-1.c dependencies.c

challenge2: toto
	$(CC) $(CFLAGS) -o challenge2 tp-2.c dependencies.c

challenge3: toto
	$(CC) $(CFLAGS) -o challenge3 tp-3.c dependencies.c

toto:
	$(CC) $(CFLAGS)  toto.c -o toto

clean:
	rm -f $(BINARIES) challenge3
