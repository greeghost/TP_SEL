# Indiquer quel compilateur est à utiliser
CC      ?= gcc

# Spécifier les options du compilateur
CFLAGS  ?= -W -Wall -Wextra -pedantic


all: clean challenge1 challenge2

challenge1: toto
	$(CC) $(CFLAGS) -o challenge1 tp-1.c dependencies.c

challenge2: toto
	$(CC) $(CFLAGS) -o challenge2 tp-2.c dependencies.c

toto:
	$(CC) $(CFLAGS)  toto.c -o toto

clean:
	rm -f challenge1 challenge2 toto
