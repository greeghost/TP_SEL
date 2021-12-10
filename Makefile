# Indiquer quel compilateur est à utiliser
CC      ?= gcc

# Spécifier les options du compilateur
CFLAGS  ?= -W -Wall -Wextra -pedantic


all: challenge1 challenge2

challenge1: toto
	$(CC) $(CFLAGS)  tp-1.c -o challenge1

challenge2: toto
	$(CC) $(CFLAGS)  tp-2.c -o challenge2

toto:
	$(CC) $(CFLAGS)  toto.c -o toto

clean:
	rm chall* toto
