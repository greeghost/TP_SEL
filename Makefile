# Indiquer quel compilateur est à utiliser
CC      ?= gcc

# Spécifier les options du compilateur
CFLAGS  ?= -W -Wall -Wextra

challenge2:
	$(CC) $(CFLAGS)  tp-2.c -o challenge2

toto:
	$(CC) $(CFLAGS)  toto.c -o toto

clean:
	challenge2 toto

all:
	challenge2 toto
