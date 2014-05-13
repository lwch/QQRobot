CC=gcc

all:
	gcc -Wall -O0 -g -ggdb -I../src -I../src/3rdParty -I../src/3rdParty/cJSON \
        -o protocol \
        protocol.c ../src/common.c ../src/3rdParty/cJSON/cJSON.c \
        -lcurl -lcrypto -lm

