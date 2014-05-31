CC=gcc

all:
	gcc -Wall -O0 -g -ggdb -I../src -I../src/3rdParty -I../src/3rdParty/cJSON -I../objs \
        -o protocol \
        protocol.c ../src/common.c ../src/str.c ../src/3rdParty/cJSON/cJSON.c \
        -lcurl -lcrypto -lm

