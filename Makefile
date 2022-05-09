# Project 2 VUT-FIT-KRY (generating RSA parameters)
# Author Adam Švenk (xsvenk00)
# Date: 2022-04-29

CXX=g++-11.3
XLOGINXX=xsvenk00

OBJ=kry.o
BIN=kry

CXXFLAGS:=-Wall -Wextra -Wsuggest-override -Wnull-dereference -Wshadow -Wold-style-cast -pedantic -lgmp -std=c++20 

LINK.o = $(LINK.cpp)

all: CXXFLAGS += -Ofast -march=native -flto
all: kry

debug: CXXFLAGS += -g3 -fsanitize=address,undefined -fno-omit-frame-pointer
debug: kry

kry: $(OBJ)
	$(CXX) $(LDFLAGS) $(OBJ) -o $(BIN) $(CXXFLAGS)

pack: zip $(XLOGINXX).zip *.cpp *.hpp  Makefile doc.pdf

dep: g++ *.cpp -MM >> Makefile

release: all
