#! /bin/bash
.PHONY:clean

default:
	gcc -O hw3.c -o hw3 -lpcap

clean:
	rm hw3
