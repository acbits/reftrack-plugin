# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2023 Aravind Ceyardass (dev@aravind.cc)

# Makefile to compile plugin testcases
#
#

SHELL := /bin/sh

TOPDIR := ..

TARGETS := sample \
		simple \
		self_assign \
		complex \
		complex2 \
		fun_call \
		static_assign \
		array \
		array2 \
		nested \
		loop \
		identity \
		identity2 \
		cycle \
		realloc \
		calloc \
		hash_test \
		block_test

TARGET_OBJS := $(foreach t, ${TARGETS}, ${t}.o)

CC ?= gcc
REFTRACK_CFLAGS := -fplugin=${TOPDIR}/reftrack.so \
	-fplugin-arg-reftrack-log_level=5 \
	-fplugin-arg-reftrack-alloc=reftrack_alloc \
	-fplugin-arg-reftrack-free=reftrack_free \
	-fplugin-arg-reftrack-addref=reftrack_addref \
	-fplugin-arg-reftrack-removeref=reftrack_removeref \
	-fplugin-arg-reftrack-replace

CFLAGS := -Wall -O3  -I${TOPDIR} ${REFTRACK_CFLAGS}

.SUFFIXES:
.SUFFIXES: .c .o

.PHONY: all
all: ${TARGETS}


.PHONY: help
help:
	@echo -e "\nAvailable targets: ${TARGETS}\nTarget objects: ${TARGET_OBJS}"

run: all
	run_test () { \
	local succ=0 fail=0; \
	for p in ${TARGETS}; \
	do \
		echo -n "Running $${p}:"; \
		./$${p} &>/dev/null; \
		if [[ $$? -ne 0 ]]; then \
			((fail++)); \
			echo " failed"; \
		else \
			((succ++)); \
			echo " passed"; \
		fi; \
	done; \
	echo "$${succ} test(s) passed, $${fail} test(s) failed"; \
	} && run_test

.PHONY: clean
clean:
	rm -f ${TARGETS} ${TARGET_OBJS}
