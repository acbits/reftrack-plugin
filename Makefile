# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2023 Aravind Ceyardass (dev@aravind.cc)

# reftrack plugin Makefile
# Requires GNU Make >= 4.2.1
#
PREFIX ?= /usr
INSTALL ?= install
PREFIX := $(DESTDIR)/$(PREFIX)
PLUGIN_SOURCE_FILES := reftrack.cc
RUNTIME_DIR := $(PREFIX)/lib64/
RUNTIME_PKG_DIR := $(PREFIX)/lib64/pkgconfig

INCLUDE_DIR := $(PREFIX)/include

TARGET_OBJ := reftrack.so

GCCPLUGINS_DIR := $(shell $(CC) -print-file-name=plugin)
CXXFLAGS += -Wall -I$(GCCPLUGINS_DIR)/include -fPIC -fno-rtti  -g


$(TARGET_OBJ): $(PLUGIN_SOURCE_FILES)
	$(CXX)  -O3 -shared -std=c++14 $(CXXFLAGS) $< -o $@


all: ${TARGET_OBJ}

install: all
	$(INSTALL) -d -m 755  $(RUNTIME_DIR)
	$(INSTALL) -d -m 755  $(INCLUDE_DIR)
	$(INSTALL) -d -m 755  $(RUNTIME_PKG_DIR)

	$(INSTALL) -s -m 644 $(TARGET_OBJ) $(RUNTIME_DIR)
	$(INSTALL) -d -m 755 $(INCLUDE_DIR)/reftrack
	$(INSTALL) -m 644 reftrack.h $(INCLUDE_DIR)/reftrack
	$(INSTALL) -m 644 hrcmm.h $(INCLUDE_DIR)/reftrack
	$(INSTALL) -m 644 reftrack.pc $(RUNTIME_PKG_DIR)

uninstall:
	rm -f $(RUNTIME_PKG_DIR)/reftrack.pc
	rm -rf $(INCLUDE_DIR)/reftrack/
	rm -f $(RUNTIME_DIR)/$(TARGET_OBJ)


.PHONY: clean
clean:
	rm -f ${TARGET_OBJ}

