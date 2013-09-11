/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdint.h>

class EHAddrSpace;

EHAddrSpace *EHNewSpace();
EHAddrSpace *EHForkSpace(const EHAddrSpace *);
void EHAddMMap(EHAddrSpace *space, uint32_t addr, uint32_t len,
               const char *path, uint32_t offset);
size_t EHUnwind(const EHAddrSpace *space, const uint32_t regs[16],
    const void *stack, size_t stacksize, uint32_t *pcOut, size_t numPCs);
