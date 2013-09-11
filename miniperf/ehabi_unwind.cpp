/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
 * This is an implementation of stack unwinding according to a subset
 * of the ARM Exception Handling ABI, as described in:
 *   http://infocenter.arm.com/help/topic/com.arm.doc.ihi0038a/IHI0038A_ehabi.pdf
 *
 * This handles only the ARM-defined "personality routines" (chapter
 * 9), and don't track the value of FP registers, because profiling
 * needs only chain of PC/SP values.
 *
 * Because the exception handling info may not be accurate for all
 * possible places where an async signal could occur (e.g., in a
 * prologue or epilogue), this bounds-checks all stack accesses.
 *
 * This file uses "struct" for structures in the exception tables and
 * "class" otherwise.  We should avoid violating the C++11
 * standard-layout rules in the former.
 */

#include "ehabi_unwind.h"

#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <elf.h>
#include <stdint.h>
#include <stdio.h>

#include <algorithm>
#include <vector>
#include <string>
#include <map>

#ifndef PT_ARM_EXIDX
#define PT_ARM_EXIDX 0x70000001
#endif


#define MOZ_DELETE = delete
#define MOZ_ASSERT(e)
#define MOZ_LITTLE_ENDIAN 1 // XXX
namespace mozilla {
template<class T> struct DebugOnly { DebugOnly(const T&) { } };
}

struct EHEntry;

enum {
  R_SP = 13,
  R_LR = 14,
  R_PC = 15
};

class EHEntryHandle {
  const EHEntry *mValue;
public:
  EHEntryHandle(const EHEntry *aEntry) : mValue(aEntry) { }
  const EHEntry *value() const { return mValue; }
};

class EHTable {
  const void *mMapBase;
  size_t mMapLen;
  const EHEntry *mIndex;
  size_t mIndexSize;
  std::map<uint32_t, const void *> mOffToMapped;
  // In principle we should be able to binary-search the index section in
  // place, but the ICS toolchain's linker is noncompliant and produces
  // indices that aren't entirely sorted (e.g., libc).  So we have this:
  std::vector<EHEntryHandle> mEntries;
  std::string mName;
public:
  EHTable(FILE *aELF, const std::string &aName);
  ~EHTable();
  const EHEntry *lookup(const void *aPC) const;
  bool isValid() const { return mMapBase != NULL; }
  const std::string &name() const { return mName; }
  bool offToMapped(uint32_t aOff, const void *&aMappedOut) const {
    std::map<uint32_t, const void *>::const_iterator i = mOffToMapped.find(aOff);
    if (i == mOffToMapped.end())
      return false;
    aMappedOut = i->second;
    return true;
  }
};

class EHMapping {
  const EHTable *mTable;
  uint32_t mStart;
  uint32_t mEnd;
  uintptr_t mMappedStart;
  EHMapping *mNext;
public:
  EHMapping(const EHTable *aTable, uint32_t aStart, uint32_t aEnd,
            const void *aMappedStart, EHMapping *aNext)
    : mTable(aTable),
      mStart(aStart),
      mEnd(aEnd),
      mMappedStart(reinterpret_cast<uintptr_t>(aMappedStart)),
      mNext(aNext)
  { }
  bool lookup(uint32_t aAddr, const EHTable *&aTableOut,
              const void *&aMappedOut) {
    for (EHMapping *here = this; here != NULL; here = here->mNext) {
      if (aAddr >= here->mStart && aAddr < here->mEnd) {
        aTableOut = here->mTable;
        aMappedOut = reinterpret_cast<const void *>((aAddr - here->mStart)
                                                    + here->mMappedStart);
        return true;
      }
    }
    return false;
  }
};

class EHAddrSpace {
  EHMapping *mMaps[1024];
  static std::map<std::string, const EHTable *> sCache;
  static const EHTable *mapFile(const char *aPath);
public:
  EHAddrSpace() { memset(&mMaps, 0, sizeof(mMaps)); }
  explicit EHAddrSpace(const EHAddrSpace *aSpace) {
    memcpy(&mMaps, &aSpace->mMaps, sizeof(mMaps));
  }
  void mmap(uint32_t aAddr, uint32_t aLen, const char *aPath, uint32_t aOffset);
  bool lookup(uint32_t aPC, const EHTable *&aTableOut,
              const void *&aMappedOut) const {
    return mMaps[aPC >> 22]->lookup(aPC, aTableOut, aMappedOut);
  }
};


struct PRel31 {
  uint32_t mBits;
  bool topBit() const { return mBits & 0x80000000; }
  uint32_t value() const { return mBits & 0x7fffffff; }
  int32_t offset() const { return (static_cast<int32_t>(mBits) << 1) >> 1; }
  const void *compute() const {
    return reinterpret_cast<const char *>(this) + offset();
  }
private:
  PRel31(const PRel31 &copied) MOZ_DELETE;
  PRel31() MOZ_DELETE;
};

struct EHEntry {
  PRel31 startPC;
  PRel31 exidx;
private:
  EHEntry(const EHEntry &copied) MOZ_DELETE;
  EHEntry() MOZ_DELETE;
};


class EHInterp {
public:
  EHInterp(const uint32_t aRegs[16], const void *aStack, size_t aStackSize)
    : mStack(aStack),
      mStackSize(aStackSize),
      mNextWord(0),
      mWordsLeft(0),
      mFailed(false),
      mDone(true)
  {
    memcpy(&mRegs, aRegs, sizeof(mRegs));
    mStackLimit = mRegs[R_SP];
    mStackBase = mStackLimit + aStackSize;
  }

  bool unwind(const EHEntry *aEntry) {
    initialize(aEntry);
    mRegs[R_PC] = 0;
    checkStack();
    while (!mFailed && !mDone)
      step();
    return !mFailed;
  }

  uint32_t getReg(int regno) const {
    return mRegs[regno];
  }

private:
  uint32_t mRegs[16];
  const void *mStack;
  size_t mStackSize;
  uint32_t mStackLimit; // inclusive, not exclusive as in APCS
  uint32_t mStackBase;
  const uint32_t *mNextWord;
  uint32_t mWord;
  uint8_t mWordsLeft;
  uint8_t mBytesLeft;
  bool mFailed;
  bool mDone;

  enum {
    I_ADDSP    = 0x00, // 0sxxxxxx (subtract if s)
    M_ADDSP    = 0x80,
    I_POPMASK  = 0x80, // 1000iiii iiiiiiii (if any i set)
    M_POPMASK  = 0xf0,
    I_MOVSP    = 0x90, // 1001nnnn
    M_MOVSP    = 0xf0,
    I_POPN     = 0xa0, // 1010lnnn
    M_POPN     = 0xf0,
    I_FINISH   = 0xb0, // 10110000
    I_POPLO    = 0xb1, // 10110001 0000iiii (if any i set)
    I_ADDSPBIG = 0xb2, // 10110010 uleb128
    I_POPFDX   = 0xb3, // 10110011 sssscccc
    I_POPFDX8  = 0xb8, // 10111nnn
    M_POPFDX8  = 0xf8,
    // "Intel Wireless MMX" extensions omitted.
    I_POPFDD   = 0xc8, // 1100100h sssscccc
    M_POPFDD   = 0xfe,
    I_POPFDD8  = 0xd0, // 11010nnn
    M_POPFDD8  = 0xf8
  };

  void initialize(const EHEntry *aEntry);
  void step(void);

  uint8_t next() {
    if (mBytesLeft == 0) {
      if (mWordsLeft == 0) {
        return I_FINISH;
      }
      mWordsLeft--;
      mWord = *mNextWord++;
      mBytesLeft = 4;
    }
    mBytesLeft--;
    mWord = (mWord << 8) | (mWord >> 24); // rotate
    return mWord;
  }

  uint32_t &vSP() { return mRegs[R_SP]; }
  uint32_t *ptrSP() { return reinterpret_cast<uint32_t *>(vSP()); }

  void checkStackBase() { if (vSP() > mStackBase) mFailed = true; }
  void checkStackLimit() { if (vSP() < mStackLimit) mFailed = true; }
  void checkStackAlign() { if ((vSP() & 3) != 0) mFailed = true; }
  void checkStack() {
    checkStackBase();
    checkStackLimit();
    checkStackAlign();
  }

  void popRange(uint8_t first, uint8_t last, uint16_t mask) {
    bool hasSP = false;
    uint32_t tmpSP;
    if (mask == 0) {
      mFailed = true;
      return;
    }
    for (uint8_t r = first; r <= last; ++r) {
      if (mask & 1) {
        if (r == R_SP) {
          hasSP = true;
          tmpSP = *ptrSP();
        } else
          mRegs[r] = *ptrSP();
        vSP() += 4;
        checkStackBase();
        if (mFailed)
          return;
      }
      mask >>= 1;
    }
    if (hasSP) {
      vSP() = tmpSP;
      checkStack();
    }
  }
};


void EHInterp::initialize(const EHEntry *aEntry)
{
  const PRel31 &exidx = aEntry->exidx;
  uint32_t firstWord;

  mDone = false;
  if (exidx.mBits == 1) {  // EXIDX_CANTUNWIND
    mFailed = true;
    return;
  }
  if (exidx.topBit()) {
    firstWord = exidx.mBits;
  } else {
    mNextWord = reinterpret_cast<const uint32_t *>(exidx.compute());
    firstWord = *mNextWord++;
  }

  switch (firstWord >> 24) {
  case 0x80: // short
    mWord = firstWord << 8;
    mBytesLeft = 3;
    break;
  case 0x81: case 0x82: // long; catch descriptor size ignored
    mWord = firstWord << 16;
    mBytesLeft = 2;
    mWordsLeft = (firstWord >> 16) & 0xff;
    break;
  default:
    // unknown personality
    mFailed = true;
  }

  // FIXME: record SP so we can't walk back down the stack?
}

void EHInterp::step() {
  uint8_t insn = next();
#if 0
  LOGF("unwind insn = %02x", (unsigned)insn);
#endif
  // Try to put the common cases first.

  // 00xxxxxx: vsp = vsp + (xxxxxx << 2) + 4
  // 01xxxxxx: vsp = vsp - (xxxxxx << 2) - 4
  if ((insn & M_ADDSP) == I_ADDSP) {
    uint32_t offset = ((insn & 0x3f) << 2) + 4;
    if (insn & 0x40) {
      vSP() -= offset;
      checkStackLimit();
    } else {
      vSP() += offset;
      checkStackBase();
    }
    return;
  }

  // 10100nnn: Pop r4-r[4+nnn]
  // 10101nnn: Pop r4-r[4+nnn], r14
  if ((insn & M_POPN) == I_POPN) {
    uint8_t n = (insn & 0x07) + 1;
    bool lr = insn & 0x08;
    uint32_t *ptr = ptrSP();
    vSP() += (n + (lr ? 1 : 0)) * 4;
    checkStackBase();
    if (mFailed)
      return;
    for (uint8_t r = 4; r < 4 + n; ++r)
      mRegs[r] = *ptr++;
    if (lr)
      mRegs[R_LR] = *ptr++;
    return;
  }

  // 1011000: Finish
  if (insn == I_FINISH) {
    mDone = true;
    if (mRegs[R_PC] == 0)
      mRegs[R_PC] = mRegs[R_LR];
    return;
  }

  // 1001nnnn: Set vsp = r[nnnn]
  if ((insn & M_MOVSP) == I_MOVSP) {
    vSP() = mRegs[insn & 0x0f];
    checkStack();
    return;
  }

  // 11001000 sssscccc: Pop VFP regs D[16+ssss]-D[16+ssss+cccc] (as FLDMFDD)
  // 11001001 sssscccc: Pop VFP regs D[ssss]-D[ssss+cccc] (as FLDMFDD)
  if ((insn & M_POPFDD) == I_POPFDD) {
    uint8_t n = (next() & 0x0f) + 1;
    // Note: if the 16+ssss+cccc > 31, the encoding is reserved.
    // As the space is currently unused, we don't try to check.
    vSP() += 8 * n;
    checkStackBase();
    return;
  }

  // 11010nnn: Pop VFP regs D[8]-D[8+nnn] (as FLDMFDD)
  if ((insn & M_POPFDD8) == I_POPFDD8) {
    uint8_t n = (insn & 0x07) + 1;
    vSP() += 8 * n;
    checkStackBase();
    return;
  }

  // 10110010 uleb128: vsp = vsp + 0x204 + (uleb128 << 2)
  if (insn == I_ADDSPBIG) {
    uint32_t acc = 0;
    uint8_t shift = 0;
    uint8_t byte;
    do {
      if (shift >= 32) {
        mFailed = true;
        return;
      }
      byte = next();
      acc |= (byte & 0x7f) << shift;
      shift += 7;
    } while (byte & 0x80);
    uint32_t offset = 0x204 + (acc << 2);
    // The calculations above could have overflowed.
    // But the one we care about is this:
    if (vSP() + offset < vSP())
      mFailed = true;
    vSP() += offset;
    // ...so that this is the only other check needed:
    checkStackBase();
    return;
  }

  // 1000iiii iiiiiiii (i not all 0): Pop under masks {r15-r12}, {r11-r4}
  if ((insn & M_POPMASK) == I_POPMASK) {
    popRange(4, 15, ((insn & 0x0f) << 8) | next());
    return;
  }

  // 1011001 0000iiii (i not all 0): Pop under mask {r3-r0}
  if (insn == I_POPLO) {
    popRange(0, 3, next() & 0x0f);
    return;
  }

  // 10110011 sssscccc: Pop VFP regs D[ssss]-D[ssss+cccc] (as FLDMFDX)
  if (insn == I_POPFDX) {
    uint8_t n = (next() & 0x0f) + 1;
    vSP() += 8 * n + 4;
    checkStackBase();
    return;
  }

  // 10111nnn: Pop VFP regs D[8]-D[8+nnn] (as FLDMFDX)
  if ((insn & M_POPFDX8) == I_POPFDX8) {
    uint8_t n = (insn & 0x07) + 1;
    vSP() += 8 * n + 4;
    checkStackBase();
    return;
  }

  // unhandled instruction
#if 0
  LOGF("Unhandled EHABI instruction 0x%02x", insn);
#endif
  mFailed = true;
}


bool operator<(const EHEntryHandle &lhs, const EHEntryHandle &rhs) {
  return lhs.value()->startPC.compute() < rhs.value()->startPC.compute();
}

const EHEntry *EHTable::lookup(const void *aPC) const {
  std::vector<EHEntryHandle>::const_iterator begin = mEntries.begin();
  std::vector<EHEntryHandle>::const_iterator end = mEntries.end();
  MOZ_ASSERT(begin < end);
  if (aPC < begin->value()->startPC.compute())
    return NULL;

  while (end - begin > 1) {
    std::vector<EHEntryHandle>::const_iterator mid = begin + (end - begin) / 2;
    if (aPC < mid->value()->startPC.compute())
      end = mid;
    else
      begin = mid;
  }
  return begin->value();
}


#if MOZ_LITTLE_ENDIAN
static const unsigned char hostEndian = ELFDATA2LSB;
#elif MOZ_BIG_ENDIAN
static const unsigned char hostEndian = ELFDATA2MSB;
#else
#error "No endian?"
#endif

EHTable::EHTable(FILE *aELF, const std::string &aName)
  : mMapBase(NULL), mName(aName)
{
  static const long page_size = sysconf(_SC_PAGESIZE);
  Elf32_Ehdr file;

  fseek(aELF, 0, SEEK_SET);
  if (fread(&file, sizeof(file), 1, aELF) < 1)
    return;
  if (memcmp(&file.e_ident[EI_MAG0], ELFMAG, SELFMAG) != 0 ||
      file.e_ident[EI_CLASS] != ELFCLASS32 ||
      file.e_ident[EI_DATA] != hostEndian ||
      file.e_ident[EI_VERSION] != EV_CURRENT ||
      file.e_ident[EI_OSABI] != ELFOSABI_SYSV ||
      file.e_ident[EI_ABIVERSION] != 0 ||
      file.e_machine != EM_ARM ||
      file.e_version != EV_CURRENT)
    // e_flags?
    return;

  uint32_t vMin = ~(uint32_t)0, vMax = 0;
  uint8_t *phbuf = reinterpret_cast<uint8_t *>(malloc(file.e_phnum * file.e_phentsize));
  if (!phbuf)
    return;
  fseek(aELF, file.e_phoff, SEEK_SET);
  if (fread(phbuf, file.e_phnum * file.e_phentsize, 1, aELF) < 1) {
    free(phbuf);
    return;
  }
  for (unsigned i = 0; i < file.e_phnum; ++i) {
    const Elf32_Phdr &phdr =
      *reinterpret_cast<const Elf32_Phdr*>(&phbuf[file.e_phentsize * i]);
    if (phdr.p_type == PT_LOAD) {
      vMin = std::min(vMin, phdr.p_vaddr);
      vMax = std::max(vMax, phdr.p_vaddr + phdr.p_memsz);
    }
  }
  if (vMin >= vMax) {
    free(phbuf);
    return;
  }
  vMin = (vMin / page_size) * page_size;
  mMapLen = vMax - vMin;
  mMapBase = mmap(NULL, mMapLen, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (mMapBase == MAP_FAILED) {
    free(phbuf);
    return;
  }
  uintptr_t baseAddr = reinterpret_cast<uintptr_t>(mMapBase);
  for (unsigned i = 0; i < file.e_phnum; ++i) {
    const Elf32_Phdr &phdr =
      *reinterpret_cast<const Elf32_Phdr*>(&phbuf[file.e_phentsize * i]);
    if (phdr.p_type == PT_LOAD && phdr.p_memsz > 0 && phdr.p_filesz > 0) {
      uintptr_t vStart = baseAddr + (phdr.p_vaddr - vMin);
      uintptr_t padding = vStart % page_size;
      uintptr_t mapsz = std::min(phdr.p_memsz, phdr.p_filesz);
      void *mapped = mmap(reinterpret_cast<void*>(vStart - padding),
                          mapsz + padding, PROT_READ, MAP_PRIVATE | MAP_FIXED,
                          fileno(aELF), phdr.p_offset - padding);
      if (mapped == MAP_FAILED) {
        free(phbuf);
        return;
      }
      mOffToMapped[phdr.p_offset] = reinterpret_cast<const void *>(vStart);
    }
    if (phdr.p_type == PT_ARM_EXIDX) {
      mIndex = reinterpret_cast<const EHEntry *>(baseAddr + (phdr.p_vaddr - vMin));
      mIndexSize = phdr.p_memsz / sizeof(EHEntry);
    }
  }
  free(phbuf);

  // Create a sorted index of the index to work around linker bugs.
  mEntries.reserve(mIndexSize);
  for (size_t i = 0; i < mIndexSize; ++i)
    mEntries.push_back(&mIndex[i]);
  std::sort(mEntries.begin(), mEntries.end());
}

EHTable::~EHTable() {
  if (isValid())
    munmap(const_cast<void*>(mMapBase), mMapLen);
}


void EHAddrSpace::mmap(uint32_t aAddr, uint32_t aLen, const char *aPath,
                       uint32_t aOffset) {
  const EHTable *table = mapFile(aPath);
  const void *mappedAddr;
  if (table && table->offToMapped(aOffset, mappedAddr))
    for (unsigned i = aAddr >> 22; i <= (aAddr + aLen - 1) >> 22; ++i)
      mMaps[i] = new EHMapping(table, aAddr, aAddr + aLen, mappedAddr, mMaps[i]);
}

std::map<std::string, const EHTable *> EHAddrSpace::sCache;

const EHTable *EHAddrSpace::mapFile(const char *aPath) {
  std::string path(aPath);
  std::map<std::string, const EHTable *>::iterator i = sCache.find(path);

  if (i != sCache.end())
    return i->second;

  EHTable *tab = NULL;
  FILE *fh = fopen(aPath, "rb");
  if (fh) {
    tab = new EHTable(fh, path);
    fclose(fh);
    if (!tab->isValid()) {
      delete tab;
      tab = NULL;
    }
  }
  sCache[path] = tab;
  return tab;
}


EHAddrSpace *EHNewSpace()
{
  return new EHAddrSpace();
}

EHAddrSpace *EHForkSpace(const EHAddrSpace *aSpace)
{
  return new EHAddrSpace(aSpace);
}

void EHAddMMap(EHAddrSpace *aSpace, uint32_t aAddr, uint32_t aLen,
               const char *aPath, uint32_t aOffset)
{
  aSpace->mmap(aAddr, aLen, aPath, aOffset);
}

size_t EHUnwind(EHAddrSpace *aSpace, const uint32_t aRegs[16],
                const void *aStack, size_t aStackSize,
                uint32_t *aPCs, size_t aNumFrames)
{
  EHInterp interp(aRegs, aStack, aStackSize);
  size_t count = 0;

  while (count < aNumFrames) {
    uint32_t pc = interp.getReg(R_PC);
    aPCs[count] = pc;
    count++;

    if (!aSpace)
      break;
    // TODO: cache these lookups.  Binary-searching libxul is
    // expensive (possibly more expensive than doing the actual
    // unwind), and even a small cache should help.
    const EHTable *table;
    const void *mappedPC;
    if (!aSpace->lookup(pc, table, mappedPC))
      break;
    const EHEntry *entry = table->lookup(mappedPC);
    if (!entry)
      break;
    if (!interp.unwind(entry))
      break;
  }

  return count;
}

