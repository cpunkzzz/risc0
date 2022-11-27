// Copyright 2022 Risc0, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <sstream>

#include "risc0/core/align.h"
#include "risc0/core/log.h"
#include "risc0/zkp/core/sha256.h"
#include "risc0/zkvm/platform/io.h"
#include "risc0/zkvm/platform/memory.h"
#include "risc0/zkvm/prove/step.h"

namespace risc0
{

  class FpG
  {
    // implement just enough operations to support extension field multiplication
    // all values are in mont form
  public:
    static CONSTSCALAR uint64_t M = 0xFFFFFFFF00000001;
    uint64_t val;

  private:
    static DEVSPEC constexpr uint64_t add(uint64_t a, uint64_t b)
    {
      bool c1 = (M - b) > a;
      uint64_t x1 = a - (M - b);
      uint32_t adj = uint32_t(0) - uint32_t(c1);
      uint64_t res = x1 - uint64_t(adj);
      // std::cout << "c1: " << c1 << ", x1: " << x1 << ", adj: " << adj << ", res: " << res << std::endl;
      return res;
    }

    static DEVSPEC constexpr uint64_t sub(uint64_t a, uint64_t b)
    {
      bool c1 = b > a;
      uint64_t x1 = a - b;
      uint32_t adj = 0 - uint32_t(c1);
      return x1 - uint64_t(adj);
    }

    static DEVSPEC constexpr uint64_t doubleVal(uint64_t a)
    {
      __uint128_t ret = __uint128_t(a) << 1;
      uint64_t result = uint64_t(ret);
      uint64_t over = uint64_t(ret >> 64);
      return result - (M * over);
    }

    static uint64_t montRedCst(__uint128_t n)
    {
      uint64_t xl = uint64_t(n);
      uint64_t xh = uint64_t(n >> 64);
      bool e = (__uint128_t(xl) + __uint128_t(xl << 32)) > UINT64_MAX; // overflow
      uint64_t a = xl + (xl << 32);
      uint64_t b = a - (a >> 32) - e;
      bool c = xh < b;
      uint64_t r = xh - b;
      uint64_t mont_result = r - (uint32_t(0) - uint32_t(c));
      return mont_result;
    }

    static DEVSPEC constexpr uint64_t mul(uint64_t a, uint64_t b)
    {
      __uint128_t n = __uint128_t(a) * __uint128_t(b);
      return montRedCst(n);
    }

  public:
    DEVSPEC constexpr FpG(uint64_t val) : val(val) {}
    DEVSPEC constexpr FpG operator+(FpG rhs) const { return FpG(add(val, rhs.val)); }
    DEVSPEC constexpr FpG operator-(FpG rhs) const { return FpG(sub(val, rhs.val)); }
    DEVSPEC constexpr FpG operator*(FpG rhs) const { return FpG(mul(val, rhs.val)); }
    DEVSPEC constexpr FpG doubleVal() const { return FpG(doubleVal(val)); }
  };

  static std::pair<FpG, FpG> extensionMul(std::pair<FpG, FpG> a, std::pair<FpG, FpG> b)
  {
    FpG a0b0 = a.first * b.first;
    FpG a1b1 = a.second * b.second;
    FpG first = a0b0 - a1b1.doubleVal();

    FpG a0a1 = a.first + a.second;
    FpG b0b1 = b.first + b.second;
    FpG second = a0a1 * b0b1 - a0b0;

    // std::cout << "CPP a: [" << a.first.val << ", " << a.second.val << "]" << std::endl;
    // std::cout << "b: [" << b.first.val << ", " << b.second.val << "]" << std::endl;

    // std::cout << "a0b0: " << a0b0.val << ", a1b1: " << a1b1.val << ", first: " << first.val
    //           << ", a0a1: " << a0a1.val << ", b0b1: " << b0b1.val << ", second: "
    //           << second.val << std::endl;

    return std::pair(first, second);
  }

  static void processSHA(MemoryState &mem, const ShaDescriptor &desc)
  {
    uint16_t type = (desc.typeAndCount & 0xFFFF) >> 4;
    uint16_t count = desc.typeAndCount & 0xFFFF;
    LOG(1,
        "SHA256 type: " << type << ", count: " << count << ", idx: " << desc.idx
                        << ", source: " << hex(desc.source) << ", digest: " << hex(desc.digest));
    ShaDigest sha = impl::initState();
    uint32_t words[16];
    for (int i = 0; i < count; i++)
    {
      for (int j = 0; j < 16; j++)
      {
        uint32_t from = desc.source + i * 16 * 4 + j * 4;
        words[j] = mem.loadBE(from);
        LOG(1, "Input[" << hex(j, 2) << "]: " << hex(from) << " -> " << hex(words[j]));
      }
      LOG(1, "Compress");
      impl::compress(sha, words);
    }
    for (int i = 0; i < 8; i++)
    {
      LOG(1, "Output[" << hex(i, 1) << "]: " << hex(sha.words[i]));
      mem.store(desc.digest + i * 4, sha.words[i]);
    }
  }

  static void processMul(MemoryState &mem, const MulDescriptor &desc)
  {
    uint32_t a0_hi = mem.load(desc.source);
    LOG(1, "Input[" << hex(0, 2) << "]: " << hex(desc.source) << " -> " << hex(a0_hi));
    uint32_t a0_lo = mem.load(desc.source + 4);
    LOG(1, "Input[" << hex(1, 2) << "]: " << hex(desc.source + 4) << " -> " << hex(a0_lo));
    uint32_t a1_hi = mem.load(desc.source + 8);
    LOG(1, "Input[" << hex(2, 2) << "]: " << hex(desc.source + 8) << " -> " << hex(a1_hi));
    uint32_t a1_lo = mem.load(desc.source + 12);
    LOG(1, "Input[" << hex(3, 2) << "]: " << hex(desc.source + 12) << " -> " << hex(a1_lo));

    uint32_t b0_hi = mem.load(desc.source + 16);
    LOG(1, "Input[" << hex(4, 2) << "]: " << hex(desc.source + 16) << " -> " << hex(b0_hi));
    uint32_t b0_lo = mem.load(desc.source + 20);
    LOG(1, "Input[" << hex(5, 2) << "]: " << hex(desc.source + 20) << " -> " << hex(b0_lo));
    uint32_t b1_hi = mem.load(desc.source + 24);
    LOG(1, "Input[" << hex(6, 2) << "]: " << hex(desc.source + 24) << " -> " << hex(b1_hi));
    uint32_t b1_lo = mem.load(desc.source + 28);
    LOG(1, "Input[" << hex(7, 2) << "]: " << hex(desc.source + 28) << " -> " << hex(b1_lo));

    uint64_t a0 = a0_lo | (uint64_t(a0_hi) << 32);
    uint64_t a1 = a1_lo | (uint64_t(a1_hi) << 32);
    uint64_t b0 = b0_lo | (uint64_t(b0_hi) << 32);
    uint64_t b1 = b1_lo | (uint64_t(b1_hi) << 32);

    std::pair<FpG, FpG> a = std::pair(FpG(a0), FpG(a1));
    std::pair<FpG, FpG> b = std::pair(FpG(b0), FpG(b1));
    std::pair<FpG, FpG> result = extensionMul(a, b);

    uint64_t r0 = result.first.val;
    uint32_t r0_high = (uint32_t)((r0 & 0xFFFFFFFF00000000LL) >> 32);
    uint32_t r0_low = (uint32_t)(r0 & 0xFFFFFFFFLL);

    uint64_t r1 = result.second.val;
    uint32_t r1_high = (uint32_t)((r1 & 0xFFFFFFFF00000000LL) >> 32);
    uint32_t r1_low = (uint32_t)(r1 & 0xFFFFFFFFLL);

    LOG(1, "Output[" << hex(0, 2) << "]: " << hex(desc.result) << " <- " << hex(r0_high));
    mem.store(desc.result, r0_high);
    LOG(1, "Output[" << hex(1, 2) << "]: " << hex(desc.result + 4) << " <- " << hex(r0_low));
    mem.store(desc.result + 4, r0_low);
    LOG(1, "Output[" << hex(2, 2) << "]: " << hex(desc.result + 8) << " <- " << hex(r1_high));
    mem.store(desc.result + 8, r1_high);
    LOG(1, "Output[" << hex(3, 2) << "]: " << hex(desc.result + 12) << " <- " << hex(r1_low));
    mem.store(desc.result + 12, r1_low);
  }

  void IoHandler::onFault(const std::string &msg)
  {
    throw std::runtime_error(msg);
  }

  MemoryHandler::MemoryHandler() : MemoryHandler(nullptr) {}

  MemoryHandler::MemoryHandler(IoHandler *io) : io(io), cur_host_to_guest_offset(kMemInputStart) {}

  void MemoryHandler::onInit(MemoryState &mem)
  {
    if (io)
    {
      io->onInit(mem);
    }
  }

  void MemoryHandler::onWrite(MemoryState &mem, uint32_t cycle, uint32_t addr, uint32_t value)
  {
    LOG(2, "MemoryHandler::onWrite> " << hex(addr) << ": " << hex(value));
    switch (addr)
    {
    case kGPIO_Mul:
    {
      LOG(1, "MemoryHandler::onWrite> GPIO_MUL");
      MulDescriptor desc;
      mem.loadRegion(value, &desc, sizeof(desc));
      processMul(mem, desc);
      break;
    }
    case kGPIO_SHA:
    {
      LOG(1, "MemoryHandler::onWrite> GPIO_SHA");
      ShaDescriptor desc;
      mem.loadRegion(value, &desc, sizeof(desc));
      processSHA(mem, desc);
    }
    break;
    case kGPIO_Commit:
    {
      LOG(1, "MemoryHandler::onWrite> GPIO_Commit");
      IoDescriptor desc;
      mem.loadRegion(value, &desc, sizeof(desc));
      if (io)
      {
        std::vector<uint8_t> buf(desc.size);
        mem.loadRegion(desc.addr, buf.data(), desc.size);
        io->onCommit(buf);
      }
    }
    break;
    case kGPIO_Fault:
    {
      LOG(1, "MemoryHandler::onWrite> GPIO_Fault");
      if (io)
      {
        size_t len = mem.strlen(value);
        std::vector<char> buf(len);
        mem.loadRegion(value, buf.data(), len);
        std::string str(buf.data(), buf.size());
        io->onFault(str);
      }
    }
    break;
    case kGPIO_Log:
    {
      LOG(2, "MemoryHandler::onWrite> GPIO_Log");
      size_t len = mem.strlen(value);
      std::vector<char> buf(len);
      mem.loadRegion(value, buf.data(), len);
      std::string str(buf.data(), buf.size());
      LOG(0, "R0VM[C" << cycle << "]> " << str);
    }
    break;
    case kGPIO_GetKey:
    {
      LOG(1, "MemoryHandler::onWrite> GPIO_GetKey");
      GetKeyDescriptor desc;
      mem.loadRegion(value, &desc, sizeof(desc));
      if (!io)
      {
        throw std::runtime_error("Get key called with no IO handler set");
      }
      size_t len = mem.strlen(desc.name);
      std::vector<char> buf(len);
      mem.loadRegion(desc.name, buf.data(), len);
      std::string str(buf.data(), buf.size());
      LOG(1, "  addr = " << hex(desc.addr));
      LOG(1, "  key = " << str);
      LOG(1, "  mode = " << desc.mode);
      KeyStore &store = io->getKeyStore();
      if (desc.mode == 0 && store.count(str))
      {
        throw std::runtime_error("GetKey Mode = NEW and key exists: " + str);
      }
      if (desc.mode == 1 && !store.count(str))
      {
        throw std::runtime_error("GetKey Mode = EXISTING and key does not exist: " + str);
      }
      const Key &key = store[str];
      mem.store(desc.addr, reinterpret_cast<const uint8_t *>(&key), sizeof(Key));
    }
    break;
    case kGPIO_SendRecvAddr:
    {
      if (io)
      {
        uint32_t channel = mem.load(kGPIO_SendRecvChannel);
        std::vector<uint8_t> buf(mem.load(kGPIO_SendRecvSize));
        LOG(1,
            "MemoryHandler::onWrite> GPIO_SendReceive, channel " << channel
                                                                 << " size=" << buf.size());
        mem.loadRegion(value, buf.data(), buf.size());
        BufferU8 result = io->onSendRecv(channel, buf);
        LOG(1,
            "MemoryHandler::onWrite> GPIO_SendReceive, host replied with " << result.size()
                                                                           << " bytes");
        size_t aligned_len = align(result.size());
        if ((cur_host_to_guest_offset + sizeof(uint32_t) + aligned_len) >= kMemInputEnd)
        {
          throw(std::runtime_error("Read buffer overrun"));
        }
        mem.store(cur_host_to_guest_offset, result.size());
        cur_host_to_guest_offset += sizeof(uint32_t);
        for (size_t i = 0; i < result.size(); ++i)
        {
          mem.storeByte(cur_host_to_guest_offset + i, result[i]);
        }
        cur_host_to_guest_offset += aligned_len;
      }
      else
      {
        throw std::runtime_error("SendRecv called with no IO handler set");
      }
    }
    break;
    }
  }

  void MemoryState::dump(size_t logLevel)
  {
    LOG(logLevel, "MemoryState::dump> size: " << data.size());
    if (getLogLevel() >= logLevel)
    {
      for (auto pair : data)
      {
        LOG(logLevel, "  " << hex(pair.first * 4) << ": " << hex(pair.second));
      }
    }
  }

  size_t MemoryState::strlen(uint32_t addr)
  {
    size_t len = 0;
    while (loadByte(addr++))
    {
      len++;
    }
    return len;
  }

  uint8_t MemoryState::loadByte(uint32_t addr)
  {
    // align to the nearest word
    uint32_t aligned = addr & ~(sizeof(uint32_t) - 1);
    size_t byte_offset = addr % sizeof(uint32_t);
    uint32_t word = load(aligned);
    return (word >> (byte_offset * 8)) & 0xff;
  }

  uint32_t MemoryState::load(uint32_t addr)
  {
    auto it = data.find(addr / 4);
    if (it == data.end())
    {
      std::stringstream ss;
      ss << "addr out of range: " << hex(addr);
      throw std::out_of_range(ss.str());
    }
    return it->second;
  }

  void MemoryState::loadRegion(uint32_t addr, void *ptr, uint32_t len)
  {
    uint8_t *bytes = static_cast<uint8_t *>(ptr);
    for (size_t i = 0; i < len; i++)
    {
      bytes[i] = loadByte(addr++);
    }
  }

  uint32_t MemoryState::loadBE(uint32_t addr)
  {
    return loadByte(addr + 0) << 24 | //
           loadByte(addr + 1) << 16 | //
           loadByte(addr + 2) << 8 |  //
           loadByte(addr + 3);
  }

  void MemoryState::storeByte(uint32_t addr, uint8_t byte)
  {
    // align to the nearest word
    uint32_t aligned = addr & ~(sizeof(uint32_t) - 1);
    size_t byte_offset = addr % sizeof(uint32_t);
    uint32_t word = data[aligned / 4] & ~(0xff << (byte_offset * 8));
    word |= byte << (byte_offset * 8);
    store(aligned, word);
  }

  void MemoryState::store(uint32_t addr, const void *ptr, uint32_t len)
  {
    const uint8_t *bytes = static_cast<const uint8_t *>(ptr);
    for (size_t i = 0; i < len; i++)
    {
      storeByte(addr++, bytes[i]);
    }
  }

  void MemoryState::store(uint32_t addr, uint32_t value)
  {
    if (addr % 4 != 0)
    {
      throw std::runtime_error("Unaligned store");
    }
    uint32_t key = addr / 4;
    auto it = data.find(key);
    if (it != data.end())
    {
      auto txn = history.lower_bound({key, 0, 0, 0});
      if (txn != history.end() && txn->addr == key && it->second != value)
      {
        // The guest has actually touched this memory, and we are not writing the same value
        throw std::runtime_error("Host cannot mutate existing memory.");
      }
      it->second = value;
    }
    else
    {
      data[key] = value;
    }
  }

} // namespace risc0
