//
// libtgvoip is free and unencumbered public domain software.
// For more information, see http://unlicense.org or the UNLICENSE file
// you should have received with this source code distribution.
//

#ifndef LIBTGVOIP_BUFFERINPUTSTREAM_H
#define LIBTGVOIP_BUFFERINPUTSTREAM_H

#include "threading.h"
#include "utils.h"
#include <array>
#include <cassert>
#include <bitset>
#include <limits>
#include <cstddef>
#include <stdexcept>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace tgvoip
{

class Buffer;

class BufferInputStream
{
public:
    BufferInputStream(const unsigned char* data, size_t m_length);
    BufferInputStream(const Buffer& m_buffer);
    ~BufferInputStream() = default;

    void Seek(size_t m_offset);
    size_t GetLength();
    size_t GetOffset();
    size_t Remaining();
    unsigned char ReadByte();
    int64_t ReadInt64();
    int32_t ReadInt32();
    int16_t ReadInt16();
    int32_t ReadTlLength();
    void ReadBytes(unsigned char* to, size_t count);
    void ReadBytes(Buffer& to);
    BufferInputStream GetPartBuffer(size_t m_length, bool advance);

private:
    void EnsureEnoughRemaining(size_t need);
    const unsigned char* m_buffer;
    size_t m_length;
    size_t m_offset;
};

class BufferOutputStream
{
public:
    TGVOIP_DISALLOW_COPY_AND_ASSIGN(BufferOutputStream);
    BufferOutputStream(size_t m_size);
    BufferOutputStream(unsigned char* m_buffer, size_t m_size);
    BufferOutputStream& operator=(BufferOutputStream&& other);
    ~BufferOutputStream();

    void WriteByte(unsigned char byte);
    void WriteInt64(int64_t i);
    void WriteInt32(int32_t i);
    void WriteInt16(int16_t i);
    void WriteBytes(const unsigned char* bytes, size_t count);
    void WriteBytes(const Buffer& m_buffer);
    void WriteBytes(const Buffer& m_buffer, size_t m_offset, size_t count);
    unsigned char* GetBuffer();
    size_t GetLength();
    void Reset();
    void Rewind(size_t numBytes);

private:
    unsigned char* m_buffer = nullptr;
    size_t m_size;
    size_t m_offset;
    bool m_bufferProvided;

    friend class Buffer;
    void ExpandBufferIfNeeded(size_t need);
};

class Buffer
{
public:
    TGVOIP_DISALLOW_COPY_AND_ASSIGN(Buffer); // use Buffer::CopyOf to copy contents explicitly
    Buffer();
    Buffer(Buffer&& other) noexcept;
    Buffer& operator=(Buffer&& other);
    Buffer(size_t capacity);
    Buffer(BufferOutputStream&& stream);
    ~Buffer();

    unsigned char& operator[](size_t i);
    const unsigned char& operator[](size_t i) const;

    unsigned char* operator*();
    const unsigned char* operator*() const;

    void CopyFrom(const Buffer& other, size_t count, size_t srcOffset = 0, size_t dstOffset = 0);
    void CopyFrom(const void* ptr, size_t dstOffset, size_t count);

    void Resize(size_t newSize);

    size_t Length() const;
    bool IsEmpty() const;

    static Buffer CopyOf(const Buffer& other);
    static Buffer CopyOf(const Buffer& other, size_t offset, size_t length);
    static Buffer Wrap(unsigned char* data, size_t size, std::function<void(void*)> freeFn, std::function<void*(void*, size_t)> reallocFn);

private:
    unsigned char* m_data;
    size_t m_length;
    std::function<void(void*)> m_freeFn;
    std::function<void*(void*, size_t)> m_reallocFn;
};

template <typename T, size_t size, typename AVG_T = T>
class HistoricBuffer
{
public:
    HistoricBuffer()
    {
        std::fill(data.begin(), data.end(), T{0});
    }

    AVG_T Average() const
    {
        AVG_T avg = AVG_T{0};
        for (T i : data)
        {
            avg += i;
        }
        return avg / AVG_T{size};
    }

    AVG_T Average(size_t firstN) const
    {
        AVG_T avg = AVG_T{0};
        for (size_t i = 0; i < firstN; i++)
        {
            avg += (*this)[i];
        }
        return avg / static_cast<AVG_T>(firstN);
    }

    AVG_T NonZeroAverage() const
    {
        AVG_T avg = AVG_T{0};
        int nonZeroCount = 0;
        for (T i : data)
        {
            if (i != 0)
            {
                nonZeroCount++;
                avg += i;
            }
        }
        if (nonZeroCount == 0)
            return AVG_T{0};
        return avg / static_cast<AVG_T>(nonZeroCount);
    }

    void Add(T el)
    {
        data[offset] = el;
        offset = (offset + 1) % size;
    }

    T Min() const
    {
        T min = std::numeric_limits<T>::max();
        for (T i : data)
        {
            if (i < min)
                min = i;
        }
        return min;
    }

    T Max() const
    {
        T max = std::numeric_limits<T>::min();
        for (T i : data)
            if (i > max)
                max = i;
        return max;
    }

    void Reset()
    {
        std::fill(data.begin(), data.end(), T{0});
        offset = 0;
    }

    T operator[](size_t i) const
    {
        assert(i < size);
        // [0] should return the most recent entry, [1] the one before it, and so on
        ptrdiff_t _i = offset - i - 1;
        if (_i < 0)
            _i = size + _i;
        return data[_i];
    }

    T& operator[](size_t i)
    {
        assert(i < size);
        // [0] should return the most recent entry, [1] the one before it, and so on
        ptrdiff_t _i = offset - i - 1;
        if (_i < 0)
            _i = size + _i;
        return data[_i];
    }

    size_t Size() const
    {
        return size;
    }

private:
    std::array<T, size> data;
    ptrdiff_t offset = 0;
};

template <size_t bufSize, size_t bufCount>
class BufferPool
{
public:
    TGVOIP_DISALLOW_COPY_AND_ASSIGN(BufferPool);
    BufferPool()
    {
        bufferStart = reinterpret_cast<unsigned char*>(malloc(bufSize * bufCount));
        if (bufferStart == nullptr)
            throw std::bad_alloc();
    }

    ~BufferPool()
    {
        assert(usedBuffers.none());
        std::free(bufferStart);
    }

    Buffer Get()
    {
        auto freeFn = [this](void* _buf)
        {
            assert(_buf != nullptr);
            unsigned char* buf = reinterpret_cast<unsigned char*>(_buf);
            size_t offset = buf - bufferStart;
            assert(offset % bufSize == 0);
            size_t index = offset / bufSize;
            assert(index < bufCount);

            MutexGuard m(mutex);
            assert(usedBuffers.test(index));
            usedBuffers[index] = 0;
        };
        auto resizeFn = [](void* buf, size_t newSize) -> void*
        {
            if (newSize > bufSize)
                throw std::invalid_argument("newSize>bufferSize");
            return buf;
        };
        MutexGuard m(mutex);
        for (size_t i = 0; i < bufCount; ++i)
        {
            if (!usedBuffers[i])
            {
                usedBuffers[i] = 1;
                return Buffer::Wrap(bufferStart + (bufSize * i), bufSize, freeFn, resizeFn);
            }
        }
        throw std::bad_alloc();
    }

private:
    std::bitset<bufCount> usedBuffers;
    unsigned char* bufferStart;
    Mutex mutex;
};
}

#endif //LIBTGVOIP_BUFFERINPUTSTREAM_H
