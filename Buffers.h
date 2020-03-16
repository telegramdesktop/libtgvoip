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
    BufferInputStream(const unsigned char* data, std::size_t m_length);
    BufferInputStream(const Buffer& m_buffer);
    ~BufferInputStream() = default;

    void Seek(std::size_t m_offset);
    std::size_t GetLength() const;
    std::size_t GetOffset() const;
    std::size_t Remaining() const;
    unsigned char ReadByte();
    std::int64_t ReadInt64();
    std::int32_t ReadInt32();
    std::int16_t ReadInt16();
    std::int32_t ReadTlLength();
    void ReadBytes(unsigned char* to, std::size_t count);
    void ReadBytes(Buffer& to);
    BufferInputStream GetPartBuffer(std::size_t m_length, bool advance);

private:
    void EnsureEnoughRemaining(std::size_t need);
    const unsigned char* m_buffer;
    std::size_t m_length;
    std::size_t m_offset;
};

class BufferOutputStream
{
public:
    TGVOIP_DISALLOW_COPY_AND_ASSIGN(BufferOutputStream);
    BufferOutputStream(std::size_t m_size);
    BufferOutputStream(unsigned char* m_buffer, std::size_t m_size);
    BufferOutputStream& operator=(BufferOutputStream&& other);
    ~BufferOutputStream();

    void WriteByte(unsigned char byte);
    void WriteInt64(std::int64_t i);
    void WriteInt32(std::int32_t i);
    void WriteInt16(std::int16_t i);
    void WriteBytes(const unsigned char* bytes, std::size_t count);
    void WriteBytes(const Buffer& m_buffer);
    void WriteBytes(const Buffer& m_buffer, std::size_t m_offset, std::size_t count);
    unsigned char* GetBuffer() const;
    std::size_t GetLength() const;
    void Reset();
    void Rewind(std::size_t numBytes);

private:
    unsigned char* m_buffer = nullptr;
    std::size_t m_size;
    std::size_t m_offset;
    bool m_bufferProvided;

    friend class Buffer;
    void ExpandBufferIfNeeded(std::size_t need);
};

class Buffer
{
public:
    TGVOIP_DISALLOW_COPY_AND_ASSIGN(Buffer); // use Buffer::CopyOf to copy contents explicitly
    Buffer();
    Buffer(Buffer&& other) noexcept;
    Buffer& operator=(Buffer&& other);
    Buffer(std::size_t capacity);
    Buffer(BufferOutputStream&& stream);
    ~Buffer();

    unsigned char& operator[](std::size_t i);
    const unsigned char& operator[](std::size_t i) const;

    unsigned char* operator*();
    const unsigned char* operator*() const;

    void CopyFrom(const Buffer& other, std::size_t count, std::size_t srcOffset = 0, std::size_t dstOffset = 0);
    void CopyFrom(const void* ptr, std::size_t dstOffset, std::size_t count);

    void Resize(std::size_t newSize);

    std::size_t Length() const;
    bool IsEmpty() const;

    static Buffer CopyOf(const Buffer& other);
    static Buffer CopyOf(const Buffer& other, std::size_t offset, std::size_t length);
    static Buffer Wrap(unsigned char* data, std::size_t size, std::function<void(void*)> freeFn, std::function<void*(void*, std::size_t)> reallocFn);

private:
    unsigned char* m_data;
    std::size_t m_length;
    std::function<void(void*)> m_freeFn;
    std::function<void*(void*, std::size_t)> m_reallocFn;
};

template <typename T, std::size_t size, typename AVG_T = T>
class HistoricBuffer
{
public:
    HistoricBuffer()
    {
        std::fill(m_data.begin(), m_data.end(), T{0});
    }

    AVG_T Average() const
    {
        AVG_T avg = AVG_T{0};
        for (T i : m_data)
        {
            avg += i;
        }
        return avg / AVG_T{size};
    }

    AVG_T Average(std::size_t firstN) const
    {
        AVG_T avg = AVG_T{0};
        for (std::size_t i = 0; i < firstN; i++)
        {
            avg += (*this)[i];
        }
        return avg / static_cast<AVG_T>(firstN);
    }

    AVG_T NonZeroAverage() const
    {
        AVG_T avg = AVG_T{0};
        int nonZeroCount = 0;
        for (T i : m_data)
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
        m_data[m_offset] = el;
        m_offset = (m_offset + 1) % size;
    }

    T Min() const
    {
        T min = std::numeric_limits<T>::max();
        for (T i : m_data)
        {
            if (i < min)
                min = i;
        }
        return min;
    }

    T Max() const
    {
        T max = std::numeric_limits<T>::min();
        for (T i : m_data)
            if (i > max)
                max = i;
        return max;
    }

    void Reset()
    {
        std::fill(m_data.begin(), m_data.end(), T{0});
        m_offset = 0;
    }

    T operator[](std::size_t i) const
    {
        assert(i < size);
        // [0] should return the most recent entry, [1] the one before it, and so on
        std::ptrdiff_t _i = m_offset - i - 1;
        if (_i < 0)
            _i = size + _i;
        return m_data[_i];
    }

    T& operator[](std::size_t i)
    {
        assert(i < size);
        // [0] should return the most recent entry, [1] the one before it, and so on
        std::ptrdiff_t _i = m_offset - i - 1;
        if (_i < 0)
            _i = size + _i;
        return m_data[_i];
    }

    std::size_t Size() const
    {
        return size;
    }

private:
    std::array<T, size> m_data;
    std::ptrdiff_t m_offset = 0;
};

template <std::size_t bufSize, std::size_t bufCount>
class BufferPool
{
public:
    TGVOIP_DISALLOW_COPY_AND_ASSIGN(BufferPool);
    BufferPool()
    {
        m_bufferStart = reinterpret_cast<unsigned char*>(std::malloc(bufSize * bufCount));
        if (m_bufferStart == nullptr)
            throw std::bad_alloc();
    }

    ~BufferPool()
    {
        assert(m_usedBuffers.none());
        std::free(m_bufferStart);
    }

    Buffer Get()
    {
        auto freeFn = [this](void* _buf)
        {
            assert(_buf != nullptr);
            unsigned char* buf = reinterpret_cast<unsigned char*>(_buf);
            std::size_t offset = buf - m_bufferStart;
            assert(offset % bufSize == 0);
            std::size_t index = offset / bufSize;
            assert(index < bufCount);

            MutexGuard m(m_mutex);
            assert(m_usedBuffers.test(index));
            m_usedBuffers[index] = 0;
        };
        auto resizeFn = [](void* buf, std::size_t newSize) -> void*
        {
            if (newSize > bufSize)
                throw std::invalid_argument("newSize>bufferSize");
            return buf;
        };
        MutexGuard m(m_mutex);
        for (std::size_t i = 0; i < bufCount; ++i)
        {
            if (!m_usedBuffers[i])
            {
                m_usedBuffers[i] = 1;
                return Buffer::Wrap(m_bufferStart + (bufSize * i), bufSize, freeFn, resizeFn);
            }
        }
        throw std::bad_alloc();
    }

private:
    std::bitset<bufCount> m_usedBuffers;
    unsigned char* m_bufferStart;
    mutable Mutex m_mutex;
};

} // namespace tgvoip

#endif // LIBTGVOIP_BUFFERINPUTSTREAM_H
