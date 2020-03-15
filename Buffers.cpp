//
// libtgvoip is free and unencumbered public domain software.
// For more information, see http://unlicense.org or the UNLICENSE file
// you should have received with this source code distribution.
//

#include "Buffers.h"
#include "logging.h"
#include <cassert>
#include <exception>
#include <stdexcept>
#include <cstdlib>
#include <cstring>

using namespace tgvoip;

#pragma mark - Buffer

Buffer::Buffer(size_t capacity)
    : m_data(nullptr)
    , m_length(capacity)
{
    if (capacity > 0)
    {
        m_data = reinterpret_cast<unsigned char*>(std::malloc(capacity));
        if (m_data == nullptr)
            throw std::bad_alloc();
    }
}

Buffer::Buffer(Buffer&& other) noexcept
    : m_data(other.m_data)
    , m_length(other.m_length)
    , m_freeFn(other.m_freeFn)
    , m_reallocFn(other.m_reallocFn)
{
    other.m_data = nullptr;
}

Buffer::Buffer(BufferOutputStream&& stream)
    : m_data(stream.m_buffer)
    , m_length(stream.m_offset)
{
    stream.m_buffer = nullptr;
}

Buffer::Buffer()
    : m_data(nullptr)
    , m_length(0)
{
}

Buffer::~Buffer()
{
    if (m_data != nullptr)
    {
        if (m_freeFn)
            m_freeFn(m_data);
        else
            std::free(m_data);
    }
    m_data = nullptr;
    m_length = 0;
}

Buffer& Buffer::operator=(Buffer&& other)
{
    if (this != &other)
    {
        if (m_data != nullptr)
        {
            if (m_freeFn)
                m_freeFn(m_data);
            else
                std::free(m_data);
        }
        m_data = other.m_data;
        m_length = other.m_length;
        m_freeFn = other.m_freeFn;
        m_reallocFn = other.m_reallocFn;
        other.m_data = nullptr;
        other.m_length = 0;
    }
    return *this;
}

unsigned char& Buffer::operator[](size_t i)
{
    if (i >= m_length)
        throw std::out_of_range("");
    return m_data[i];
}

const unsigned char& Buffer::operator[](size_t i) const
{
    if (i >= m_length)
        throw std::out_of_range("");
    return m_data[i];
}

unsigned char* Buffer::operator*()
{
    return m_data;
}

const unsigned char* Buffer::operator*() const
{
    return m_data;
}

void Buffer::CopyFrom(const Buffer& other, size_t count, size_t srcOffset, size_t dstOffset)
{
    if (other.m_data == nullptr)
        throw std::invalid_argument("CopyFrom can't copy from NULL");
    if (other.m_length < srcOffset + count || m_length < dstOffset + count)
        throw std::out_of_range("Out of offset+count bounds of either buffer");
    std::memcpy(m_data + dstOffset, other.m_data + srcOffset, count);
}

void Buffer::CopyFrom(const void* ptr, size_t dstOffset, size_t count)
{
    if (m_length < dstOffset + count)
        throw std::out_of_range("Offset+count is out of bounds");
    std::memcpy(m_data + dstOffset, ptr, count);
}

void Buffer::Resize(size_t newSize)
{
    if (m_reallocFn)
        m_data = reinterpret_cast<unsigned char*>(m_reallocFn(m_data, newSize));
    else
        m_data = reinterpret_cast<unsigned char*>(std::realloc(m_data, newSize));
    if (m_data == nullptr)
        throw std::bad_alloc();
    m_length = newSize;
}

size_t Buffer::Length() const
{
    return m_length;
}

bool Buffer::IsEmpty() const
{
    return (m_length == 0) || (m_data == nullptr);
}

Buffer Buffer::CopyOf(const Buffer& other)
{
    if (other.IsEmpty())
        return Buffer();
    Buffer buf(other.m_length);
    buf.CopyFrom(other, other.m_length);
    return buf;
}

Buffer Buffer::CopyOf(const Buffer& other, size_t offset, size_t length)
{
    if (offset + length > other.Length())
        throw std::out_of_range("offset+length out of bounds");
    Buffer buf(length);
    buf.CopyFrom(other, length, offset);
    return buf;
}

Buffer Buffer::Wrap(unsigned char* data, size_t size, std::function<void(void*)> freeFn, std::function<void*(void*, size_t)> reallocFn)
{
    Buffer b = Buffer();
    b.m_data = data;
    b.m_length = size;
    b.m_freeFn = freeFn;
    b.m_reallocFn = reallocFn;
    return b;
}

#pragma mark - BufferInputStream

BufferInputStream::BufferInputStream(const unsigned char* data, size_t length)
    : m_buffer(data)
    , m_length(length)
    , m_offset(0)
{
}

BufferInputStream::BufferInputStream(const Buffer& buffer)
    : m_buffer(*buffer)
    , m_length(buffer.Length())
    , m_offset(0)
{
}

void BufferInputStream::Seek(size_t offset)
{
    if (offset > m_length)
    {
        throw std::out_of_range("Not enough bytes in buffer");
    }
    this->m_offset = offset;
}

size_t BufferInputStream::GetLength()
{
    return m_length;
}

size_t BufferInputStream::GetOffset()
{
    return m_offset;
}

size_t BufferInputStream::Remaining()
{
    return m_length - m_offset;
}

unsigned char BufferInputStream::ReadByte()
{
    EnsureEnoughRemaining(1);
    return m_buffer[m_offset++];
}

int32_t BufferInputStream::ReadInt32()
{
    EnsureEnoughRemaining(4);
    int32_t res = ((static_cast<int32_t>(m_buffer[m_offset + 0]) & 0xFF) <<  0) |
                  ((static_cast<int32_t>(m_buffer[m_offset + 1]) & 0xFF) <<  8) |
                  ((static_cast<int32_t>(m_buffer[m_offset + 2]) & 0xFF) << 16) |
                  ((static_cast<int32_t>(m_buffer[m_offset + 3]) & 0xFF) << 24);
    m_offset += 4;
    return res;
}

int64_t BufferInputStream::ReadInt64()
{
    EnsureEnoughRemaining(8);
    int64_t res = ((static_cast<int64_t>(m_buffer[m_offset + 0]) & 0xFF) <<  0) |
                  ((static_cast<int64_t>(m_buffer[m_offset + 1]) & 0xFF) <<  8) |
                  ((static_cast<int64_t>(m_buffer[m_offset + 2]) & 0xFF) << 16) |
                  ((static_cast<int64_t>(m_buffer[m_offset + 3]) & 0xFF) << 24) |
                  ((static_cast<int64_t>(m_buffer[m_offset + 4]) & 0xFF) << 32) |
                  ((static_cast<int64_t>(m_buffer[m_offset + 5]) & 0xFF) << 40) |
                  ((static_cast<int64_t>(m_buffer[m_offset + 6]) & 0xFF) << 48) |
                  ((static_cast<int64_t>(m_buffer[m_offset + 7]) & 0xFF) << 56);
    m_offset += 8;
    return res;
}

int16_t BufferInputStream::ReadInt16()
{
    EnsureEnoughRemaining(2);
    int16_t res = static_cast<int16_t>(((m_buffer[m_offset + 0]) & 0xFF) << 0) |
                  static_cast<int16_t>(((m_buffer[m_offset + 1]) & 0xFF) << 8);
    m_offset += 2;
    return res;
}

int32_t BufferInputStream::ReadTlLength()
{
    unsigned char l = ReadByte();
    if (l < 254)
        return l;
    assert(m_length - m_offset >= 3);
    EnsureEnoughRemaining(3);
    int32_t res = ((static_cast<int32_t>(m_buffer[m_offset + 0]) & 0xFF) <<  0) |
                  ((static_cast<int32_t>(m_buffer[m_offset + 1]) & 0xFF) <<  8) |
                  ((static_cast<int32_t>(m_buffer[m_offset + 2]) & 0xFF) << 16);
    m_offset += 3;
    return res;
}

void BufferInputStream::ReadBytes(unsigned char* to, size_t count)
{
    EnsureEnoughRemaining(count);
    std::memcpy(to, m_buffer + m_offset, count);
    m_offset += count;
}

void BufferInputStream::ReadBytes(Buffer& to)
{
    ReadBytes(*to, to.Length());
}

BufferInputStream BufferInputStream::GetPartBuffer(size_t length, bool advance)
{
    EnsureEnoughRemaining(length);
    BufferInputStream s = BufferInputStream(m_buffer + m_offset, length);
    if (advance)
        m_offset += length;
    return s;
}

void BufferInputStream::EnsureEnoughRemaining(size_t need)
{
    if (m_length - m_offset < need)
    {
        throw std::out_of_range("Not enough bytes in buffer");
    }
}

#pragma mark - BufferOutputStream

BufferOutputStream::BufferOutputStream(size_t size)
    : m_buffer(reinterpret_cast<unsigned char*>(malloc(size)))
    , m_size(size)
    , m_offset(0)
    , m_bufferProvided(false)
{
    if (m_buffer == nullptr)
        throw std::bad_alloc();
}

BufferOutputStream::BufferOutputStream(unsigned char* buffer, size_t size)
    : m_buffer(buffer)
    , m_size(size)
    , m_offset(0)
    , m_bufferProvided(true)
{
}

BufferOutputStream& BufferOutputStream::operator=(BufferOutputStream&& other)
{
    if (this != &other)
    {
        if (!m_bufferProvided && m_buffer != nullptr)
            std::free(m_buffer);
        m_buffer = other.m_buffer;
        m_offset = other.m_offset;
        m_size = other.m_size;
        m_bufferProvided = other.m_bufferProvided;
        other.m_buffer = nullptr;
    }
    return *this;
}

BufferOutputStream::~BufferOutputStream()
{
    if (!m_bufferProvided && m_buffer != nullptr)
        std::free(m_buffer);
}

void BufferOutputStream::WriteByte(unsigned char byte)
{
    this->ExpandBufferIfNeeded(1);
    m_buffer[m_offset++] = byte;
}

void BufferOutputStream::WriteInt32(int32_t i)
{
    this->ExpandBufferIfNeeded(4);
    m_buffer[m_offset + 3] = static_cast<unsigned char>((i >> 24) & 0xFF);
    m_buffer[m_offset + 2] = static_cast<unsigned char>((i >> 16) & 0xFF);
    m_buffer[m_offset + 1] = static_cast<unsigned char>((i >>  8) & 0xFF);
    m_buffer[m_offset + 0] = static_cast<unsigned char>((i >>  0) & 0xFF);
    m_offset += 4;
}

void BufferOutputStream::WriteInt64(int64_t i)
{
    this->ExpandBufferIfNeeded(8);
    m_buffer[m_offset + 7] = static_cast<unsigned char>((i >> 56) & 0xFF);
    m_buffer[m_offset + 6] = static_cast<unsigned char>((i >> 48) & 0xFF);
    m_buffer[m_offset + 5] = static_cast<unsigned char>((i >> 40) & 0xFF);
    m_buffer[m_offset + 4] = static_cast<unsigned char>((i >> 32) & 0xFF);
    m_buffer[m_offset + 3] = static_cast<unsigned char>((i >> 24) & 0xFF);
    m_buffer[m_offset + 2] = static_cast<unsigned char>((i >> 16) & 0xFF);
    m_buffer[m_offset + 1] = static_cast<unsigned char>((i >>  8) & 0xFF);
    m_buffer[m_offset + 0] = static_cast<unsigned char>((i >>  0) & 0xFF);
    m_offset += 8;
}

void BufferOutputStream::WriteInt16(int16_t i)
{
    this->ExpandBufferIfNeeded(2);
    m_buffer[m_offset + 1] = static_cast<unsigned char>((i >> 8) & 0xFF);
    m_buffer[m_offset + 0] = static_cast<unsigned char>((i >> 0) & 0xFF);
    m_offset += 2;
}

void BufferOutputStream::WriteBytes(const unsigned char* bytes, size_t count)
{
    this->ExpandBufferIfNeeded(count);
    std::memcpy(m_buffer + m_offset, bytes, count);
    m_offset += count;
}

void BufferOutputStream::WriteBytes(const Buffer& buffer)
{
    WriteBytes(*buffer, buffer.Length());
}

void BufferOutputStream::WriteBytes(const Buffer& buffer, size_t offset, size_t count)
{
    if (offset + count > buffer.Length())
        throw std::out_of_range("offset out of buffer bounds");
    WriteBytes(*buffer + offset, count);
}

unsigned char* BufferOutputStream::GetBuffer()
{
    return m_buffer;
}

size_t BufferOutputStream::GetLength()
{
    return m_offset;
}

void BufferOutputStream::ExpandBufferIfNeeded(size_t need)
{
    if (m_offset + need > m_size)
    {
        if (m_bufferProvided)
        {
            throw std::out_of_range("buffer overflow");
        }
        unsigned char* new_buffer;
        need = std::max(need, size_t {1024});
        new_buffer = reinterpret_cast<unsigned char*>(std::realloc(m_buffer, m_size + need));
        if (new_buffer == nullptr)
        {
            std::free(m_buffer);
            m_buffer = nullptr;
            throw std::bad_alloc();
        }
        m_buffer = new_buffer;
        m_size += need;
    }
}

void BufferOutputStream::Reset()
{
    m_offset = 0;
}

void BufferOutputStream::Rewind(size_t numBytes)
{
    if (numBytes > m_offset)
        throw std::out_of_range("buffer underflow");
    m_offset -= numBytes;
}
