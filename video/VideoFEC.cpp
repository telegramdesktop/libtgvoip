//
// Created by Grishka on 24/03/2019.
//

#include "VideoFEC.h"
#include "../logging.h"
#include <cstdlib>

using namespace tgvoip;
using namespace tgvoip::video;

Buffer ParityFEC::Encode(const std::vector<Buffer>& packets)
{
    size_t maxSize = 0;

    for (const Buffer& pkt : packets)
    {
        maxSize = std::max(maxSize, pkt.Length());
    }
    Buffer result(maxSize + 2); // add 2 bytes for length
    uint8_t* _result = *result;
    memset(_result, 0, result.Length());
    for (const Buffer& pkt : packets)
    {
        for (size_t i = 0; i < pkt.Length(); i++)
        {
            _result[i] ^= pkt[i];
        }
        uint16_t len = static_cast<uint16_t>(pkt.Length());
        _result[maxSize + 0] ^= static_cast<uint8_t>(len >> 0);
        _result[maxSize + 1] ^= static_cast<uint8_t>(len >> 8);
    }

    return result;
}

Buffer ParityFEC::Decode(const std::vector<Buffer>& dataPackets, const Buffer& fecPacket)
{
    size_t maxSize = 0;
    for (const Buffer& pkt : dataPackets)
    {
        maxSize = std::max(maxSize, pkt.Length());
    }

    if (fecPacket.Length() < maxSize + 2)
    {
        LOGE("ParityFEC: FEC packet too small (%u, expected >=%u)", static_cast<unsigned int>(fecPacket.Length()), static_cast<unsigned int>(maxSize + 2));
        return Buffer();
    }
    Buffer result = Buffer::CopyOf(fecPacket);
    uint8_t* _result = *result;
    unsigned int emptyCount = 0;
    for (const Buffer& pkt : dataPackets)
    {
        if (pkt.Length() == 0)
        {
            emptyCount++;
            continue;
        }
        for (size_t i = 0; i < pkt.Length(); i++)
        {
            _result[i] ^= pkt[i];
        }
        uint16_t len = static_cast<uint16_t>(pkt.Length());
        _result[maxSize + 0] ^= static_cast<uint8_t>(len >> 0);
        _result[maxSize + 1] ^= static_cast<uint8_t>(len >> 8);
    }
    if (emptyCount != 1)
    {
        LOGE("ParityFEC: %u packets lost", emptyCount);
        return Buffer();
    }

    uint16_t len = static_cast<uint16_t>(_result[maxSize + 0] << 0) |
                   static_cast<uint16_t>(_result[maxSize + 1] << 8);
    if (len > maxSize)
    {
        LOGE("ParityFEC: incorrect length %u", len);
        return Buffer();
    }
    LOGV("ParityFEC decoded packet size %u", len);

    result.Resize(len);
    return result;
}
