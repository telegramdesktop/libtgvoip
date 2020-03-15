//
// Created by Grishka on 19.03.2018.
//

#ifndef TGVOIP_PACKETREASSEMBLER_H
#define TGVOIP_PACKETREASSEMBLER_H

#include <functional>
#include <memory>
#include <unordered_map>
#include <vector>

#include "Buffers.h"
#include "logging.h"

namespace tgvoip
{
class PacketReassembler
{
public:
    PacketReassembler();
    virtual ~PacketReassembler();

    void Reset();
    void AddFragment(Buffer pkt, unsigned int fragmentIndex, unsigned int fragmentCount, std::uint32_t pts, std::uint8_t fseq, bool keyframe, std::uint16_t rotation);
    void AddFEC(Buffer data, std::uint8_t fseq, unsigned int frameCount, unsigned int fecScheme);
    void SetCallback(std::function<void(Buffer packet, std::uint32_t pts, bool keyframe, std::uint16_t rotation)> callback);

private:
    struct Packet
    {
        std::uint32_t seq;
        std::uint32_t timestamp;
        std::uint32_t partCount;
        std::uint32_t receivedPartCount;
        bool isKeyframe;
        std::uint16_t rotation;
        std::vector<Buffer> parts;

        Packet(std::uint32_t seq, std::uint32_t timestamp, std::uint32_t partCount, std::uint32_t receivedPartCount, bool keyframe, std::uint16_t rotation)
            : seq(seq)
            , timestamp(timestamp)
            , partCount(partCount)
            , receivedPartCount(receivedPartCount)
            , isKeyframe(keyframe)
            , rotation(rotation)
        {
        }

        void AddFragment(Buffer pkt, std::uint32_t fragmentIndex);
        Buffer Reassemble();
    };
    struct FecPacket
    {
        std::uint32_t seq;
        std::uint32_t prevFrameCount;
        std::uint32_t fecScheme;
        Buffer data;
    };

    bool TryDecodeFEC(FecPacket& fec);

    std::function<void(Buffer, std::uint32_t, bool, std::uint16_t)> callback;
    std::vector<std::unique_ptr<Packet>> packets;
    std::vector<std::unique_ptr<Packet>> oldPackets; // for FEC
    std::vector<FecPacket> fecPackets;
    std::uint32_t maxTimestamp = 0;
    std::uint32_t lastFrameSeq = 0;
    bool waitingForFEC = false;
};
}

#endif //TGVOIP_PACKETREASSEMBLER_H
