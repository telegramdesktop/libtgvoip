//
// Created by Grishka on 19/03/2019.
//

#ifndef LIBTGVOIP_VIDEOPACKETSENDER_H
#define LIBTGVOIP_VIDEOPACKETSENDER_H

#include "../Buffers.h"
#include "../PacketSender.h"
#include "../threading.h"
#include <memory>
#include <cstdint>
#include <vector>

namespace tgvoip
{

namespace video
{

class VideoSource;

class VideoPacketSender : public PacketSender
{
public:
    VideoPacketSender(VoIPController* controller, VideoSource* videoSource, std::shared_ptr<VoIPController::Stream> stream);
    ~VideoPacketSender() override;
    void PacketAcknowledged(uint32_t seq, double sendTime, double ackTime, uint8_t type, uint32_t size) override;
    void PacketLost(uint32_t seq, uint8_t type, uint32_t size) override;
    void SetSource(VideoSource* m_source);

    uint32_t GetBitrate() const
    {
        return m_currentVideoBitrate;
    }

private:
    struct SentVideoFrame
    {
        uint32_t seq;
        uint32_t fragmentCount;
        std::vector<uint32_t> unacknowledgedPackets;
        uint32_t fragmentsInQueue;
    };
    struct QueuedPacket
    {
        VoIPController::PendingOutgoingPacket packet;
        uint32_t seq;
    };

    void SendFrame(const Buffer& frame, uint32_t flags, uint32_t rotation);
    uint32_t GetVideoResolutionForCurrentBitrate();

    VideoSource* m_source = nullptr;
    std::shared_ptr<VoIPController::Stream> m_stm;
    video::ScreamCongestionController m_videoCongestionControl;
    double m_firstVideoFrameTime = 0.0;
    uint32_t m_videoFrameCount = 0;
    std::vector<SentVideoFrame> m_sentVideoFrames;
    bool m_videoKeyframeRequested = false;
    uint32_t m_sendVideoPacketID = MessageThread::INVALID_ID;
    uint32_t m_videoPacketLossCount = 0;
    uint32_t m_currentVideoBitrate = 0;
    double m_lastVideoResolutionChangeTime = 0.0;
    double m_sourceChangeTime = 0.0;

    std::vector<Buffer> m_packetsForFEC;
    size_t m_fecFrameCount = 0;
    uint32_t m_frameSeq = 0;
};

} // namespace video

} // namespace tgvoip

#endif // LIBTGVOIP_VIDEOPACKETSENDER_H
