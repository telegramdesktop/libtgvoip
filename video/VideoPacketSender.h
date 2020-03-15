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
    void PacketAcknowledged(std::uint32_t seq, double sendTime, double ackTime, std::uint8_t type, std::uint32_t size) override;
    void PacketLost(std::uint32_t seq, std::uint8_t type, std::uint32_t size) override;
    void SetSource(VideoSource* m_source);

    std::uint32_t GetBitrate() const
    {
        return m_currentVideoBitrate;
    }

private:
    struct SentVideoFrame
    {
        std::uint32_t seq;
        std::uint32_t fragmentCount;
        std::vector<std::uint32_t> unacknowledgedPackets;
        std::uint32_t fragmentsInQueue;
    };
    struct QueuedPacket
    {
        VoIPController::PendingOutgoingPacket packet;
        std::uint32_t seq;
    };

    void SendFrame(const Buffer& frame, std::uint32_t flags, std::uint32_t rotation);
    std::uint32_t GetVideoResolutionForCurrentBitrate();

    VideoSource* m_source = nullptr;
    std::shared_ptr<VoIPController::Stream> m_stm;
    video::ScreamCongestionController m_videoCongestionControl;
    double m_firstVideoFrameTime = 0.0;
    std::uint32_t m_videoFrameCount = 0;
    std::vector<SentVideoFrame> m_sentVideoFrames;
    bool m_videoKeyframeRequested = false;
    std::uint32_t m_sendVideoPacketID = MessageThread::INVALID_ID;
    std::uint32_t m_videoPacketLossCount = 0;
    std::uint32_t m_currentVideoBitrate = 0;
    double m_lastVideoResolutionChangeTime = 0.0;
    double m_sourceChangeTime = 0.0;

    std::vector<Buffer> m_packetsForFEC;
    std::size_t m_fecFrameCount = 0;
    std::uint32_t m_frameSeq = 0;
};

} // namespace video

} // namespace tgvoip

#endif // LIBTGVOIP_VIDEOPACKETSENDER_H
