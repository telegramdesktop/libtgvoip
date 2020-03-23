//
// Created by Grishka on 19/03/2019.
//

#include "VideoPacketSender.h"
#include "../PrivateDefines.h"
#include "../logging.h"
#include "VideoFEC.h"
#include <algorithm>

using namespace tgvoip;
using namespace tgvoip::video;

VideoPacketSender::VideoPacketSender(VoIPController* controller, VideoSource* videoSource, std::shared_ptr<VoIPController::Stream> stream)
    : PacketSender(controller)
    , m_stm(stream)
{
    SetSource(videoSource);
}

VideoPacketSender::~VideoPacketSender()
{
}

std::uint32_t VideoPacketSender::GetBitrate() const
{
    return m_currentVideoBitrate;
}

void VideoPacketSender::PacketAcknowledged(std::uint32_t seq, double sendTime, double ackTime, PktType type, std::uint32_t size)
{
    std::uint32_t bytesNewlyAcked = 0;
    //if(!videoKeyframeRequested){
    // video frames are stored in sentVideoFrames in order of increasing numbers
    // so if a frame (or part of it) is acknowledged but isn't sentVideoFrames[0], we know there was a packet loss
    for (SentVideoFrame& f : m_sentVideoFrames)
    {
        for (std::vector<std::uint32_t>::iterator s = f.unacknowledgedPackets.begin(); s != f.unacknowledgedPackets.end();)
        {
            //RecentOutgoingPacket* opkt=GetRecentOutgoingPacket(*s);
            if (/*opkt && opkt->ackTime!=0.0*/ *s == seq)
            {
                s = f.unacknowledgedPackets.erase(s);
                //newlyAckedVideoBytes+=opkt->size;
                bytesNewlyAcked = size;
                break;
            }
            else
            {
                ++s;
            }
        }
    }
    for (std::vector<SentVideoFrame>::iterator f = m_sentVideoFrames.begin(); f != m_sentVideoFrames.end();)
    {
        if (f->unacknowledgedPackets.empty() && f->fragmentsInQueue == 0)
        {
            f = m_sentVideoFrames.erase(f);
            continue;
        }
        ++f;
    }
    //}
    if (bytesNewlyAcked)
    {
        float _sendTime = static_cast<float>(sendTime - GetConnectionInitTime());
        float recvTime = static_cast<float>(ackTime);
        float oneWayDelay = recvTime - _sendTime;
        //LOGV("one-way delay: %f", oneWayDelay);
        m_videoCongestionControl.ProcessAcks(oneWayDelay, bytesNewlyAcked, m_videoPacketLossCount, RTTHistory().Average(5));
    }
    //videoCongestionControl.GetPacingInterval();
}

void VideoPacketSender::PacketLost(std::uint32_t seq, PktType type, std::uint32_t size)
{
    if (type == PktType::STREAM_EC)
        return;
    LOGW("VideoPacketSender::PacketLost: %u (size %u)", seq, size);
    //LOGI("frame count %u", (unsigned int)sentVideoFrames.size());
    for (std::vector<SentVideoFrame>::iterator f = m_sentVideoFrames.begin(); f != m_sentVideoFrames.end(); ++f)
    {
        std::vector<std::uint32_t>::iterator pkt = std::find(f->unacknowledgedPackets.begin(), f->unacknowledgedPackets.end(), seq);
        if (pkt != f->unacknowledgedPackets.end())
        {
            LOGW("Lost packet belongs to frame %u", f->seq);
            m_videoPacketLossCount++;
            m_videoCongestionControl.ProcessPacketLost(size);
            if (!m_videoKeyframeRequested)
            {
                m_videoKeyframeRequested = true;
                m_source->RequestKeyFrame();
            }
            f->unacknowledgedPackets.erase(pkt);
            if (f->unacknowledgedPackets.empty() && f->fragmentsInQueue == 0)
            {
                m_sentVideoFrames.erase(f);
            }
            return;
        }
    }
    //std::abort();
}

void VideoPacketSender::SetSource(VideoSource* source)
{
    if (this->m_source == source)
        return;

    if (this->m_source)
    {
        this->m_source->Stop();
        this->m_source->SetCallback(nullptr);
        //delete this->source;
    }

    this->m_source = source;

    if (!source)
        return;

    m_sourceChangeTime = m_lastVideoResolutionChangeTime = VoIPController::GetCurrentTime();
    std::uint32_t bitrate = m_videoCongestionControl.GetBitrate();
    m_currentVideoBitrate = bitrate;
    source->SetBitrate(bitrate);
    source->Reset(m_stm->codec, m_stm->resolution = static_cast<int>(GetVideoResolutionForCurrentBitrate()));
    source->Start();
    source->SetCallback(std::bind(&VideoPacketSender::SendFrame, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
    source->SetStreamStateCallback([this](bool paused)
    {
        m_stm->paused = paused;
        GetMessageThread().Post([this]()
        {
            SendStreamFlags(*m_stm);
        });
    });
}

void VideoPacketSender::SendFrame(const Buffer& _frame, std::uint32_t flags, std::uint32_t rotation)
{
    std::shared_ptr<Buffer> framePtr = std::make_shared<Buffer>(Buffer::CopyOf(_frame));
    GetMessageThread().Post([this, framePtr, flags, rotation] {
        const Buffer& frame = *framePtr;

        double currentTime = VoIPController::GetCurrentTime();

        if (m_firstVideoFrameTime == 0.0)
            m_firstVideoFrameTime = currentTime;

        m_videoCongestionControl.UpdateMediaRate(static_cast<std::uint32_t>(frame.Length()));
        std::uint32_t bitrate = m_videoCongestionControl.GetBitrate();
        if (bitrate != m_currentVideoBitrate)
        {
            m_currentVideoBitrate = bitrate;
            LOGD("Setting video bitrate to %u", bitrate);
            m_source->SetBitrate(bitrate);
        }
        int resolutionFromBitrate = static_cast<int>(GetVideoResolutionForCurrentBitrate());
        if (resolutionFromBitrate != m_stm->resolution && currentTime - m_lastVideoResolutionChangeTime > 3.0 && currentTime - m_sourceChangeTime > 10.0)
        {
            LOGI("Changing video resolution: %d -> %d", m_stm->resolution, resolutionFromBitrate);
            m_stm->resolution = resolutionFromBitrate;
            GetMessageThread().Post([this, resolutionFromBitrate]
            {
                m_source->Reset(m_stm->codec, resolutionFromBitrate);
                m_stm->csdIsValid = false;
            });
            m_lastVideoResolutionChangeTime = currentTime;
            return;
        }

        if (m_videoKeyframeRequested)
        {
            if (flags & VIDEO_FRAME_FLAG_KEYFRAME)
            {
                m_videoKeyframeRequested = false;
            }
            else
            {
                LOGV("Dropping input video frame waiting for key frame");
                //return;
            }
        }

        std::uint32_t pts = m_videoFrameCount++;
        bool csdInvalidated = !m_stm->csdIsValid;
        if (!m_stm->csdIsValid)
        {
            std::vector<Buffer>& csd = m_source->GetCodecSpecificData();
            m_stm->codecSpecificData.clear();
            for (Buffer& b : csd)
            {
                m_stm->codecSpecificData.emplace_back(Buffer::CopyOf(b));
            }
            m_stm->csdIsValid = true;
            m_stm->width = m_source->GetFrameWidth();
            m_stm->height = m_source->GetFrameHeight();
            //SendStreamCSD();
        }

        Buffer csd;
        if (flags & VIDEO_FRAME_FLAG_KEYFRAME)
        {
            BufferOutputStream os(256);
            os.WriteUInt16(static_cast<std::uint16_t>(m_stm->width));
            os.WriteUInt16(static_cast<std::uint16_t>(m_stm->height));
            std::uint8_t sizeAndFlag = static_cast<std::uint8_t>(m_stm->codecSpecificData.size());
            if (csdInvalidated)
                sizeAndFlag |= 0x80;
            os.WriteUInt8(sizeAndFlag);
            for (const Buffer& b : m_stm->codecSpecificData)
            {
                assert(b.Length() < 255);
                os.WriteUInt8(static_cast<std::uint8_t>(b.Length()));
                os.WriteBytes(b);
            }
            csd = std::move(os);
        }

        ++m_frameSeq;
        std::size_t totalLength = csd.Length() + frame.Length();
        std::size_t segmentCount = totalLength / 1024;
        if (totalLength % 1024 > 0)
            ++segmentCount;
        SentVideoFrame sentFrame;
        sentFrame.seq = m_frameSeq;
        sentFrame.fragmentCount = static_cast<std::uint32_t>(segmentCount);
        sentFrame.fragmentsInQueue = 0; //static_cast<std::uint32_t>(segmentCount);
        std::size_t offset = 0;
        std::size_t packetSize = totalLength / segmentCount;
        for (std::size_t seg = 0; seg < segmentCount; ++seg)
        {
            BufferOutputStream pkt(1500);
            std::size_t len; //=std::min((std::size_t)1024, frame.Length()-offset);
            if (seg == segmentCount - 1)
            {
                len = frame.Length() - offset;
            }
            else
            {
                len = packetSize;
            }
            std::uint8_t pflags = STREAM_DATA_FLAG_LEN16;
            //pflags |= STREAM_DATA_FLAG_HAS_MORE_FLAGS;
            pkt.WriteUInt8(static_cast<std::uint8_t>(m_stm->id | pflags)); // streamID + flags
            std::uint16_t lengthAndFlags = static_cast<std::uint16_t>(len & 0x7FF);
            if (segmentCount > 1)
                lengthAndFlags |= STREAM_DATA_XFLAG_FRAGMENTED;
            if (flags & VIDEO_FRAME_FLAG_KEYFRAME)
                lengthAndFlags |= STREAM_DATA_XFLAG_KEYFRAME;
            pkt.WriteUInt16(lengthAndFlags);
            //pkt.WriteInt32(audioTimestampOut);
            pkt.WriteUInt32(pts);
            if (segmentCount > 1)
            {
                pkt.WriteUInt8(static_cast<std::uint8_t>(seg));
                pkt.WriteUInt8(static_cast<std::uint8_t>(segmentCount));
            }
            pkt.WriteUInt8(static_cast<std::uint8_t>(m_frameSeq));
            std::size_t dataOffset = pkt.GetLength();
            if (seg == 0)
            {
                VideoRotation _rotation;
                switch (rotation)
                {
                case 90:
                    _rotation = VideoRotation::_90;
                    break;
                case 180:
                    _rotation = VideoRotation::_180;
                    break;
                case 270:
                    _rotation = VideoRotation::_270;
                    break;
                case 0:
                default:
                    _rotation = VideoRotation::_0;
                    break;
                }
                pkt.WriteUInt8(static_cast<std::uint8_t>(_rotation));
                dataOffset++;

                if (!csd.IsEmpty())
                {
                    pkt.WriteBytes(csd);
                    len -= csd.Length();
                }
            }
            pkt.WriteBytes(frame, offset, len);
            //LOGV("Sending segment %u of %u, length %u", (unsigned int)seg, (unsigned int)segmentCount, (unsigned int)pkt.GetLength());

            Buffer fecPacketData(pkt.GetLength() - dataOffset);
            fecPacketData.CopyFrom(pkt.GetBuffer() + dataOffset, 0, pkt.GetLength() - dataOffset);
            m_packetsForFEC.emplace_back(std::move(fecPacketData));
            offset += len;

            Buffer packetData(std::move(pkt));

            std::size_t packetDataLength = packetData.Length();
            VoIPController::PendingOutgoingPacket p {
                /*.seq=*/0,
                /*.type=*/PktType::STREAM_DATA,
                /*.len=*/packetDataLength,
                /*.data=*/std::move(packetData),
                /*.endpoint=*/0,
            };
            IncrementUnsentStreamPackets();
            std::uint32_t seq = SendPacket(std::move(p));
            m_videoCongestionControl.ProcessPacketSent(static_cast<unsigned int>(pkt.GetLength()));
            sentFrame.unacknowledgedPackets.emplace_back(seq);
            //packetQueue.Put(QueuedPacket{std::move(p), sentFrame.seq});
        }
        ++m_fecFrameCount;
        if (m_fecFrameCount >= 3)
        {
            Buffer fecPacket = ParityFEC::Encode(m_packetsForFEC);

            m_packetsForFEC.clear();
            m_fecFrameCount = 0;
            LOGV("FEC packet length: %u", static_cast<unsigned int>(fecPacket.Length()));
            BufferOutputStream out(1500);
            out.WriteUInt8(m_stm->id);
            out.WriteUInt8(static_cast<std::uint8_t>(m_frameSeq));
            out.WriteUInt8(FEC_SCHEME_XOR);
            out.WriteUInt8(3);
            out.WriteUInt16(static_cast<std::uint16_t>(fecPacket.Length()));
            out.WriteBytes(fecPacket);

            VoIPController::PendingOutgoingPacket p
            {
                0,
                PktType::STREAM_EC,
                out.GetLength(),
                Buffer(std::move(out)),
                0
            };
            std::uint32_t seq = SendPacket(std::move(p));
        }
        m_sentVideoFrames.emplace_back(sentFrame);
    });
}

InitVideoRes VideoPacketSender::GetVideoResolutionForCurrentBitrate()
{
    InitVideoRes peerMaxVideoResolution = GetProtocolInfo().maxVideoResolution;
    InitVideoRes resolutionFromBitrate = InitVideoRes::_1080;
    if (VoIPController::GetCurrentTime() - m_sourceChangeTime > 10.0)
    {
        // TODO: probably move this to server config
        if (m_stm->codec == CODEC_AVC || m_stm->codec == CODEC_VP8)
        {
            if (m_currentVideoBitrate > 400000)
            {
                resolutionFromBitrate = InitVideoRes::_720;
            }
            else if (m_currentVideoBitrate > 250000)
            {
                resolutionFromBitrate = InitVideoRes::_480;
            }
            else
            {
                resolutionFromBitrate = InitVideoRes::_360;
            }
        }
        else if (m_stm->codec == CODEC_HEVC || m_stm->codec == CODEC_VP9)
        {
            if (m_currentVideoBitrate > 400000)
            {
                resolutionFromBitrate = InitVideoRes::_1080;
            }
            else if (m_currentVideoBitrate > 250000)
            {
                resolutionFromBitrate = InitVideoRes::_720;
            }
            else if (m_currentVideoBitrate > 100000)
            {
                resolutionFromBitrate = InitVideoRes::_480;
            }
            else
            {
                resolutionFromBitrate = InitVideoRes::_360;
            }
        }
    }
    else
    {
        if (m_stm->codec == CODEC_AVC || m_stm->codec == CODEC_VP8)
            resolutionFromBitrate = InitVideoRes::_720;
        else if (m_stm->codec == CODEC_HEVC || m_stm->codec == CODEC_VP9)
            resolutionFromBitrate = InitVideoRes::_1080;
    }
    return static_cast<InitVideoRes>(std::min(static_cast<std::uint8_t>(peerMaxVideoResolution),
                                              static_cast<std::uint8_t>(resolutionFromBitrate)));
}
