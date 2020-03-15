//
// libtgvoip is free and unencumbered public domain software.
// For more information, see http://unlicense.org or the UNLICENSE file
// you should have received with this source code distribution.
//

#ifndef LIBTGVOIP_CONGESTIONCONTROL_H
#define LIBTGVOIP_CONGESTIONCONTROL_H

#include "Buffers.h"
#include "threading.h"
#include <cstdint>
#include <cstdlib>

namespace tgvoip
{

enum class ConctlAct
{
    NONE,
    INCREASE,
    DECREASE,
};

struct tgvoip_congestionctl_packet_t
{
    double sendTime;
    std::size_t size;
    std::uint32_t seq;
};
typedef struct tgvoip_congestionctl_packet_t tgvoip_congestionctl_packet_t;

class CongestionControl
{
public:
    CongestionControl();
    ~CongestionControl();

    void PacketSent(std::uint32_t seq, std::size_t size);
    void PacketLost(std::uint32_t seq);
    void PacketAcknowledged(std::uint32_t seq);
    void Tick();

    double GetAverageRTT() const;
    double GetMinimumRTT() const;
    std::size_t GetInflightDataSize() const;
    std::size_t GetCongestionWindow() const;
    std::size_t GetAcknowledgedDataSize() const;
    ConctlAct GetBandwidthControlAction() const;
    std::uint32_t GetSendLossCount() const;

private:
    HistoricBuffer<double, 100> m_rttHistory;
    HistoricBuffer<std::size_t, 30> m_inflightHistory;
    tgvoip_congestionctl_packet_t m_inflightPackets[100];
    double m_tmpRtt;
    int m_tmpRttCount;
    std::uint32_t m_lossCount;
    mutable double m_lastActionTime;
    double m_lastActionRtt;
    double m_stateTransitionTime;
    std::uint32_t m_lastSentSeq;
    std::uint32_t m_tickCount;
    std::size_t m_inflightDataSize;
    std::size_t m_cwnd;
};

} // namespace tgvoip

#endif // LIBTGVOIP_CONGESTIONCONTROL_H
