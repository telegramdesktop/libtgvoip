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

//#define TGVOIP_CONCTL_ACT_INCREASE 1
//#define TGVOIP_CONCTL_ACT_DECREASE 2
//#define TGVOIP_CONCTL_ACT_NONE 0

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
    size_t size;
    uint32_t seq;
};
typedef struct tgvoip_congestionctl_packet_t tgvoip_congestionctl_packet_t;

class CongestionControl
{
public:
    CongestionControl();
    ~CongestionControl();

    void PacketSent(uint32_t seq, size_t size);
    void PacketLost(uint32_t seq);
    void PacketAcknowledged(uint32_t seq);
    void Tick();

    double GetAverageRTT() const;
    double GetMinimumRTT() const;
    size_t GetInflightDataSize() const;
    size_t GetCongestionWindow() const;
    size_t GetAcknowledgedDataSize() const;
    ConctlAct GetBandwidthControlAction() const;
    uint32_t GetSendLossCount() const;

private:
    HistoricBuffer<double, 100> m_rttHistory;
    HistoricBuffer<size_t, 30> m_inflightHistory;
    tgvoip_congestionctl_packet_t m_inflightPackets[100];
    double m_tmpRtt;
    int m_tmpRttCount;
    uint32_t m_lossCount;
    mutable double m_lastActionTime;
    double m_lastActionRtt;
    double m_stateTransitionTime;
    uint32_t m_lastSentSeq;
    uint32_t m_tickCount;
    size_t m_inflightDataSize;
    size_t m_cwnd;
};

} // namespace tgvoip

#endif // LIBTGVOIP_CONGESTIONCONTROL_H
