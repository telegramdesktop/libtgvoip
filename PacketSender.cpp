#include "PacketSender.h"

using namespace tgvoip;

PacketSender::PacketSender(VoIPController* controller)
    : m_controller(controller)
{
}

PacketSender::~PacketSender()
{
}

void PacketSender::SendExtra(Buffer& data, unsigned char type) const
{
    m_controller->SendExtra(data, type);
}

void PacketSender::IncrementUnsentStreamPackets()
{
    ++m_controller->unsentStreamPackets;
}

std::uint32_t PacketSender::SendPacket(VoIPController::PendingOutgoingPacket pkt)
{
    std::uint32_t seq = m_controller->GenerateOutSeq();
    pkt.seq = seq;
    m_controller->SendOrEnqueuePacket(std::move(pkt), true, this);
    return seq;
}

double PacketSender::GetConnectionInitTime() const
{
    return m_controller->connectionInitTime;
}

const HistoricBuffer<double, 32>& PacketSender::RTTHistory() const
{
    return m_controller->rttHistory;
}

MessageThread& PacketSender::GetMessageThread()
{
    return m_controller->messageThread;
}

const MessageThread& PacketSender::GetMessageThread() const
{
    return m_controller->messageThread;
}

const VoIPController::ProtocolInfo& PacketSender::GetProtocolInfo() const
{
    return m_controller->protocolInfo;
}

void PacketSender::SendStreamFlags(VoIPController::Stream& stm) const
{
    m_controller->SendStreamFlags(stm);
}

const VoIPController::Config& PacketSender::GetConfig() const
{
    return m_controller->config;
}
