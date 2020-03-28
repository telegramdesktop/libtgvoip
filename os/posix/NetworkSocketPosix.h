//
// libtgvoip is free and unencumbered public domain software.
// For more information, see http://unlicense.org or the UNLICENSE file
// you should have received with this source code distribution.
//

#ifndef LIBTGVOIP_NETWORKSOCKETPOSIX_H
#define LIBTGVOIP_NETWORKSOCKETPOSIX_H

#include "../../Buffers.h"
#include "../../NetworkSocket.h"

#include <pthread.h>
#include <sys/select.h>

#include <cstdint>
#include <mutex>
#include <string>

namespace tgvoip
{

class SocketSelectCancellerPosix : public SocketSelectCanceller
{
    friend class NetworkSocketPosix;

public:
    SocketSelectCancellerPosix();
    virtual ~SocketSelectCancellerPosix();
    virtual void CancelSelect();

private:
    int m_pipeRead;
    int m_pipeWrite;
};

class NetworkSocketPosix : public NetworkSocket
{
public:
    NetworkSocketPosix(NetworkProtocol m_protocol);
    virtual ~NetworkSocketPosix() override;
    virtual void Send(NetworkPacket packet) override;
    virtual NetworkPacket Receive(std::size_t maxLen) override;
    virtual void Open() override;
    virtual void Close() override;
    virtual void Connect(const NetworkAddress& address, std::uint16_t port) override;
    virtual std::string GetLocalInterfaceInfo(NetworkAddress* v4addr, NetworkAddress* v6addr) override;
    virtual void OnActiveInterfaceChanged() override;
    virtual std::uint16_t GetLocalPort() override;

    static std::string V4AddressToString(std::uint32_t address);
    static std::string V6AddressToString(const std::uint8_t address[16]);
    static std::uint32_t StringToV4Address(const std::string& address);
    static void StringToV6Address(const std::string& address, std::uint8_t* out);
    static NetworkAddress ResolveDomainName(const std::string& name);
    static bool Select(std::list<NetworkSocket*>& readFds, std::list<NetworkSocket*>& writeFds,
                       std::list<NetworkSocket*>& errorFds, SocketSelectCanceller* canceller);

    virtual NetworkAddress GetConnectedAddress() override;
    virtual std::uint16_t GetConnectedPort() override;

    virtual void SetTimeouts(int sendTimeout, int recvTimeout) override;
    virtual bool OnReadyToSend() override;

protected:
    virtual void SetMaxPriority() override;

private:
    Buffer m_recvBuffer = Buffer(2048);
    NetworkPacket m_pendingOutgoingPacket = NetworkPacket::Empty();
    NetworkAddress m_tcpConnectedAddress = NetworkAddress::Empty();

    double m_switchToV6at;
    std::mutex m_mutexFd;

    std::atomic<int> m_fd;

    std::uint16_t m_tcpConnectedPort;

    std::atomic<bool> m_isV4Available;
    std::atomic<bool> m_closing;
    bool m_needUpdateNat64Prefix;
    bool m_nat64Present;

    static int GetDescriptorFromSocket(NetworkSocket* socket);
};

} // namespace tgvoip

#endif // LIBTGVOIP_NETWORKSOCKETPOSIX_H
