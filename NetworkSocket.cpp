//
// Created by Grishka on 29.03.17.
//

#include <algorithm>
#include <stdexcept>
#include <cstdlib>
#include <cstring>
#if defined(_WIN32)
#include "os/windows/NetworkSocketWinsock.h"
#include <winsock2.h>
#else
#include "os/posix/NetworkSocketPosix.h"
#endif
#include "Buffers.h"
#include "NetworkSocket.h"
#include "VoIPController.h"
#include "VoIPServerConfig.h"
#include "logging.h"

#define MIN_UDP_PORT 16384
#define MAX_UDP_PORT 32768

using namespace tgvoip;

NetworkAddress::NetworkAddress()
{
}

NetworkPacket::NetworkPacket(Buffer data, NetworkAddress address, std::uint16_t port, NetworkProtocol protocol)
    : data(std::move(data))
    , address(address)
    , port(port)
    , protocol(protocol)
{
}

NetworkPacket NetworkPacket::Empty()
{
    return NetworkPacket{ Buffer(), NetworkAddress::Empty(), 0, NetworkProtocol::UDP };
}

bool NetworkPacket::IsEmpty() const
{
    return data.IsEmpty() || (protocol == NetworkProtocol::UDP && (port == 0 || address.IsEmpty()));
}

NetworkSocket::NetworkSocket(NetworkProtocol protocol)
    : m_ipv6Timeout(ServerConfig::GetSharedInstance()->GetDouble("nat64_fallback_timeout", 3))
    , m_protocol(protocol)
    , m_failed(false)
{
}

NetworkSocket::~NetworkSocket()
{
}

std::string NetworkSocket::GetLocalInterfaceInfo(NetworkAddress* inet4addr, NetworkAddress* inet6addr)
{
    return "not implemented";
}

std::uint16_t NetworkSocket::GenerateLocalPort()
{
    std::uint16_t rnd;
    VoIPController::crypto.rand_bytes(reinterpret_cast<std::uint8_t*>(&rnd), 2);
    return static_cast<std::uint16_t>((rnd % (MAX_UDP_PORT - MIN_UDP_PORT)) + MIN_UDP_PORT);
}

void NetworkSocket::SetMaxPriority()
{
}

std::uint16_t NetworkSocket::GetLocalPort()
{
    return 0;
}

void NetworkSocket::OnActiveInterfaceChanged()
{
}

NetworkAddress NetworkSocket::GetConnectedAddress()
{
    return NetworkAddress::Empty();
}

std::uint16_t NetworkSocket::GetConnectedPort()
{
    return 0;
}

void NetworkSocket::SetTimeouts(int sendTimeout, int recvTimeout)
{
}

bool NetworkSocket::IsFailed() const
{
    return m_failed;
}

bool NetworkSocket::IsReadyToSend() const
{
    return m_readyToSend;
}

bool NetworkSocket::OnReadyToSend()
{
    m_readyToSend = true;
    return true;
}

bool NetworkSocket::OnReadyToReceive()
{
    return true;
}

void NetworkSocket::SetTimeout(double timeout)
{
    m_timeout = timeout;
}

NetworkSocket* NetworkSocket::Create(NetworkProtocol protocol)
{
#ifndef _WIN32
    return new NetworkSocketPosix(protocol);
#else
    return new NetworkSocketWinsock(protocol);
#endif
}

NetworkAddress NetworkSocket::ResolveDomainName(std::string name)
{
#ifndef _WIN32
    return NetworkSocketPosix::ResolveDomainName(name);
#else
    return NetworkSocketWinsock::ResolveDomainName(name);
#endif
}

void NetworkSocket::GenerateTCPO2States(unsigned char* buffer, TCPO2State* recvState, TCPO2State* sendState)
{
    std::memset(recvState, 0, sizeof(TCPO2State));
    std::memset(sendState, 0, sizeof(TCPO2State));
    unsigned char nonce[64];
    std::uint32_t *first = reinterpret_cast<std::uint32_t*>(nonce), *second = first + 1;
    std::uint32_t first1 = 0x44414548U, first2 = 0x54534f50U, first3 = 0x20544547U, first4 = 0x20544547U, first5 = 0xeeeeeeeeU;
    std::uint32_t second1 = 0;
    do
    {
        VoIPController::crypto.rand_bytes(nonce, sizeof(nonce));
    } while (*first == first1 || *first == first2 || *first == first3 || *first == first4 || *first == first5 || *second == second1 || *reinterpret_cast<unsigned char*>(nonce) == 0xef);

    // prepare encryption key/iv
    std::memcpy(sendState->key, nonce + 8, 32);
    std::memcpy(sendState->iv, nonce + 8 + 32, 16);

    // prepare decryption key/iv
    char reversed[48];
    std::memcpy(reversed, nonce + 8, sizeof(reversed));
    std::reverse(reversed, reversed + sizeof(reversed));
    std::memcpy(recvState->key, reversed, 32);
    std::memcpy(recvState->iv, reversed + 32, 16);

    // write protocol identifier
    *reinterpret_cast<std::uint32_t*>(nonce + 56) = 0xefefefefU;
    std::memcpy(buffer, nonce, 56);
    EncryptForTCPO2(nonce, sizeof(nonce), sendState);
    std::memcpy(buffer + 56, nonce + 56, 8);
}

void NetworkSocket::EncryptForTCPO2(unsigned char* buffer, std::size_t len, TCPO2State* state)
{
    VoIPController::crypto.aes_ctr_encrypt(buffer, len, state->key, state->iv, state->ecount, &state->num);
}

std::size_t NetworkSocket::Receive(unsigned char* buffer, std::size_t len)
{
    NetworkPacket pkt = Receive(len);
    if (pkt.IsEmpty())
        return 0;
    std::size_t actualLen = std::min(len, pkt.data.Length());
    std::memcpy(buffer, *pkt.data, actualLen);
    return actualLen;
}

NetworkSocketWrapper::NetworkSocketWrapper(NetworkProtocol protocol)
    : NetworkSocket(protocol)
{
}

NetworkSocketWrapper::~NetworkSocketWrapper()
{
}

void NetworkSocketWrapper::SetNonBlocking(bool)
{
}

bool NetworkAddress::operator==(const NetworkAddress& other) const
{
    if (isIPv6 != other.isIPv6)
        return false;
    if (!isIPv6)
    {
        return addr.ipv4 == other.addr.ipv4;
    }
    return std::memcmp(addr.ipv6, other.addr.ipv6, 16) == 0;
}

bool NetworkAddress::operator!=(const NetworkAddress& other) const
{
    return !(*this == other);
}

std::string NetworkAddress::ToString() const
{
    if (isIPv6)
    {
#ifndef _WIN32
        return NetworkSocketPosix::V6AddressToString(addr.ipv6);
#else
        return NetworkSocketWinsock::V6AddressToString(addr.ipv6);
#endif
    }
    else
    {
#ifndef _WIN32
        return NetworkSocketPosix::V4AddressToString(addr.ipv4);
#else
        return NetworkSocketWinsock::V4AddressToString(addr.ipv4);
#endif
    }
}

bool NetworkAddress::IsEmpty() const
{
    if (isIPv6)
    {
        const std::uint64_t* a = reinterpret_cast<const std::uint64_t*>(addr.ipv6);
        return a[0] == 0LL && a[1] == 0LL;
    }
    return addr.ipv4 == 0;
}

bool NetworkAddress::PrefixMatches(const unsigned int prefix, const NetworkAddress& other) const
{
    if (isIPv6 != other.isIPv6)
        return false;
    if (!isIPv6)
    {
        std::uint32_t mask = 0xFFFFFFFF << (32 - prefix);
        return (addr.ipv4 & mask) == (other.addr.ipv4 & mask);
    }
    return false;
}

NetworkAddress NetworkAddress::Empty()
{
    NetworkAddress addr;
    addr.isIPv6 = false;
    addr.addr.ipv4 = 0;
    return addr;
}

NetworkAddress NetworkAddress::IPv4(std::string str)
{
    NetworkAddress addr;
    addr.isIPv6 = false;
#ifndef _WIN32
    addr.addr.ipv4 = NetworkSocketPosix::StringToV4Address(str);
#else
    addr.addr.ipv4 = NetworkSocketWinsock::StringToV4Address(str);
#endif
    return addr;
}

NetworkAddress NetworkAddress::IPv4(std::uint32_t addr)
{
    NetworkAddress a;
    a.isIPv6 = false;
    a.addr.ipv4 = addr;
    return a;
}

NetworkAddress NetworkAddress::IPv6(std::string str)
{
    NetworkAddress addr;
    addr.isIPv6 = false;
#ifndef _WIN32
    NetworkSocketPosix::StringToV6Address(str, addr.addr.ipv6);
#else
    NetworkSocketWinsock::StringToV6Address(str, addr.addr.ipv6);
#endif
    return addr;
}

NetworkAddress NetworkAddress::IPv6(const std::uint8_t addr[16])
{
    NetworkAddress a;
    a.isIPv6 = true;
    std::memcpy(a.addr.ipv6, addr, 16);
    return a;
}

bool NetworkSocket::Select(std::vector<NetworkSocket*>& readFds, std::vector<NetworkSocket*>& writeFds, std::vector<NetworkSocket*>& errorFds, SocketSelectCanceller* canceller)
{
#ifndef _WIN32
    return NetworkSocketPosix::Select(readFds, writeFds, errorFds, canceller);
#else
    return NetworkSocketWinsock::Select(readFds, writeFds, errorFds, canceller);
#endif
}

SocketSelectCanceller::~SocketSelectCanceller()
{
}

SocketSelectCanceller* SocketSelectCanceller::Create()
{
#ifndef _WIN32
    return new SocketSelectCancellerPosix();
#else
    return new SocketSelectCancellerWin32();
#endif
}

NetworkSocketTCPObfuscated::NetworkSocketTCPObfuscated(NetworkSocket* wrapped)
    : NetworkSocketWrapper(NetworkProtocol::TCP)
    , m_wrapped(wrapped)
{
}

NetworkSocketTCPObfuscated::~NetworkSocketTCPObfuscated()
{
    if (m_wrapped)
        delete m_wrapped;
}

NetworkSocket* NetworkSocketTCPObfuscated::GetWrapped()
{
    return m_wrapped;
}

void NetworkSocketTCPObfuscated::InitConnection()
{
    Buffer buf(64);
    GenerateTCPO2States(*buf, &m_recvState, &m_sendState);
    m_wrapped->Send(NetworkPacket
    {
        std::move(buf),
        NetworkAddress::Empty(),
        0,
        NetworkProtocol::TCP
    });
}

void NetworkSocketTCPObfuscated::Send(NetworkPacket packet)
{
    BufferOutputStream os(packet.data.Length() + 4);
    std::size_t len = packet.data.Length() / 4;
    if (len < 0x7F)
    {
        os.WriteByte(static_cast<unsigned char>(len));
    }
    else
    {
        os.WriteByte(0x7F);
        os.WriteByte(static_cast<unsigned char>((len >>  0) & 0xFF));
        os.WriteByte(static_cast<unsigned char>((len >>  8) & 0xFF));
        os.WriteByte(static_cast<unsigned char>((len >> 16) & 0xFF));
    }
    os.WriteBytes(packet.data);
    EncryptForTCPO2(os.GetBuffer(), os.GetLength(), &m_sendState);
    m_wrapped->Send(NetworkPacket
    {
        Buffer(std::move(os)),
        NetworkAddress::Empty(),
        0,
        NetworkProtocol::TCP
    });
    //LOGD("Sent %u bytes", os.GetLength());
}

bool NetworkSocketTCPObfuscated::OnReadyToSend()
{
    LOGV("TCPO socket ready to send");
    if (!m_initialized)
    {
        LOGV("Initializing TCPO2 connection");
        m_initialized = true;
        InitConnection();
        m_readyToSend = true;
        return false;
    }
    return m_wrapped->OnReadyToSend();
}

NetworkPacket NetworkSocketTCPObfuscated::Receive(std::size_t maxLen)
{
    unsigned char len1;
    std::size_t packetLen = 0;
    std::size_t offset = 0;
    std::size_t len;
    len = m_wrapped->Receive(&len1, 1);
    if (len <= 0)
    {
        return NetworkPacket::Empty();
    }
    EncryptForTCPO2(&len1, 1, &m_recvState);

    if (len1 < 0x7F)
    {
        packetLen = static_cast<std::size_t>(len1) * 4;
    }
    else
    {
        unsigned char len2[3];
        len = m_wrapped->Receive(len2, 3);
        if (len <= 0)
        {
            return NetworkPacket::Empty();
        }
        EncryptForTCPO2(len2, 3, &m_recvState);
        packetLen = ((static_cast<std::size_t>(len2[0]) <<  0) |
                     (static_cast<std::size_t>(len2[1]) <<  8) |
                     (static_cast<std::size_t>(len2[2]) << 16)) * 4;
    }

    if (packetLen > 1500)
    {
        LOGW("packet too big to fit into buffer (%u vs %u)", static_cast<unsigned>(packetLen), 1500u);
        return NetworkPacket::Empty();
    }
    Buffer buf(packetLen);

    while (offset < packetLen)
    {
        len = m_wrapped->Receive(*buf, packetLen - offset);
        if (len <= 0)
        {
            return NetworkPacket::Empty();
        }
        offset += len;
    }
    EncryptForTCPO2(*buf, packetLen, &m_recvState);
    return NetworkPacket
    {
        std::move(buf),
        m_wrapped->GetConnectedAddress(),
        m_wrapped->GetConnectedPort(),
        NetworkProtocol::TCP
    };
}

void NetworkSocketTCPObfuscated::Open()
{
}

void NetworkSocketTCPObfuscated::Close()
{
    m_wrapped->Close();
}

void NetworkSocketTCPObfuscated::Connect(const NetworkAddress address, std::uint16_t port)
{
    m_wrapped->Connect(address, port);
}

bool NetworkSocketTCPObfuscated::IsFailed() const
{
    return m_wrapped->IsFailed();
}

bool NetworkSocketTCPObfuscated::IsReadyToSend() const
{
    return m_readyToSend && m_wrapped->IsReadyToSend();
}

NetworkSocketSOCKS5Proxy::NetworkSocketSOCKS5Proxy(NetworkSocket* tcp, NetworkSocket* udp, std::string username, std::string password)
    : NetworkSocketWrapper(udp ? NetworkProtocol::UDP : NetworkProtocol::TCP)
    , m_tcp(tcp)
    , m_udp(udp)
    , m_username(std::move(username))
    , m_password(std::move(password))
{
}

NetworkSocketSOCKS5Proxy::~NetworkSocketSOCKS5Proxy()
{
    delete m_tcp;
}

void NetworkSocketSOCKS5Proxy::Send(NetworkPacket packet)
{
    if (m_protocol == NetworkProtocol::TCP)
    {
        m_tcp->Send(std::move(packet));
    }
    else if (m_protocol == NetworkProtocol::UDP)
    {
        BufferOutputStream out(1500);
        out.WriteInt16(0); // RSV
        out.WriteByte(0); // FRAG
        if (!packet.address.isIPv6)
        {
            out.WriteByte(1); // ATYP (IPv4)
            out.WriteInt32(static_cast<std::int32_t>(packet.address.addr.ipv4));
        }
        else
        {
            out.WriteByte(4); // ATYP (IPv6)
            out.WriteBytes(packet.address.addr.ipv6, 16);
        }
        out.WriteInt16(static_cast<std::int16_t>(htons(packet.port)));
        out.WriteBytes(packet.data);
        m_udp->Send(NetworkPacket
        {
            Buffer(std::move(out)),
            m_connectedAddress,
            m_connectedPort,
            NetworkProtocol::UDP
        });
    }
}

NetworkPacket NetworkSocketSOCKS5Proxy::Receive(std::size_t maxLen)
{
    if (m_protocol == NetworkProtocol::TCP)
    {
        NetworkPacket packet = m_tcp->Receive();
        packet.address = m_connectedAddress;
        packet.port = m_connectedPort;
        return packet;
    }
    else
    {
        NetworkPacket p = m_udp->Receive();
        if (!p.IsEmpty() && p.address == m_connectedAddress && p.port == m_connectedPort)
        {
            BufferInputStream in(p.data);
            in.ReadInt16(); // RSV
            in.ReadByte(); // FRAG
            unsigned char atyp = in.ReadByte();
            NetworkAddress address = NetworkAddress::Empty();
            if (atyp == 1)
            { // IPv4
                address = NetworkAddress::IPv4(static_cast<std::uint32_t>(in.ReadInt32()));
            }
            else if (atyp == 4)
            { // IPv6
                unsigned char addr[16];
                in.ReadBytes(addr, 16);
                address = NetworkAddress::IPv6(addr);
            }
            return NetworkPacket
            {
                Buffer::CopyOf(p.data, in.GetOffset(), in.Remaining()),
                address,
                htons(static_cast<std::uint16_t>(in.ReadInt16())),
                m_protocol
            };
        }
    }
    return NetworkPacket::Empty();
}

void NetworkSocketSOCKS5Proxy::Open()
{
}

void NetworkSocketSOCKS5Proxy::Close()
{
    m_tcp->Close();
}

void NetworkSocketSOCKS5Proxy::Connect(const NetworkAddress address, std::uint16_t port)
{
    m_connectedAddress = address;
    m_connectedPort = port;
}

NetworkSocket* NetworkSocketSOCKS5Proxy::GetWrapped()
{
    return m_protocol == NetworkProtocol::TCP ? m_tcp : m_udp;
}

void NetworkSocketSOCKS5Proxy::InitConnection()
{
}

bool NetworkSocketSOCKS5Proxy::IsFailed() const
{
    return NetworkSocket::IsFailed() || m_tcp->IsFailed();
}

NetworkAddress NetworkSocketSOCKS5Proxy::GetConnectedAddress()
{
    return m_connectedAddress;
}

std::uint16_t NetworkSocketSOCKS5Proxy::GetConnectedPort()
{
    return m_connectedPort;
}

bool NetworkSocketSOCKS5Proxy::OnReadyToSend()
{
    //LOGV("on ready to send, state=%d", state);
    if (m_state == ConnectionState::Initial)
    {
        BufferOutputStream p(16);
        p.WriteByte(5); // VER
        if (!m_username.empty())
        {
            p.WriteByte(2); // NMETHODS
            p.WriteByte(0); // no auth
            p.WriteByte(2); // user/pass
        }
        else
        {
            p.WriteByte(1); // NMETHODS
            p.WriteByte(0); // no auth
        }
        m_tcp->Send(NetworkPacket {
            Buffer(std::move(p)),
            NetworkAddress::Empty(),
            0,
            NetworkProtocol::TCP});
        m_state = ConnectionState::WaitingForAuthMethod;
        return false;
    }
    return m_udp ? m_udp->OnReadyToSend() : m_tcp->OnReadyToSend();
}

bool NetworkSocketSOCKS5Proxy::OnReadyToReceive()
{
    //LOGV("on ready to receive state=%d", state);
    unsigned char buf[1024];
    if (m_state == ConnectionState::WaitingForAuthMethod)
    {
        std::size_t l = m_tcp->Receive(buf, sizeof(buf));
        if (l < 2 || m_tcp->IsFailed())
        {
            m_failed = true;
            return false;
        }
        BufferInputStream in(buf, l);
        unsigned char ver = in.ReadByte();
        unsigned char chosenMethod = in.ReadByte();
        LOGV("socks5: VER=%02X, METHOD=%02X", ver, chosenMethod);
        if (ver != 5)
        {
            LOGW("socks5: incorrect VER in response");
            m_failed = true;
            return false;
        }
        if (chosenMethod == 0)
        {
            // connected, no further auth needed
            SendConnectionCommand();
        }
        else if (chosenMethod == 2 && !m_username.empty())
        {
            BufferOutputStream p(512);
            p.WriteByte(1); // VER
            p.WriteByte(static_cast<unsigned char>(m_username.length() > 255 ? 255 : m_username.length())); // ULEN
            p.WriteBytes(reinterpret_cast<const unsigned char*>(m_username.c_str()), m_username.length() > 255 ? 255 : m_username.length()); // UNAME
            p.WriteByte(static_cast<unsigned char>(m_password.length() > 255 ? 255 : m_password.length())); // PLEN
            p.WriteBytes(reinterpret_cast<const unsigned char*>(m_password.c_str()), m_password.length() > 255 ? 255 : m_password.length()); // PASSWD
            m_tcp->Send(NetworkPacket
            {
                Buffer(std::move(p)),
                NetworkAddress::Empty(),
                0,
                NetworkProtocol::TCP
            });
            m_state = ConnectionState::WaitingForAuthResult;
        }
        else
        {
            LOGW("socks5: unsupported auth method");
            m_failed = true;
            return false;
        }
        return false;
    }
    else if (m_state == ConnectionState::WaitingForAuthResult)
    {
        std::size_t l = m_tcp->Receive(buf, sizeof(buf));
        if (l < 2 || m_tcp->IsFailed())
        {
            m_failed = true;
            return false;
        }
        BufferInputStream in(buf, l);
        std::uint8_t ver = in.ReadByte();
        unsigned char status = in.ReadByte();
        LOGV("socks5: auth response VER=%02X, STATUS=%02X", ver, status);
        if (ver != 1)
        {
            LOGW("socks5: auth response VER is incorrect");
            m_failed = true;
            return false;
        }
        if (status != 0)
        {
            LOGW("socks5: username/password auth failed");
            m_failed = true;
            return false;
        }
        LOGV("socks5: authentication succeeded");
        SendConnectionCommand();
        return false;
    }
    else if (m_state == ConnectionState::WaitingForCommandResult)
    {
        std::size_t l = m_tcp->Receive(buf, sizeof(buf));
        if (m_protocol == NetworkProtocol::TCP)
        {
            if (l < 2 || m_tcp->IsFailed())
            {
                LOGW("socks5: connect failed")
                m_failed = true;
                return false;
            }
            BufferInputStream in(buf, l);
            unsigned char ver = in.ReadByte();
            if (ver != 5)
            {
                LOGW("socks5: connect: wrong ver in response");
                m_failed = true;
                return false;
            }
            unsigned char rep = in.ReadByte();
            if (rep != 0)
            {
                LOGW("socks5: connect: failed with error %02X", rep);
                m_failed = true;
                return false;
            }
            LOGV("socks5: connect succeeded");
            m_state = ConnectionState::Connected;
            m_tcp = new NetworkSocketTCPObfuscated(m_tcp);
            m_readyToSend = true;
            return m_tcp->OnReadyToSend();
        }
        else if (m_protocol == NetworkProtocol::UDP)
        {
            if (l < 2 || m_tcp->IsFailed())
            {
                LOGW("socks5: udp associate failed");
                m_failed = true;
                return false;
            }
            try
            {
                BufferInputStream in(buf, l);
                unsigned char ver = in.ReadByte();
                unsigned char rep = in.ReadByte();
                if (ver != 5)
                {
                    LOGW("socks5: udp associate: wrong ver in response");
                    m_failed = true;
                    return false;
                }
                if (rep != 0)
                {
                    LOGW("socks5: udp associate failed with error %02X", rep);
                    m_failed = true;
                    return false;
                }
                in.ReadByte(); // RSV
                unsigned char atyp = in.ReadByte();
                if (atyp == 1)
                {
                    std::uint32_t addr = static_cast<std::uint32_t>(in.ReadInt32());
                    m_connectedAddress = NetworkAddress::IPv4(addr);
                }
                else if (atyp == 3)
                {
                    unsigned char len = in.ReadByte();
                    char domain[256];
                    std::memset(domain, 0, sizeof(domain));
                    in.ReadBytes(reinterpret_cast<unsigned char*>(domain), len);
                    LOGD("address type is domain, address=%s", domain);
                    m_connectedAddress = ResolveDomainName(std::string(domain));
                    if (m_connectedAddress.IsEmpty())
                    {
                        LOGW("socks5: failed to resolve domain name '%s'", domain);
                        m_failed = true;
                        return false;
                    }
                }
                else if (atyp == 4)
                {
                    unsigned char addr[16];
                    in.ReadBytes(addr, 16);
                    m_connectedAddress = NetworkAddress::IPv6(addr);
                }
                else
                {
                    LOGW("socks5: unknown address type %d", atyp);
                    m_failed = true;
                    return false;
                }
                m_connectedPort = ntohs(static_cast<std::uint16_t>(in.ReadInt16()));
                m_state = ConnectionState::Connected;
                m_readyToSend = true;
                LOGV("socks5: udp associate successful, given endpoint %s:%d", m_connectedAddress.ToString().c_str(), m_connectedPort);
            }
            catch (const std::out_of_range&)
            {
                LOGW("socks5: udp associate response parse failed");
                m_failed = true;
            }
        }
    }
    return m_udp ? m_udp->OnReadyToReceive() : m_tcp->OnReadyToReceive();
}

void NetworkSocketSOCKS5Proxy::SendConnectionCommand()
{
    BufferOutputStream out(1024);
    if (m_protocol == NetworkProtocol::TCP)
    {
        out.WriteByte(5); // VER
        out.WriteByte(1); // CMD (CONNECT)
        out.WriteByte(0); // RSV
        if (!m_connectedAddress.isIPv6)
        {
            out.WriteByte(1); // ATYP (IPv4)
            out.WriteInt32(static_cast<std::int32_t>(m_connectedAddress.addr.ipv4));
        }
        else
        {
            out.WriteByte(4); // ATYP (IPv6)
            out.WriteBytes(reinterpret_cast<unsigned char*>(m_connectedAddress.addr.ipv6), 16);
        }
        out.WriteInt16(static_cast<std::int16_t>(htons(m_connectedPort))); // DST.PORT
    }
    else if (m_protocol == NetworkProtocol::UDP)
    {
        LOGV("Sending udp associate");
        out.WriteByte(5); // VER
        out.WriteByte(3); // CMD (UDP ASSOCIATE)
        out.WriteByte(0); // RSV
        out.WriteByte(1); // ATYP (IPv4)
        out.WriteInt32(0); // DST.ADDR
        out.WriteInt16(0); // DST.PORT
    }
    m_tcp->Send(NetworkPacket {
        Buffer(std::move(out)),
        NetworkAddress::Empty(),
        0,
        NetworkProtocol::TCP});
    m_state = ConnectionState::WaitingForCommandResult;
}

bool NetworkSocketSOCKS5Proxy::NeedSelectForSending()
{
    return m_state == ConnectionState::Initial || m_state == ConnectionState::Connected;
}
