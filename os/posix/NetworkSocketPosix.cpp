//
// libtgvoip is free and unencumbered public domain software.
// For more information, see http://unlicense.org or the UNLICENSE file
// you should have received with this source code distribution.
//

#include "NetworkSocketPosix.h"
#include "../../Buffers.h"
#include "../../VoIPController.h"
#include "../../logging.h"
#include <cassert>
#include <cerrno>
#include <fcntl.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#ifdef __ANDROID__
#include <NetworkSocket.h>
#include <jni.h>
#include <sys/system_properties.h>

extern JavaVM* sharedJVM;
extern jclass jniUtilitiesClass;
#else
#include <ifaddrs.h>
#endif

using namespace tgvoip;

NetworkSocketPosix::NetworkSocketPosix(NetworkProtocol protocol)
    : NetworkSocket(protocol)
    , m_fd(-1)
    , m_needUpdateNat64Prefix(true)
    , m_nat64Present(false)
    , m_switchToV6at(0)
    , m_isV4Available(false)
    , m_closing(false)
    , m_tcpConnectedPort(0)
{
    if (protocol == NetworkProtocol::TCP)
        m_timeout = 10.0;
    m_lastSuccessfulOperationTime = VoIPController::GetCurrentTime();
}

NetworkSocketPosix::~NetworkSocketPosix()
{
    if (m_fd >= 0)
    {
        Close();
    }
}

void NetworkSocketPosix::SetMaxPriority()
{
#ifdef __APPLE__
    int prio = NET_SERVICE_TYPE_VO;
    int res = setsockopt(fd, SOL_SOCKET, SO_NET_SERVICE_TYPE, &prio, sizeof(prio));
    if (res < 0)
    {
        LOGE("error setting darwin-specific net priority: %d / %s", errno, strerror(errno));
    }
#elif defined(__linux__)
    int prio = 6;
    int res = setsockopt(m_fd, SOL_SOCKET, SO_PRIORITY, &prio, sizeof(prio));
    if (res < 0)
    {
        LOGE("error setting priority: %d / %s", errno, strerror(errno));
    }
    prio = 46 << 2;
    res = setsockopt(m_fd, SOL_IP, IP_TOS, &prio, sizeof(prio));
    if (res < 0)
    {
        LOGE("error setting ip tos: %d / %s", errno, strerror(errno));
    }
#else
    LOGI("cannot set socket priority");
#endif
}

void NetworkSocketPosix::Send(NetworkPacket packet)
{
    if (packet.data.IsEmpty() || (m_protocol == NetworkProtocol::UDP && packet.port == 0))
    {
        LOGW("tried to send null packet");
        return;
    }
    int res;
    if (m_protocol == NetworkProtocol::UDP)
    {
        sockaddr_in6 addr;
        if (!packet.address.isIPv6)
        {
            if (m_needUpdateNat64Prefix && !m_isV4Available && VoIPController::GetCurrentTime() > m_switchToV6at && m_switchToV6at != 0)
            {
                LOGV("Updating NAT64 prefix");
                m_nat64Present = false;
                addrinfo* addr0;
                int res = getaddrinfo("ipv4only.arpa", nullptr, nullptr, &addr0);
                if (res != 0)
                {
                    LOGW("Error updating NAT64 prefix: %d / %s", res, gai_strerror(res));
                }
                else
                {
                    addrinfo* addrPtr;
                    std::uint8_t* addr170 = nullptr;
                    std::uint8_t* addr171 = nullptr;
                    for (addrPtr = addr0; addrPtr; addrPtr = addrPtr->ai_next)
                    {
                        if (addrPtr->ai_family == AF_INET6)
                        {
                            sockaddr_in6* translatedAddr = reinterpret_cast<sockaddr_in6*>(addrPtr->ai_addr);
                            std::uint32_t v4part = *(reinterpret_cast<std::uint32_t*>(&translatedAddr->sin6_addr.s6_addr[12]));
                            if (v4part == 0xAA0000C0 && !addr170)
                            {
                                addr170 = translatedAddr->sin6_addr.s6_addr;
                            }
                            if (v4part == 0xAB0000C0 && !addr171)
                            {
                                addr171 = translatedAddr->sin6_addr.s6_addr;
                            }
                            char buf[INET6_ADDRSTRLEN];
                            LOGV("Got translated address: %s", inet_ntop(AF_INET6, &translatedAddr->sin6_addr, buf, sizeof(buf)));
                        }
                    }
                    if (addr170 && addr171 && memcmp(addr170, addr171, 12) == 0)
                    {
                        m_nat64Present = true;
                        std::memcpy(m_nat64Prefix, addr170, 12);
                        char buf[INET6_ADDRSTRLEN];
                        LOGV("Found nat64 prefix from %s", inet_ntop(AF_INET6, addr170, buf, sizeof(buf)));
                    }
                    else
                    {
                        LOGV("Didn't find nat64");
                    }
                    freeaddrinfo(addr0);
                }
                m_needUpdateNat64Prefix = false;
            }
            std::memset(&addr, 0, sizeof(sockaddr_in6));
            addr.sin6_family = AF_INET6;
            *(reinterpret_cast<std::uint32_t*>(&addr.sin6_addr.s6_addr[12])) = packet.address.addr.ipv4;
            if (m_nat64Present)
                std::memcpy(addr.sin6_addr.s6_addr, m_nat64Prefix, 12);
            else
                addr.sin6_addr.s6_addr[11] = addr.sin6_addr.s6_addr[10] = 0xFF;
        }
        else
        {
            std::memcpy(addr.sin6_addr.s6_addr, packet.address.addr.ipv6, 16);
            addr.sin6_family = AF_INET6;
        }
        addr.sin6_port = htons(packet.port);
        std::lock_guard<std::mutex> lock(m_mutexFd);
        res = static_cast<int>(sendto(m_fd, *packet.data, packet.data.Length(), 0,
                               reinterpret_cast<sockaddr*>(&addr), sizeof(addr)));
    }
    else
    {
        std::lock_guard<std::mutex> lock(m_mutexFd);
        res = static_cast<int>(send(m_fd, *packet.data, packet.data.Length(), 0));
    }
    if (res <= 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            if (!m_pendingOutgoingPacket.IsEmpty())
            {
                LOGE("Got EAGAIN but there's already a pending packet");
                m_failed = true;
            }
            else
            {
                LOGV("Socket %d not ready to send", int(m_fd));
                m_pendingOutgoingPacket = std::move(packet);
                m_readyToSend = false;
            }
        }
        else
        {
            LOGE("error sending: %d / %s", errno, strerror(errno));
            if (errno == ENETUNREACH && !m_isV4Available && VoIPController::GetCurrentTime() < m_switchToV6at)
            {
                m_switchToV6at = VoIPController::GetCurrentTime();
                LOGI("Network unreachable, trying NAT64");
            }
        }
    }
    else if (static_cast<std::size_t>(res) != packet.data.Length() && packet.protocol == NetworkProtocol::TCP)
    {
        if (!m_pendingOutgoingPacket.IsEmpty())
        {
            LOGE("send returned less than packet length but there's already a pending packet");
            m_failed = true;
        }
        else
        {
            LOGV("Socket %d not ready to send", int(m_fd));
            m_pendingOutgoingPacket = std::move(packet);
            m_readyToSend = false;
        }
    }
}

bool NetworkSocketPosix::OnReadyToSend()
{
    if (!m_pendingOutgoingPacket.IsEmpty())
    {
        Send(std::move(m_pendingOutgoingPacket));
        m_pendingOutgoingPacket = NetworkPacket::Empty();
        return false;
    }
    m_readyToSend = true;
    return true;
}

NetworkPacket NetworkSocketPosix::Receive(std::size_t maxLen)
{
    if (maxLen == 0)
        maxLen = std::numeric_limits<std::int32_t>::max();
    if (m_failed)
        return NetworkPacket::Empty();
    switch (m_protocol)
    {
    case NetworkProtocol::UDP:
    {
        int addrLen = sizeof(sockaddr_in6);
        sockaddr_in6 srcAddr;
        ssize_t len;
        len = recvfrom(m_fd, *m_recvBuffer, std::min(m_recvBuffer.Length(), maxLen), 0,
                       reinterpret_cast<sockaddr*>(&srcAddr), reinterpret_cast<socklen_t*>(&addrLen));
        if (len > 0)
        {
            if (!m_isV4Available && IN6_IS_ADDR_V4MAPPED(&srcAddr.sin6_addr))
            {
                m_isV4Available = true;
                LOGI("Detected IPv4 connectivity, will not try IPv6");
            }
            NetworkAddress addr = NetworkAddress::Empty();
            if (IN6_IS_ADDR_V4MAPPED(&srcAddr.sin6_addr) || (m_nat64Present && memcmp(m_nat64Prefix, srcAddr.sin6_addr.s6_addr, 12) == 0))
            {
                in_addr v4addr = *(reinterpret_cast<in_addr*>(&srcAddr.sin6_addr.s6_addr[12]));
                addr = NetworkAddress::IPv4(v4addr.s_addr);
            }
            else
            {
                addr = NetworkAddress::IPv6(srcAddr.sin6_addr.s6_addr);
            }
            return NetworkPacket
            {
                Buffer::CopyOf(m_recvBuffer, 0, static_cast<std::size_t>(len)),
                addr,
                ntohs(srcAddr.sin6_port),
                NetworkProtocol::UDP
            };
        }
        LOGE("error receiving %d / %s", errno, strerror(errno));
        return NetworkPacket::Empty();
        //LOGV("Received %d bytes from %s:%d at %.5lf", len, inet_ntoa(srcAddr.sin_addr), ntohs(srcAddr.sin_port), GetCurrentTime());
    }
    case NetworkProtocol::TCP:
    {
        ssize_t res = recv(m_fd, *m_recvBuffer, std::min(m_recvBuffer.Length(), maxLen), 0);
        if (res <= 0)
        {
            LOGE("Error receiving from TCP socket: %d / %s", errno, strerror(errno));
            m_failed = true;
            return NetworkPacket::Empty();
        }
        return NetworkPacket
        {
            Buffer::CopyOf(m_recvBuffer, 0, static_cast<std::size_t>(res)),
            m_tcpConnectedAddress,
            m_tcpConnectedPort,
            NetworkProtocol::TCP
        };
    }
    }
    return NetworkPacket::Empty();
}

void NetworkSocketPosix::Open()
{
    if (m_protocol != NetworkProtocol::UDP)
        return;
    m_fd = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (m_fd < 0)
    {
        LOGE("error creating socket: %d / %s", errno, strerror(errno));
        m_failed = true;
        return;
    }
    int flag = 0;
    int res = setsockopt(m_fd, IPPROTO_IPV6, IPV6_V6ONLY, &flag, sizeof(flag));
    if (res < 0)
    {
        LOGE("error enabling dual stack socket: %d / %s", errno, strerror(errno));
        m_failed = true;
        return;
    }

    SetMaxPriority();
    if (fcntl(m_fd, F_SETFL, O_NONBLOCK) == -1)
    {
        LOGE("error setting nonblock flag on socket: %d / %s", errno, strerror(errno));
        m_failed = true;
        return;
    }

#ifdef __APPLE__
    flag = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &flag, sizeof(flag));
#endif

    int tries = 0;
    sockaddr_in6 addr;
    //addr.sin6_addr.s_addr=0;
    std::memset(&addr, 0, sizeof(sockaddr_in6));
    //addr.sin6_len=sizeof(sa_family_t);
    addr.sin6_family = AF_INET6;
    for (tries = 0; tries < 10; tries++)
    {
        addr.sin6_port = htons(GenerateLocalPort());
        res = ::bind(m_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(sockaddr_in6));
        LOGV("trying bind to port %u", ntohs(addr.sin6_port));
        if (res < 0)
        {
            LOGE("error binding to port %u: %d / %s", ntohs(addr.sin6_port), errno, strerror(errno));
        }
        else
        {
            break;
        }
    }
    if (tries == 10)
    {
        addr.sin6_port = 0;
        res = ::bind(m_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(sockaddr_in6));
        if (res < 0)
        {
            LOGE("error binding to port %u: %d / %s", ntohs(addr.sin6_port), errno, strerror(errno));
            //SetState(State::FAILED);
            m_failed = true;
            return;
        }
    }
    std::size_t addrLen = sizeof(sockaddr_in6);
    getsockname(m_fd, reinterpret_cast<sockaddr*>(&addr), reinterpret_cast<socklen_t*>(&addrLen));
    LOGD("Bound to local UDP port %u", ntohs(addr.sin6_port));

    m_needUpdateNat64Prefix = true;
    m_isV4Available = false;
    m_switchToV6at = VoIPController::GetCurrentTime() + m_ipv6Timeout;
}

void NetworkSocketPosix::Close()
{
    if (m_closing)
    {
        return;
    }
    m_closing = true;
    m_failed = true;

    std::lock_guard<std::mutex> lock(m_mutexFd);
    if (m_fd >= 0)
    {
        shutdown(m_fd, SHUT_RDWR);
        close(m_fd);
        m_fd = -1;
    }
}

void NetworkSocketPosix::Connect(const NetworkAddress& address, std::uint16_t port)
{
    struct sockaddr_in v4;
    std::memset(&v4, 0, sizeof(v4));
    struct sockaddr_in6 v6;
    std::memset(&v6, 0, sizeof(v6));
    struct sockaddr* addr = nullptr;
    std::size_t addrLen = 0;
    if (!address.isIPv6)
    {
        v4.sin_family = AF_INET;
        v4.sin_addr.s_addr = address.addr.ipv4;
        v4.sin_port = htons(port);
        addr = reinterpret_cast<sockaddr*>(&v4);
        addrLen = sizeof(v4);
    }
    else
    {
        v6.sin6_family = AF_INET6;
        std::memcpy(v6.sin6_addr.s6_addr, address.addr.ipv6, 16);
        v6.sin6_flowinfo = 0;
        v6.sin6_scope_id = 0;
        v6.sin6_port = htons(port);
        addr = reinterpret_cast<sockaddr*>(&v6);
        addrLen = sizeof(v6);
    }
    m_fd = socket(addr->sa_family, SOCK_STREAM, IPPROTO_TCP);
    if (m_fd < 0)
    {
        LOGE("Error creating TCP socket: %d / %s", errno, strerror(errno));
        m_failed = true;
        return;
    }
    int opt = 1;
    setsockopt(m_fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
    timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    setsockopt(m_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    timeout.tv_sec = 60;
    setsockopt(m_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    fcntl(m_fd, F_SETFL, O_NONBLOCK);
    int res = connect(m_fd, reinterpret_cast<const sockaddr*>(addr), static_cast<socklen_t>(addrLen));
    if (res != 0 && errno != EINVAL && errno != EINPROGRESS)
    {
        LOGW("error connecting TCP socket to %s:%u: %d / %s; %d / %s", address.ToString().c_str(), port, res, strerror(res), errno, strerror(errno));
        close(m_fd);
        m_failed = true;
        return;
    }
    m_tcpConnectedAddress = address;
    m_tcpConnectedPort = port;
    LOGI("successfully connected to %s:%d", m_tcpConnectedAddress.ToString().c_str(), m_tcpConnectedPort);
}

void NetworkSocketPosix::OnActiveInterfaceChanged()
{
    m_needUpdateNat64Prefix = true;
    m_isV4Available = false;
    m_switchToV6at = VoIPController::GetCurrentTime() + m_ipv6Timeout;
}

std::string NetworkSocketPosix::GetLocalInterfaceInfo(NetworkAddress* v4addr, NetworkAddress* v6addr)
{
    std::string name = "";
    // Android doesn't support ifaddrs
#ifdef __ANDROID__
    JNIEnv* env = nullptr;
    bool didAttach = false;
    sharedJVM->GetEnv((void**)&env, JNI_VERSION_1_6);
    if (!env)
    {
        sharedJVM->AttachCurrentThread(&env, nullptr);
        didAttach = true;
    }

    jmethodID getLocalNetworkAddressesAndInterfaceNameMethod = env->GetStaticMethodID(jniUtilitiesClass, "getLocalNetworkAddressesAndInterfaceName", "()[Ljava/lang/String;");
    jobjectArray jinfo = (jobjectArray)env->CallStaticObjectMethod(jniUtilitiesClass, getLocalNetworkAddressesAndInterfaceNameMethod);
    if (jinfo)
    {
        jstring jitfName = static_cast<jstring>(env->GetObjectArrayElement(jinfo, 0));
        jstring jipv4 = static_cast<jstring>(env->GetObjectArrayElement(jinfo, 1));
        jstring jipv6 = static_cast<jstring>(env->GetObjectArrayElement(jinfo, 2));
        if (jitfName)
        {
            const char* itfchars = env->GetStringUTFChars(jitfName, nullptr);
            name = std::string(itfchars);
            env->ReleaseStringUTFChars(jitfName, itfchars);
        }

        if (v4addr && jipv4)
        {
            const char* ipchars = env->GetStringUTFChars(jipv4, nullptr);
            *v4addr = NetworkAddress::IPv4(ipchars);
            env->ReleaseStringUTFChars(jipv4, ipchars);
        }
        if (v6addr && jipv6)
        {
            const char* ipchars = env->GetStringUTFChars(jipv6, nullptr);
            *v6addr = NetworkAddress::IPv6(ipchars);
            env->ReleaseStringUTFChars(jipv6, ipchars);
        }
    }
    else
    {
        LOGW("Failed to get android network interface info");
    }

    if (didAttach)
    {
        sharedJVM->DetachCurrentThread();
    }
#else
    struct ifaddrs* interfaces;
    if (getifaddrs(&interfaces) == 0)
    {
        struct ifaddrs* interface;
        for (interface = interfaces; interface; interface = interface->ifa_next)
        {
            if (!(interface->ifa_flags & IFF_UP) || !(interface->ifa_flags & IFF_RUNNING) || (interface->ifa_flags & IFF_LOOPBACK))
                continue;
            const struct sockaddr_in* addr = reinterpret_cast<const struct sockaddr_in*>(interface->ifa_addr);
            if (addr != nullptr)
            {
                if (addr->sin_family == AF_INET)
                {
                    if ((ntohl(addr->sin_addr.s_addr) & 0xFFFF0000) == 0xA9FE0000)
                        continue;
                    if (v4addr != nullptr)
                        *v4addr = NetworkAddress::IPv4(addr->sin_addr.s_addr);
                    name = interface->ifa_name;
                }
                else if (addr->sin_family == AF_INET6)
                {
                    const struct sockaddr_in6* addr6 = reinterpret_cast<const struct sockaddr_in6*>(addr);
                    if ((addr6->sin6_addr.s6_addr[0] & 0xF0) == 0xF0)
                        continue;
                    if (v6addr != nullptr)
                        *v6addr = NetworkAddress::IPv6(addr6->sin6_addr.s6_addr);
                    name = interface->ifa_name;
                }
            }
        }
        freeifaddrs(interfaces);
    }
#endif
    return name;
}

std::uint16_t NetworkSocketPosix::GetLocalPort()
{
    sockaddr_in6 addr;
    std::size_t addrLen = sizeof(sockaddr_in6);
    getsockname(m_fd, reinterpret_cast<sockaddr*>(&addr), reinterpret_cast<socklen_t*>(&addrLen));
    return ntohs(addr.sin6_port);
}

std::string NetworkSocketPosix::V4AddressToString(std::uint32_t address)
{
    char buf[INET_ADDRSTRLEN];
    in_addr addr;
    addr.s_addr = address;
    inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    return std::string(buf);
}

std::string NetworkSocketPosix::V6AddressToString(const std::uint8_t* address)
{
    char buf[INET6_ADDRSTRLEN];
    in6_addr addr;
    std::memcpy(addr.s6_addr, address, 16);
    inet_ntop(AF_INET6, &addr, buf, sizeof(buf));
    return std::string(buf);
}

std::uint32_t NetworkSocketPosix::StringToV4Address(const std::string& address)
{
    in_addr addr;
    inet_pton(AF_INET, address.c_str(), &addr);
    return addr.s_addr;
}

void NetworkSocketPosix::StringToV6Address(const std::string& address, std::uint8_t* out)
{
    in6_addr addr;
    inet_pton(AF_INET6, address.c_str(), &addr);
    std::memcpy(out, addr.s6_addr, 16);
}

NetworkAddress NetworkSocketPosix::ResolveDomainName(const std::string& name)
{
    addrinfo* addr0;
    NetworkAddress ret = NetworkAddress::Empty();
    int res = getaddrinfo(name.c_str(), nullptr, nullptr, &addr0);
    if (res != 0)
    {
        LOGW("Error updating NAT64 prefix: %d / %s", res, gai_strerror(res));
    }
    else
    {
        addrinfo* addrPtr;
        for (addrPtr = addr0; addrPtr; addrPtr = addrPtr->ai_next)
        {
            if (addrPtr->ai_family == AF_INET)
            {
                sockaddr_in* addr = reinterpret_cast<sockaddr_in*>(addrPtr->ai_addr);
                ret = NetworkAddress::IPv4(addr->sin_addr.s_addr);
                break;
            }
        }
        freeaddrinfo(addr0);
    }
    return ret;
}

NetworkAddress NetworkSocketPosix::GetConnectedAddress()
{
    return m_tcpConnectedAddress;
}

std::uint16_t NetworkSocketPosix::GetConnectedPort()
{
    return m_tcpConnectedPort;
}

void NetworkSocketPosix::SetTimeouts(int sendTimeout, int recvTimeout)
{
    timeval timeout;
    timeout.tv_sec = sendTimeout;
    timeout.tv_usec = 0;
    setsockopt(m_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    timeout.tv_sec = recvTimeout;
    setsockopt(m_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
}

bool NetworkSocketPosix::Select(std::vector<NetworkSocket*>& readFds, std::vector<NetworkSocket*>& writeFds, std::vector<NetworkSocket*>& errorFds, SocketSelectCanceller* _canceller)
{
    fd_set readSet;
    fd_set writeSet;
    fd_set errorSet;
    FD_ZERO(&readSet);
    FD_ZERO(&writeSet);
    FD_ZERO(&errorSet);
    SocketSelectCancellerPosix* canceller = dynamic_cast<SocketSelectCancellerPosix*>(_canceller);
    if (canceller)
        FD_SET(canceller->pipeRead, &readSet);

    int maxfd = canceller ? canceller->pipeRead : 0;

    for (NetworkSocket*& s : readFds)
    {
        int sfd = GetDescriptorFromSocket(s);
        if (sfd <= 0)
        {
            LOGW("can't select on one of sockets because it's not a NetworkSocketPosix instance");
            continue;
        }
        FD_SET(sfd, &readSet);
        if (maxfd < sfd)
            maxfd = sfd;
    }

    for (NetworkSocket*& s : writeFds)
    {
        int sfd = GetDescriptorFromSocket(s);
        if (sfd <= 0)
        {
            LOGW("can't select on one of sockets because it's not a NetworkSocketPosix instance");
            continue;
        }
        FD_SET(sfd, &writeSet);
        if (maxfd < sfd)
            maxfd = sfd;
    }

    bool anyFailed = false;

    for (NetworkSocket*& s : errorFds)
    {
        int sfd = GetDescriptorFromSocket(s);
        if (sfd <= 0)
        {
            LOGW("can't select on one of sockets because it's not a NetworkSocketPosix instance");
            continue;
        }
        if (s->m_timeout > 0 && VoIPController::GetCurrentTime() - s->m_lastSuccessfulOperationTime > s->m_timeout)
        {
            LOGW("Socket %d timed out", sfd);
            s->m_failed = true;
        }
        anyFailed |= s->IsFailed();
        FD_SET(sfd, &errorSet);
        if (maxfd < sfd)
            maxfd = sfd;
    }

    select(maxfd + 1, &readSet, &writeSet, &errorSet, nullptr);

    if (canceller && FD_ISSET(canceller->pipeRead, &readSet) && !anyFailed)
    {
        char c;
        (void)read(canceller->pipeRead, &c, 1);
        return false;
    }
    else if (anyFailed)
    {
        FD_ZERO(&readSet);
        FD_ZERO(&writeSet);
    }

    std::vector<NetworkSocket*>::iterator itr = readFds.begin();
    while (itr != readFds.end())
    {
        int sfd = GetDescriptorFromSocket(*itr);
        if (FD_ISSET(sfd, &readSet))
            (*itr)->m_lastSuccessfulOperationTime = VoIPController::GetCurrentTime();
        if (sfd == 0 || !FD_ISSET(sfd, &readSet) || !(*itr)->OnReadyToReceive())
        {
            itr = readFds.erase(itr);
        }
        else
        {
            ++itr;
        }
    }

    itr = writeFds.begin();
    while (itr != writeFds.end())
    {
        int sfd = GetDescriptorFromSocket(*itr);
        if (sfd == 0 || !FD_ISSET(sfd, &writeSet))
        {
            itr = writeFds.erase(itr);
        }
        else
        {
            LOGV("Socket %d is ready to send", sfd);
            (*itr)->m_lastSuccessfulOperationTime = VoIPController::GetCurrentTime();
            if ((*itr)->OnReadyToSend())
                ++itr;
            else
                itr = writeFds.erase(itr);
        }
    }

    itr = errorFds.begin();
    while (itr != errorFds.end())
    {
        int sfd = GetDescriptorFromSocket(*itr);
        if ((sfd == 0 || !FD_ISSET(sfd, &errorSet)) && !(*itr)->IsFailed())
        {
            itr = errorFds.erase(itr);
        }
        else
        {
            ++itr;
        }
    }
    //LOGV("select fds left: read=%d, write=%d, error=%d", (int)readFds.size(), (int)writeFds.size(), (int)errorFds.size());

    return readFds.size() > 0 || errorFds.size() > 0 || writeFds.size() > 0;
}

SocketSelectCancellerPosix::SocketSelectCancellerPosix()
{
    int p[2];
    int pipeRes = pipe(p);
    if (pipeRes != 0)
    {
        LOGE("pipe() failed");
        std::abort();
    }
    pipeRead = p[0];
    pipeWrite = p[1];
}

SocketSelectCancellerPosix::~SocketSelectCancellerPosix()
{
    close(pipeRead);
    close(pipeWrite);
}

void SocketSelectCancellerPosix::CancelSelect()
{
    char c = 1;
    (void)write(pipeWrite, &c, 1);
}

int NetworkSocketPosix::GetDescriptorFromSocket(NetworkSocket* socket)
{
    NetworkSocketPosix* sp = dynamic_cast<NetworkSocketPosix*>(socket);
    if (sp)
        return sp->m_fd;
    NetworkSocketWrapper* sw = dynamic_cast<NetworkSocketWrapper*>(socket);
    if (sw)
        return GetDescriptorFromSocket(sw->GetWrapped());
    return 0;
}
