//
// libtgvoip is free and unencumbered public domain software.
// For more information, see http://unlicense.org or the UNLICENSE file
// you should have received with this source code distribution.
//
#ifndef TGVOIP_MOCK_REFLECTOR
#define TGVOIP_MOCK_REFLECTOR

#include <array>
#include <pthread.h>
#include <cstdint>
#include <string>
#include <unordered_map>

#include <cassert>
#include <cerrno>
#include <net/if.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

namespace tgvoip
{
namespace test
{
    class MockReflector
    {
    public:
        MockReflector(std::string bindAddress, std::uint16_t bindPort);
        ~MockReflector();
        void Start();
        void Stop();
        void SetDropAllPackets(bool drop);
        static std::array<std::array<std::uint8_t, 16>, 2> GeneratePeerTags();

    private:
        void RunThread();
        struct ClientPair
        {
            sockaddr_in addr0 = {0};
            sockaddr_in addr1 = {0};
        };
        std::unordered_map<std::uint64_t, ClientPair> clients; // clients are identified by the first half of their peer_tag
        int sfd;
        pthread_t thread;
        bool running = false;
        bool dropAllPackets = false;
    };
}
}

#endif //TGVOIP_MOCK_REFLECTOR
