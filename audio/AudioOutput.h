//
// libtgvoip is free and unencumbered public domain software.
// For more information, see http://unlicense.org or the UNLICENSE file
// you should have received with this source code distribution.
//

#ifndef LIBTGVOIP_AUDIOOUTPUT_H
#define LIBTGVOIP_AUDIOOUTPUT_H

#include "../MediaStreamItf.h"
#include <memory>
#include <cstdint>
#include <string>
#include <vector>

namespace tgvoip
{

class AudioInputDevice;
class AudioOutputDevice;

namespace audio
{
    class AudioOutput : public MediaStreamItf
    {
    public:
        AudioOutput();
        AudioOutput(std::string deviceID);
        virtual ~AudioOutput();
        virtual bool IsPlaying() = 0;
        static std::int32_t GetEstimatedDelay();
        virtual std::string GetCurrentDevice();
        virtual void SetCurrentDevice(std::string deviceID);
        //static std::unique_ptr<AudioOutput> Create(std::string deviceID, void* platformSpecific);
        static void EnumerateDevices(std::vector<AudioOutputDevice>& devs);
        bool IsInitialized();

    protected:
        std::string currentDevice;
        bool failed;
        static std::int32_t estimatedDelay;
    };
}
}

#endif //LIBTGVOIP_AUDIOOUTPUT_H
