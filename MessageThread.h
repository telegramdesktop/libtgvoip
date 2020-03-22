//
// Created by Grishka on 17.06.2018.
//

#ifndef LIBTGVOIP_MESSAGETHREAD_H
#define LIBTGVOIP_MESSAGETHREAD_H

#include "threading.h"
#include "utils.h"
#include <atomic>
#include <functional>
#include <vector>
#include <mutex>

namespace tgvoip
{

class MessageThread : public Thread
{
public:
    TGVOIP_DISALLOW_COPY_AND_ASSIGN(MessageThread);
    MessageThread();
    ~MessageThread() override;
    std::uint32_t Post(std::function<void()> func, double delay = 0, double interval = 0);
    void Cancel(std::uint32_t id);
    void CancelSelf();
    void Stop();

    enum
    {
        INVALID_ID = 0
    };

private:
    struct Message
    {
        std::uint32_t id;
        double deliverAt;
        double interval;
        std::function<void()> func;
    };

    std::atomic<bool> m_running;
    std::vector<Message> m_queue;
    mutable Mutex m_queueMutex;
    mutable Mutex m_queueAccessMutex;

    std::uint32_t m_lastMessageID = 1;
    mutable std::mutex m_mutexLastMessageID;
    bool m_cancelCurrent = false;

#ifdef _WIN32
    HANDLE event;
#else
    pthread_cond_t cond;
#endif

    void Run();
    void InsertMessageInternal(Message& m);
};

} // namespace tgvoip

#endif // LIBTGVOIP_MESSAGETHREAD_H
