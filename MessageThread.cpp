//
// Created by Grishka on 17.06.2018.
//

#include <cassert>
#include <cfloat>
#include <cmath>
#include <cstdint>
#include <ctime>

#ifndef _WIN32
#include <sys/time.h>
#endif

#include "MessageThread.h"
#include "VoIPController.h"
#include "logging.h"

using namespace tgvoip;

MessageThread::MessageThread()
    : Thread(std::bind(&MessageThread::Run, this))
    , m_running(true)
{
    SetName("MessageThread");

#ifdef _WIN32
#if !defined(WINAPI_FAMILY) || WINAPI_FAMILY != WINAPI_FAMILY_PHONE_APP
    event = CreateEvent(NULL, false, false, NULL);
#else
    event = CreateEventEx(NULL, NULL, 0, EVENT_ALL_ACCESS);
#endif
#else
    pthread_cond_init(&cond, nullptr);
#endif
}

MessageThread::~MessageThread()
{
    Stop();
#ifdef _WIN32
    CloseHandle(event);
#else
    pthread_cond_destroy(&cond);
#endif
}

void MessageThread::Stop()
{
    if (m_running)
    {
        m_running = false;
#ifdef _WIN32
        SetEvent(event);
#else
        pthread_cond_signal(&cond);
#endif
        Join();
    }
}

void MessageThread::Run()
{
    m_queueMutex.Lock();
    while (m_running)
    {
        double currentTime = VoIPController::GetCurrentTime();
        double waitTimeout;
        {
            MutexGuard _m(m_queueAccessMutex);
            waitTimeout = m_queue.empty() ? DBL_MAX : (m_queue[0].deliverAt - currentTime);
        }
        //LOGW("MessageThread wait timeout %f", waitTimeout);
        if (waitTimeout > 0.0)
        {
#ifdef _WIN32
            queueMutex.Unlock();
            DWORD actualWaitTimeout = waitTimeout == DBL_MAX ? INFINITE : ((DWORD)round(waitTimeout * 1000.0));
#if !defined(WINAPI_FAMILY) || WINAPI_FAMILY != WINAPI_FAMILY_PHONE_APP
            WaitForSingleObject(event, actualWaitTimeout);
#else
            WaitForSingleObjectEx(event, actualWaitTimeout, false);
#endif
            // we don't really care if a context switch happens here and anything gets added to the queue by another thread
            // since any new no-delay messages will get delivered on this iteration anyway
            queueMutex.Lock();
#else
            if (waitTimeout != std::numeric_limits<double>::max())
            {
                struct timeval now;
                struct timespec timeout;
                gettimeofday(&now, nullptr);
                waitTimeout += now.tv_sec;
                waitTimeout += (now.tv_usec / 1000000.0);
                timeout.tv_sec = static_cast<std::time_t>(std::floor(waitTimeout));
                timeout.tv_nsec = static_cast<long>((waitTimeout - std::floor(waitTimeout)) * 1000 * 1000 * 1000.0);
                pthread_cond_timedwait(&cond, m_queueMutex.NativeHandle(), &timeout);
            }
            else
            {
                pthread_cond_wait(&cond, m_queueMutex.NativeHandle());
            }
#endif
        }
        if (!m_running)
        {
            m_queueMutex.Unlock();
            return;
        }
        currentTime = VoIPController::GetCurrentTime();
        std::vector<Message> msgsToDeliverNow;
        {
            MutexGuard _m(m_queueAccessMutex);
            for (std::vector<Message>::iterator m = m_queue.begin(); m != m_queue.end();)
            {
                if (m->deliverAt == 0.0 || currentTime >= m->deliverAt)
                {
                    msgsToDeliverNow.push_back(*m);
                    m = m_queue.erase(m);
                    continue;
                }
                ++m;
            }
        }

        for (Message& m : msgsToDeliverNow)
        {
            //LOGI("MessageThread delivering %u", m.msg);
            m_cancelCurrent = false;
            if (m.deliverAt == 0.0)
                m.deliverAt = VoIPController::GetCurrentTime();
            if (m.func != nullptr)
            {
                m.func();
            }
            if (!m_cancelCurrent && m.interval > 0.0)
            {
                m.deliverAt += m.interval;
                InsertMessageInternal(m);
            }
        }
    }
    m_queueMutex.Unlock();
}

std::uint32_t MessageThread::Post(std::function<void()> func, double delay, double interval)
{
    assert(delay >= 0);
    //LOGI("MessageThread post [function] delay %f", delay);
    double currentTime = VoIPController::GetCurrentTime();
    Message m {m_lastMessageID++, delay == 0.0 ? 0.0 : (currentTime + delay), interval, func};
    InsertMessageInternal(m);
    if (!IsCurrent())
    {
#ifdef _WIN32
        SetEvent(event);
#else
        pthread_cond_signal(&cond);
#endif
    }
    return m.id;
}

void MessageThread::InsertMessageInternal(MessageThread::Message& m)
{
    MutexGuard _m(m_queueAccessMutex);
    if (m_queue.empty())
    {
        m_queue.push_back(m);
    }
    else
    {
        if (m_queue[0].deliverAt > m.deliverAt)
        {
            m_queue.insert(m_queue.begin(), m);
        }
        else
        {
            std::vector<Message>::iterator insertAfter = m_queue.begin();
            for (; insertAfter != m_queue.end(); ++insertAfter)
            {
                std::vector<Message>::iterator next = std::next(insertAfter);
                if (next == m_queue.end() || (next->deliverAt > m.deliverAt && insertAfter->deliverAt <= m.deliverAt))
                {
                    m_queue.insert(next, m);
                    break;
                }
            }
        }
    }
}

void MessageThread::Cancel(std::uint32_t id)
{
    MutexGuard _m(m_queueAccessMutex);

    for (std::vector<Message>::iterator m = m_queue.begin(); m != m_queue.end();)
    {
        if (m->id == id)
        {
            m = m_queue.erase(m);
        }
        else
        {
            ++m;
        }
    }
}

void MessageThread::CancelSelf()
{
    assert(IsCurrent());
    m_cancelCurrent = true;
}
