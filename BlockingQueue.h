//
// libtgvoip is free and unencumbered public domain software.
// For more information, see http://unlicense.org or the UNLICENSE file
// you should have received with this source code distribution.
//

#ifndef LIBTGVOIP_BLOCKINGQUEUE_H
#define LIBTGVOIP_BLOCKINGQUEUE_H

#include "threading.h"
#include "utils.h"
#include <list>
#include <cstdlib>
#include <functional>

namespace tgvoip
{

template <typename T>
class BlockingQueue
{
public:
    TGVOIP_DISALLOW_COPY_AND_ASSIGN(BlockingQueue);
    BlockingQueue(std::size_t capacity)
        : m_capacity(capacity)
        , m_semaphore(capacity, 0)
        , m_overflowCallback(nullptr)
    {
    }

    ~BlockingQueue()
    {
        m_semaphore.Release();
    }

    void Put(T thing)
    {
        MutexGuard sync(m_mutex);
        m_queue.emplace_back(std::move(thing));
        bool didOverflow = false;
        while (m_queue.size() > m_capacity)
        {
            didOverflow = true;
            if (m_overflowCallback)
            {
                m_overflowCallback(std::move(m_queue.front()));
                m_queue.pop_front();
            }
            else
            {
                std::abort();
            }
        }
        if (!didOverflow)
            m_semaphore.Release();
    }

    T GetBlocking()
    {
        m_semaphore.Acquire();
        MutexGuard sync(m_mutex);
        return GetInternal();
    }

    T Get() const
    {
        MutexGuard sync(m_mutex);
        if (m_queue.size() > 0)
            m_semaphore.Acquire();
        return GetInternal();
    }

    std::size_t Size() const
    {
        return m_queue.size();
    }

    void PrepareDealloc()
    {
    }

    void SetOverflowCallback(const std::function<void(T)>& overflowCallback)
    {
        m_overflowCallback = overflowCallback;
    }

private:
    T GetInternal()
    {
        //if(queue.size()==0)
        //	return NULL;
        T r = std::move(m_queue.front());
        m_queue.pop_front();
        return r;
    }

    std::list<T> m_queue;
    std::size_t m_capacity;
    //tgvoip_lock_t lock;
    mutable Semaphore m_semaphore;
    mutable Mutex m_mutex;
    std::function<void(T)> m_overflowCallback;
};

} // namespace tgvoip

#endif // LIBTGVOIP_BLOCKINGQUEUE_H
