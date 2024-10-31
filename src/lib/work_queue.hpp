#ifndef THREAD_SAFE_WORK_QUEUE
#define THREAD_SAFE_WORK_QUEUE

#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>

template <typename T>
class ThreadSafeWorkQueue
{
    std::queue<T> queue;
    std::mutex mtx;
    std::condition_variable cv;

public:
    void push(const T &item)
    {
        std::lock_guard<std::mutex> lock(mtx);
        queue.push(item);
        cv.notify_one();
    }

    bool try_pop(T &item)
    {
        std::unique_lock<std::mutex> lock(mtx);

        if (queue.empty())
            return false;

        item = queue.front();
        queue.pop();
        return true;
    }

    bool empty()
    {
        std::lock_guard<std::mutex> lock(mtx);
        return queue.empty();
    }
};

#endif