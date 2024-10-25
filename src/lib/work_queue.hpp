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
    bool done;

public:
    explicit ThreadSafeWorkQueue() : done(false) {}

    void push(const T &item)
    {
        std::lock_guard<std::mutex> lock(mtx);
        queue.push(item);
        cv.notify_one();
    }

    bool try_pop(T &item)
    {
        std::unique_lock<std::mutex> lock(mtx);
        cv.wait(lock, [this]()
                { return !queue.empty() || done; });

        if (queue.empty() && done)
            return false;

        if (!queue.empty())
        {
            item = queue.front();
            queue.pop();
            return true;
        }
        return false;
    }

    void set_done()
    {
        std::lock_guard<std::mutex> lock(mtx);
        done = true;
        cv.notify_all();
    }

    bool is_done() const
    {
        return done && queue.empty();
    }
};

#endif