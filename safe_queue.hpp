#ifndef __SAFE_QUEUE__
#define __SAFE_QUEUE__

#include <cstdio>
#include <queue>
#include <thread>
#include <chrono>
#include <mutex>
#include <condition_variable>

using namespace std;

template <typename T>
class SafeQueue {
private:
    queue<T> q;
    mutable mutex m;
    mutable condition_variable c;
public:
    SafeQueue() = default;
    virtual ~SafeQueue() = default;

    void enqueue(T &data) {
        lock_guard<mutex> lock(this->m);
        this->q.push(data);
        this->c.notify_one();
    }

    T& dequeue() {
        unique_lock<mutex> lock(this->m);
        this->c.wait(lock, [&]{return !this->q.empty();});
        T &val = this->q.front();
        q.pop();
        return val;
    }

    int getSize() {
        return static_cast<int>(this->q.size());
    }
};

#endif