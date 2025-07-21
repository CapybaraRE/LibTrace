﻿#pragma once

#include <functional>
#include <future>
#include <mutex>
#include <queue>

class CThreadPool
{
public:
    explicit CThreadPool(const size_t threads) : stop(false), threads_(threads)
    {
        for(size_t i = 0; i < threads; ++i)
            workers.emplace_back
        (
                [this]
                {
                    for(;;)
                    {
                        std::function<void()> task;
                        {
                            std::unique_lock<std::mutex> lock(this->queue_mutex);
                            this->condition.wait(lock,
                                [this]{ return this->stop || !this->tasks.empty(); });
                            if(this->stop && this->tasks.empty())
                                return;
                            task = std::move(this->tasks.front());
                            this->tasks.pop();
                        }
                        task();
                    }
                }
            );
    }

    template<class F, class... Args>
    auto enqueue(F&& f, Args&&... args) -> std::future<std::invoke_result_t<F, Args...>>
    {
        using return_type = std::invoke_result_t<F, Args...>;

        auto task = std::make_shared< std::packaged_task<return_type()> >
        (
            [Func = std::forward<F>(f)] { return Func(); }
        );
            
        std::future<return_type> res = task->get_future();
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            if(stop)
            {
                throw std::runtime_error("Enqueue on stopped ThreadPool");
            }
            
            tasks.emplace([task](){ (*task)(); });
        }
        condition.notify_one();
        
        return res;
    }

    ~CThreadPool()
    {
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            stop = true;
        }
        condition.notify_all();
        
        for(std::thread &worker: workers)
            worker.join();
    }
private:
    std::vector<std::thread> workers;
    std::queue<std::function<void()>> tasks;
    
    std::mutex queue_mutex;
    std::condition_variable condition;
    bool stop;
    size_t threads_;
};
