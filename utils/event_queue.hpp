/**
 * Header for unbounded, single-producer/single consumer queue
 * @author Owen Capell
*/
#ifndef EVENT_QUEUE
#define EVENT_QUEUE

#include <queue>
#include <memory>
#include <mutex>
#include <condition_variable>

#include "bluetoothdef.hpp"

class eventQueue{
public:
	eventQueue();

	/**
	 * @brief
	 * Enqueues a pointer to processed_adv_event to queue
	*/
	void push(std::shared_ptr<processed_adv_event> p);

	/**
	 * @brief
	 * Removes and returns front element from queue
	*/
	std::shared_ptr<processed_adv_event> pop();

private:
	std::mutex lock;
	std::condition_variable cv;
	std::queue<std::shared_ptr<processed_adv_event>> queue;
};

#endif