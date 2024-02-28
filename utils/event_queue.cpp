/**
 * Implementation of unbounded single-producer/single-consumer queue
 * @author Owen Capell
*/

#include <queue>
#include <memory>
#include <mutex>

#include "bluetoothdef.hpp"
#include "event_queue.hpp"

eventQueue::eventQueue() : 
	lock(), cv(), queue()	
{
	/**
	 * Default constructor for eventQueue
	 * Intializes members
	*/

}

void eventQueue::push(std::shared_ptr<processed_adv_event> p){
	/**
	 * Enqueues pointer p to queue
	 * 
	 * @param p	Pointer to enqueue
	*/

	lock.lock();
	queue.push(p); 
	lock.unlock();

	cv.notify_one();
}

std::shared_ptr<processed_adv_event> eventQueue::pop(){
	/**
	 * Dequeus front-most pointer from queue
	 * 
	 * @returns std::shared_ptr<processed_adv_event> at front of queue
	*/

	std::unique_lock<std::mutex> lockGuard(lock);
	cv.wait(lockGuard, [this]{ return !queue.empty(); });

	std::shared_ptr<processed_adv_event> p = queue.front();
	queue.pop();
	

	return p;
}