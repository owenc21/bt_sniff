/**
 * Header/Interface for the BT_Sniff class
 * @author: Owen Capell
*/
#ifndef BT_SNIFF
#define BT_SNIFF

#include <string>
#include <memory>
#include <atomic>
#include <queue>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#include "bluetoothdef.hpp"

/**
 * @details
 * Typedef of event queue that's used by scanning loop to
 * queue procsedded_adv_event objects
*/
typedef std::queue<std::shared_ptr<processed_adv_event>> non_atom_event_queue;

/**
 * @details
 * Typedef of atomic (wrapper) queue that's used by scanning loop to queue
 * processed_adv_event objects to be consumed by user
 * 
 * There are libraries that implement much better lock-free queues,
 * but i have zero interest in bringing in an external library
 * for such a simple synchronizaiton-friendly,
 * single-producer/single-consumer queue lol
*/
typedef std::atomic<non_atom_event_queue> event_queue;


class BT_Sniff{
public:
    BT_Sniff();
    ~BT_Sniff();

    /**
     * @brief Starts the capture loop
    */
    int start_le_scan(event_queue& usr_queue, const bool& verbose, const bool& raw);
    
    /**
     * @brief Stops the capture loop
    */
    int stopCapture();

private:
    /**
     * @brief Device id for the Bluetooth device (adapter)
    */
    int device_id;

    /**
     * @brief Socket file descriptor
    */
    int socket_fd;

    /**
     * @brief Boolean flag to indicate if instance is initialized
    */
    bool initialized;

    /**
     * @brief Boolean flag to indicate if scanning is ongoing
    */
    bool is_scanning;

    /**
     * @brief Boolean flag to indicate if ready to start scanning
    */
    bool scan_ready;

    /**
     * @brief Inner function that initializes and binds the socket and sets data fields
    */
    int initialize();
};

#endif