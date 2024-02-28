/**
 * Header/Interface for the BT_Sniff class
 * @author: Owen Capell
*/
#ifndef BT_SNIFF
#define BT_SNIFF

#include <string>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#include "bluetoothdef.hpp"
#include "event_queue.hpp"

class BT_Sniff{
public:
    BT_Sniff();
    ~BT_Sniff();

    /**
     * @brief Starts the capture loop
    */
    int start_le_scan(eventQueue& usr_queue, const bool& verbose, const bool& raw);
    
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