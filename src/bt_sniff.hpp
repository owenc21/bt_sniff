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

class BT_Sniff{
public:
    BT_Sniff();
    ~BT_Sniff();

    /**
     * @brief Starts the capture loop
    */
    int start_le_scan();
    
    /**
     * @brief Stops the capture loop
    */
    int stopCapture();

    /**
     * @brief Wrapper funciton for setting BLE scan parameters
    */
    void set_scan_parameters(u_int8_t type, uint16_t inter,
        uint16_t win, uint8_t own_addr, uint8_t filter);

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
     * @brief pointer to bdaddr_t type for the 48-bit Bluetooth device (adapter) address
    */
    bdaddr_t *bdaddr;    

    /**
     * @brief Dictates type of scanning (0x00 = passive; 0x01 = active)
    */
    uint8_t scan_type; 

    /**
     * @brief Time between start of consecutive scan windows (units of 0.625 ms)
    */
    uint16_t interval;

    /**
     * @brief Length of single scan window (units of 0.625 ms)
    */
    uint16_t window;

    /**
     * @brief Type of address used by scanner (0x00 - public, 0x01 - random)
    */
    uint8_t own_address;

    /**
     * @brief Filter policy (0x00 - all advertisements, 0x01 - whitelist)
    */
    uint8_t filter_policy;

    /**
     * @brief HCI command issuing implementation
    */
    int send_cmd(const std::string& cmd_str);

    /**
     * @brief Inner function that initializes and binds the socket and sets data fields
    */
    int initialize();

    /**
     * @brief Inner function that resets the Bluetooth contoller before configuration
    */
    int reset_controller();

};

#endif