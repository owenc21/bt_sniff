#include <iostream>
#include <unistd.h>
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#include "bt_sniff.hpp"

BT_Sniff::BT_Sniff()
    : device_id(-1), socket_fd(-1), scan_type(0x00), interval(0x0010),
    window(0x0010), own_address(0x00), filter_policy(0x00), initialized(false),
    is_scanning(false), scan_ready(false), bdaddr(nullptr)
{
    /**
     * Constructor for BT_Sniff object
     * Calls private initialize function upoin initilization
     * Defaults scan parameters to
     *      Passing scanning (scan_type 0x00)
     *      10 ms interval
     *      10 ms scan window
     *      Public addressing
     *      No filtering
    */
  
    int status = initialize();
    if(status < 0){
        std::cerr << "Initilizaiton Error" << std::endl <<
            errno << std::endl;
    }
    else{
        initialized = true;
    }
}

BT_Sniff::~BT_Sniff(){
    /**
     * Destructor for BT_Sniff object
     * Deallocates data members and closes socket
    */

    if(initialized){
        close(socket_fd);
    }
}

void BT_Sniff::set_scan_parameters(u_int8_t type, uint16_t inter,
    uint16_t win, uint8_t own_addr, uint8_t filter){
    /**
     * Wrapper function to set the data members corresponding
     * to the scan parameters for BLE scan
     * 
     * @param type  uint8_t corresponding to scan type
     * @param inter uint16_t corresponding to time between scan windows (ms)
     * @param win   uint16_t corresponding to the duration of a scan window (ms)
     * @param own_addr uint8_t corresponding to type of address used by scanner (0x00 - public, 0x01 - private)
     * @param filter uint8_t corresponding to scan filter policy (0x00 - no filtering, 0x01 - whitelist)
    */
    if(type != 0x00 || type != 0x01) return;
    scan_type = type;
    interval = htobs(inter);
    window = htobs(win);
    own_address = own_addr;
    filter_policy = filter;
}

int BT_Sniff::set_capture(){
    /**
     * Sets the Bluetooth socket to capture BLE Advertising packets
     * Initializes necessary filter
     * 
     * @returns: 0 on success, -1 on failure
    */

   /* Attempt to reset controller */
   if(reset_controller() < 0) return -1;

    struct hci_filter filter;

    /* Initializes empty filter, sets packet type capture to all hardware, capturs BLE meta events */
    /**
     * TODO: Look into other filters
    */
    hci_filter_clear(&filter);
    hci_filter_set_ptype(HCI_EVENT_PKT, &filter); 
    hci_filter_set_event(EVT_LE_META_EVENT, &filter);

    /* Apply filter */
    if(setsockopt(socket_fd, SOL_HCI, HCI_FILTER, &filter, sizeof(filter)) < 0){
        std::cerr << "Error setting packet types and event filter on socket" << std::endl <<
            errno << std::endl; 
        return -1;
    }

    /* Set scan parameters and enable LE scan */
    if(hci_le_set_scan_parameters(socket_fd, scan_type, interval,
        window, own_address, filter_policy, 1000) < 0){
        std::cerr << "Error setting LE scan parameters" << std::endl <<
            errno << std::endl;

        return -1;
    }

    if(hci_le_set_scan_enable(socket_fd, 0x01, 0x01, 1000)){
        std::cerr << "Error enabling HCI LE scan" << std::endl <<
            errno << std::endl;

        return -1;
    }

    scan_ready = true;
    return 0;
}

int BT_Sniff::initialize(){
    /**
     * Initializes relevant fields for BT_Sniff object
     * Finds Bluetooth device (adapter), opens and binds HCI socket
     * 
     * @param: None
     * @returns: 0 on success, -1 on failure
    */

    /* Get Bluetooth device/adapter (not assuming it is 0) */
    device_id = hci_get_route(NULL);
    struct hci_dev_info dev_info;
    if (hci_devinfo(device_id, &dev_info) < 0){
        std::cerr << "Error getting device id" << std::endl <<
            errno << std::endl;
        return -1;
    }
    memcpy(&this->bdaddr, &dev_info.bdaddr, sizeof(bdaddr_t));


    /* Need raw socket for sniffing; HCI is standard protocol */
    socket_fd = socket(AF_BLUETOOTH, SOCK_RAW | SOCK_CLOEXEC, BTPROTO_HCI);
    if (socket_fd < 0){
        std::cerr << "Error opening socket" << std::endl << 
            errno << std::endl;
        return -1;
    }

    /* Bind socket with the bluetooth device */
    struct sockaddr_hci addr = {};
    addr.hci_family = AF_BLUETOOTH;
    addr.hci_dev =  device_id;
    if(bind(socket_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0){
        close(socket_fd);
        std::cerr << "Error binding socket to device" << std::endl <<
            errno << std::endl;
        return -1;
    }

    /**
     * It's worth noting that the above process is handled by an API wrapper:
     * hci_open_dev, but I'm interested in learning socket programming on an
     * intimate level so I'm opening the socket and binding it myself
    */

    return 0;
}

int BT_Sniff::reset_controller(){
    /**
     * To prevent I/O Errors, bluetooth controller is reset
     * Resets the device binded to the raw socket
     * 
     * @returns 0 on success, -1 on error 
    */

    uint16_t ogf = 0x03; // Link OGF
    uint16_t ocf = 0x0003; // "Reset" command
    uint8_t plen = 0; // Length

    if(hci_send_cmd(socket_fd, ogf, ocf, plen, NULL) < 0){
        std::cerr << "Error resetting the Bluetooth controller" << std::endl <<
            errno << std::endl;
        return -1;
    }

    return 0;
}

int BT_Sniff::startCapture(){
    /**
     * Begins capturing loop in separate process
     * Does NOT process packet (yet)
     * Does NOT utilizng any IPC (yet)
     * 
     * @returns 0 on successful capture loop completion, -1 on error
    */

    if(set_capture() < 0){
        return -1;
    }

    unsigned char buf[HCI_MAX_EVENT_SIZE];
    while(true){
       int len = read(socket_fd, buf, sizeof(buf));
       if(len < 0){
        std::cerr << "Error reading socket" << std::endl <<
            errno << std::endl;
        return -1;
       }

       std::cout << "len: " << len << std::endl;
       std::cout << buf << std::endl;
    }
}

int BT_Sniff::stopCapture(){
    /**
     * Dummy implementation
    */

    return 0;
}