#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <vector>
#include <unistd.h>
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#include "bt_sniff.hpp"
#include "bluetoothdef.hpp"
#include "utils.hpp"

BT_Sniff::BT_Sniff()
    : device_id(-1), socket_fd(-1), initialized(false),
    is_scanning(false), scan_ready(false)
    {
    /**
     * Constructor for BT_Sniff object
     * Calls private initialize function upoin initilization
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

    /* Need raw socket for sniffing; HCI is standard protocol */
    socket_fd = socket(AF_BLUETOOTH, SOCK_RAW | SOCK_CLOEXEC, BTPROTO_HCI);
    if (socket_fd < 0){
        std::cerr << "Error opening socket" << std::endl << 
            errno << std::endl;
        return -1;
    }

    /* Configure to capture all packets and events */
    struct hci_filter filter;
    hci_filter_clear(&filter);
    hci_filter_all_ptypes(&filter);
    hci_filter_all_events(&filter);

    /* Apply filter */
    if(setsockopt(socket_fd, SOL_HCI, HCI_FILTER, &filter, sizeof(filter)) < 0){
        std::cerr << "Error applying HCI filter on socket" << std::endl <<
            errno << std::endl;
        return -1;
    }

    /**
     * TODO: Add setsockopt() calls to enable timestamping and HCI directionality
    */

    /* Bind socket with the bluetooth device */
    struct sockaddr_hci addr = {};
    addr.hci_family = AF_BLUETOOTH;
    addr.hci_dev =  device_id;
    addr.hci_channel = HCI_CHANNEL_RAW;
    if(bind(socket_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0){
        close(socket_fd);
        std::cerr << "Error binding socket to device" << std::endl <<
            errno << std::endl;
        return -1;
    }

    return 0;
}


int BT_Sniff::start_le_scan(
    std::shared_ptr<processed_adv_event> usr_evt, const bool& verbose){
    /**
     * Begins capturing loop in separate process
     * Does NOT process packet (yet)
     * Does NOT utilizng any IPC (yet)
     * 
     * @param usr_evt Pointer to processed_adv_event struct to populate for user-space analysis 
     * @param verbose Boolean flag to enable packet capture from printing to stdout
     * @returns 0 on successful capture loop completion, -1 on error
    */

    unsigned char buf[HCI_MAX_EVENT_SIZE];
    while(true){
       int len = read(socket_fd, buf, sizeof(buf));
       if(len < 0){
        std::cerr << "Error reading socket" << std::endl <<
            errno << std::endl;
        return -1;
       }

        /**
         * Manual filtering of HCI_EVENT_LE_META 
         * TODO: Add advanced filtering logic
        */
        if((unsigned int)buf[0] == HCI_PACK_EVENT){
            hci_pack_event_head_t *packet = (hci_pack_event_head_t *)(buf + 1);

            if(packet->event_code == HCI_EVENT_LE_META){
                /* Assuming the meta event will be an extended advertising report */
                hci_le_meta_ear_t *meta = (hci_le_meta_ear_t*)packet->data;

				/* Skip if not extended advertising report */
                if(meta->subevent_code != SUBEVT_HCI_LE_EXTENDED_ADVERTISING_REPORT) continue;

                hci_le_meta_ear_event_t *event = (hci_le_meta_ear_event_t*)meta->event_start;

                for(uint8_t i=0; i<meta->num_reports; ++i){
                    uint16_t evt = event->event_type;
                    /* Manual filter of event PDU */
                    if(evt!=ADV_NONCONN_IND && evt!=ADV_DIRECT_IND){
                        process_extended_advertising_report(event, usr_evt, verbose);
                    }
                    event = event + sizeof(event);
                }
            }
        }

    //    std::cout << std::endl << "Raw packet data: " << std::endl;
    //    for (int i = 0; i < len; i++) {
    //         printf("%02x ", (unsigned int)buf[i]);
    //     }
    //     std::cout << std::endl; 
        
    }
}

int BT_Sniff::stopCapture(){
    /**
     * Dummy implementation
    */

    return 0;
}