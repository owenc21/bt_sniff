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

BT_Sniff::BT_Sniff()
    : device_id(-1), socket_fd(-1), scan_type(0x01), interval(0x0010),
    window(0x0010), own_address(0x00), filter_policy(0x00), initialized(false),
    is_scanning(false), scan_ready(false), bdaddr(nullptr)
{
    /**
     * Constructor for BT_Sniff object
     * Calls private initialize function upoin initilization
     * Defaults scan parameters to
     *      Active scanning (scan_type 0x01)
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

static std::string addr_to_str(const uint8_t *addr){
    /**
     * Utility function to convert the address array into
     * human-readable string (big endian)
     * 
     * @param addr  The uint8_t address array
    */

    std::stringstream ss;

    ss << std::hex << std::setfill('0');

    for(int i=5; i>=0; i--){
        ss << std::hex << std::setw(2) << static_cast<int>(addr[i]);
        ss << ":";
    }

    std::string address = ss.str();
    address.pop_back();
    std::transform(address.begin(), address.end(), address.begin(), toupper);
    
    return address;
}

static std::string event_type(uint16_t event_type){
    /**
     * Utility funciton to convert event_type field
     * into human readable string
     * 
     * @param event_type    the uint16_t event_type field
    */

    std::string event_str;
    switch(event_type){
        case 0b0010011:
            event_str = "ADV_IND";
            break;
        case 0b0010101:
            event_str = "ADV_DIRECT_IND";
            break;
        case 0b0010010:
            event_str = "ADV_SCAN_IND";
            break;
        case 0b0010000:
            event_str = "ADV_NONCONN_IND";
            break;
        case 0b0011011:
            event_str = "SCAN_RSP to an ADV_IND";
            break;
        case 0b0011010:
            event_str = "SCAN_RSP to an ADV_SCAN_IND";
            break;
        default:
            event_str = "EVENT TYPE NOT FOUND";
            break;
    }

    return event_str;
}

static std::string addr_type(uint8_t addr_type){
    /**
     * Utility function to convert address type field
     * into human-readable string
     * 
     * @param addr_type     uint8_t representing the address type
    */

    std::string addr_type_str;

    switch(addr_type){
        case 0x00:
            addr_type_str = "Public";
            break;
        case 0x01:
            addr_type_str = "Random";
            break;
        case 0x02:
            addr_type_str = "Public Identity";
            break;
        case 0x03:
            addr_type_str = "Random (static)";
            break;
        case 0xFF:
            addr_type_str = "None (anonymous)";
            break;
        default:
            addr_type_str = "UNKOWN ADDRESS TYPE";
            break;
    }
    
    return addr_type_str;
}

static void process_ad(hci_le_meta_ear_event_t *event){
    /**
     * Utility funciton to process the advertising data porition of
     * the packet
     * 
     * @param event Pointer to the hci_le_meta_era_event_t
    */

    int data_size = (int) event->data_length;
    if(data_size <= 0) return;

    printf("TOTAL_DATA_LENGTH: %d\n", data_size);

    /* Iterate over all AD payloads */
    ad_data_t *ad_data = (ad_data_t*)event->data;
    while(data_size > 0){
        printf("AD_LENGTH: %u\nAD_TYPE: %02x\n", ad_data->length, ad_data->type);

        data_size -= (int)((ad_data->length) + 1);
        ad_data = (ad_data_t*)((void*)ad_data + (int)(ad_data->length + 1)); // OMG UGLY!!
    }
}

static void print_extended_advertising_report(hci_le_meta_ear_event_t *event){
    /**
     * Uitlity funciton to print information about the extended advertising report
     * 
     * @param event Pointer to the hci_le_meta_era_event_t
    */

    std::cout << "Event type: " << event_type(event->event_type) << std::endl;
    std::cout << "Address: " << addr_to_str(event->address.address) << std::endl;
    std::cout << "Address Type: " << addr_type(event->address_type) << std::endl;
    process_ad(event);
    std::cout << std::endl;
}

int BT_Sniff::start_le_scan(){
    /**
     * Begins capturing loop in separate process
     * Does NOT process packet (yet)
     * Does NOT utilizng any IPC (yet)
     * 
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
                hci_le_meta_ear_t *meta = (hci_le_meta_ear_t*)packet->data;

                hci_le_meta_ear_event_t *event = (hci_le_meta_ear_event_t*)meta->event_start;

                for(uint8_t i=0; i<meta->num_reports; ++i){
                    print_extended_advertising_report(event);
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