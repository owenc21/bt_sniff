#include <iostream>
#include <string>
#include <iomanip>
#include <sstream>
#include <algorithm>

#include "bluetoothdef.hpp"
#include "utils.hpp"

std::string addr_to_str(const uint8_t *addr){
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

std::string event_type(uint16_t event_type){
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

std::string addr_type(uint8_t addr_type){
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

void process_ad(hci_le_meta_ear_event_t *event){
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

		/* Important: there is a name */
        if(ad_data->type == 0x09){
            int name_length = (int)(ad_data->length - 1);
            std::string name;
            for(int i=0; i<name_length; i++){
                name.push_back((char)ad_data->data[i]);
            }
            std::cout << "DEVICE NAME: " << name << std::endl;
        }

        data_size -= (int)((ad_data->length) + 1);
        ad_data = (ad_data_t*)((char*)ad_data + (int)(ad_data->length + 1)); // OMG UGLY!!
    }
}

void print_extended_advertising_report(hci_le_meta_ear_event_t *event){
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