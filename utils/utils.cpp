#include <iostream>
#include <string>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <memory>

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
        case ADV_IND:
            event_str = "ADV_IND";
            break;
        case ADV_DIRECT_IND:
            event_str = "ADV_DIRECT_IND";
            break;
        case ADV_SCAN_IND:
            event_str = "ADV_SCAN_IND";
            break;
        case ADV_NONCONN_IND:
            event_str = "ADV_NONCONN_IND";
            break;
        case SCAN_RSP_TO_ADV_IND:
            event_str = "SCAN_RSP to an ADV_IND";
            break;
        case SCAN_RSP_TO_ADV_SCAN_IND:
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

void process_ad(
    hci_le_meta_ear_event_t *event, std::shared_ptr<processed_adv_event> usr_evt, const bool& verbose){
    /**
     * Utility funciton to process the advertising data porition of
     * the packet
     * 
     * @param event Pointer to the hci_le_meta_era_event_t
     * @param usr_evt   Pointer to user-space event struct to add name to
     * @param verbose Boolean flag indicating whether to print AD details
    */

    int data_size = (int) event->data_length;
    if(data_size <= 0) return;

    std::string name = "";

    /* Iterate over all AD payloads */
    ad_data_t *ad_data = (ad_data_t*)event->data;
    while(data_size > 0){
        /* Flags */
        /* For now, only worry about flags in verbose mode */
        if(ad_data->type == 0x01 && verbose){
            uint8_t flag = event->data[0];
            std::cout << "FLAGS: " << std::endl;
            if(flag & 0x01) std::cout << "LE Limited Discoverable Mode" << std::endl;
            flag >>= 1;
            if(flag & 0x01) std::cout << "LE General Discoverable Mode" << std::endl;
            flag >>= 1;
            if(flag & 0x01) std::cout << "BR/EDR Not Supported" << std::endl;
            flag >>= 1;
            if(flag & 0x01) std::cout << "Simultaneous LE and BR/EDR" << std::endl;
            flag >>= 1;
            if(flag & 0x01) std::cout << "Previously Used" << std::endl;
        }

		/* Important: there is a name */
        if(ad_data->type == 0x09){
            int name_length = (int)(ad_data->length - 1);
            for(int i=0; i<name_length; i++){
                name.push_back((char)ad_data->data[i]);
            }
            if(verbose) std::cout << "DEVICE NAME: " << name << std::endl;
        }

        data_size -= (int)((ad_data->length) + 1);
        ad_data = (ad_data_t*)((char*)ad_data + (int)(ad_data->length + 1)); // OMG UGLY!!
    }

    usr_evt->name = name;
}

void process_extended_advertising_report(
    hci_le_meta_ear_event_t *event, std::shared_ptr<processed_adv_event> usr_evt, const bool& verbose){
    /**
     * Uitlity funciton to print information about the extended advertising report
     * Updates the provided user-space struct with relevant information (name, address) 
     * 
     * @param event Pointer to the hci_le_meta_era_event_t
     * @param usr_evt   Pointer to user-space event struct to populate with relevant information
     * @param verbose   Boolean flag indicating whether advertising report info should be printed to stdout
    */

    std::string evt_type = event_type(event->event_type);
    std::string addr = addr_to_str(event->address.address);

    if(verbose){
        std::cout << "Event type: " << evt_type << std::endl;
        std::cout << "Address: " << addr << std::endl;
        std::cout << "Address Type: " << addr_type(event->address_type) << std::endl;
        
        std::cout << std::endl;
    }

    usr_evt->event_s = evt_type;
    usr_evt->address = addr;

    process_ad(event, usr_evt, verbose);
}