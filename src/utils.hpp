#ifndef BT_SNIFF_UTILS
#define BT_SNIFF_UTILS

#include <string>

#include "bluetoothdef.hpp"

/**
 * @brief
 * Convert 6-byte address into string
*/
static std::string addr_to_str(const uint8_t *addr);

/**
 * @brief
 * Convert event_type flag into human-readable string
*/
static std::string event_type(uint16_t event_type);

/**
 * @brief
 * Convert addr_type flag into human_readable string
*/
static std::string addr_type(uint8_t addr_type);

/**
 * @brief
 * Processes AD data in HCI_LE_META_EXTENDED_ADVERTISEMENT_RESPONSE_EVENT packet
*/
static void process_ad(hci_le_meta_ear_event_t *event);

/**
 * @brief
 * Print all necessary fields for the HCI_LE_META_EXTENDED_ADVERTISEMENT_RESPONSE_EVENT
*/
static void print_extended_advertising_report(hci_le_meta_ear_event_t *event);

#endif