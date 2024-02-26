/**
 * Header and documentation for HCI Interface types
 * @author Owen Capell
*/
#ifndef BLUETOOTHDEF
#define BLUETOOTHDEF

/**
 * TODO:
 * Move HCI definitions into separate file
*/

/**
 * @details
 * Typedef to store Bluetooth Device Address
 * Abandons BlueZ btaddr_t but maintains cast compatability
 * @param address	The raw Bluetooth Device Address
*/
typedef struct{
	uint8_t address[6];
} __attribute__ ((packed)) bt_dev_addr_t;

/**
 * @details
 * Typedef to store Advertising/Scan Response Data
 * @param length	Length (in octets) of AD_type + AD_data
 * @param type		AD Type
 * @param data		AD data
*/
typedef struct{
	uint8_t length;
	uint8_t type;
	uint8_t data[];
} __attribute__ ((packed)) ad_data_t;

/* Bluetooth Core Specifications, Version 5.3, Vol 4, Parte E */

/* Raw HCI Packet Types */
#define HCI_PACK_COMMAND    0x01
#define HCI_PACK_ACLDATA    0x02
#define HCI_PACK_SCODATA    0x03
#define HCI_PACK_EVENT      0x04
#define HCI_PACK_ISODATA    0x05
#define HCI_PACK_VENDOR     0xff

/* HCI Event Types */
#define HCI_EVENT_INQUIRY_COMPLETE        0x01
#define HCI_EVENT_INQUIRY_RESULT          0x02
#define HCI_EVENT_CONNECTION_COMPLETE     0x03
#define HCI_EVENT_CONNECTION_REQUEST      0x04
#define HCI_EVENT_DISCONNECTION_COMPLETE  0x05
#define HCI_EVENT_AUTHENTICATION_COMPLETE 0x06
#define HCI_EVENT_REMOTE_NAMEREQUEST_COMPLETE      0x07
#define HCI_EVENT_ENCRYPT_CHANGE_V2       0x59
#define HCI_EVENT_ENCRYPT_CHANGE_V1       0x08
#define HCI_EVENT_CHANGE_CONN_LINK_KEY_COMPLETE	0x09 
#define HCI_EVENT_LINK_KEY_TYPE_CHANGE			0x0A
#define HCI_EVENT_READ_REMOTE_SUPPORTED_FEATURES	0x0B
#define HCI_EVENT_READ_REMOTE_VERSION_INFO_COMPLETE	0x0C
#define HCI_EVENT_QOS_SETUP_COMPLETE	0x0D
#define HCI_EVENT_COMMAND_COMPLETE		0x0E
#define HCI_EVENT_LE_META	0x3E /* LE Controller Specific Event */
/**
 * TODO: Finish adding HCI Events
 * Page 2186 Bluetooth Core Specifications v 5.3
*/

/* LE Meta Event Subcodes */
#define SUBEVT_HCI_LE_CONNECTION_COMPLETE	0x01
#define SUBEVT_HCI_LE_ADVERTISING_REPORT	0x02
#define SUBEVT_HCI_LE_DIRECTED_ADVERTISING_REPORT	0x0B
#define SUBEVT_HCI_LE_PHY_UPDATE_COMPLETE	0x0C
#define SUBEVT_HCI_LE_PERIODIC_ADVERTISING_SYNC_ESTABLISHED	0x0E
#define SUBEVT_HCI_LE_EXTENDED_ADVERTISING_REPORT	0x0D
#define SUBEVT_HCI_LE_PERIODIC_ADVERTISING_REPORT	0x0F
#define SUBEVT_HCI_LE_PERIODIC_ADVERTISING_SYNC_LOST	0x10
#define SUBEVT_HCI_LE_SCAN_TIMEOUT	0x11
#define SUBEVT_HCI_LE_ADVERTISING_SET_TERMINATED	0x12
#define SUBEVT_HCI_LE_SCAN_REQUEST_RECEIVED		0x13

/**
 * @details
 * Typedef to parse HCI Event Packet Header
 * Follows Specifications 5.4.4 (Page 1814)
 * @param event_code	Event code corresponding to the event type
 * @param param_length	Length of all parameters contained in packet (in octets)
 * @param data			Beginning of packet data (beyond header); pointer
*/
typedef struct{
	uint8_t event_code;
	uint8_t	param_length;
	uint8_t data[];
} __attribute__((packed)) hci_pack_event_head_t;

/**
 * @details
 * Typedef to parse event parameters from HCI Event Command Complete
 * Follows specifications 7.7.14 (Page 2188)
 * @param num_hci_command_packets	Number of HCI Command packets allowed to be sent from Host to Controller
 * @param command_op	Opcode of command used to cause event 
 * @param ret	Reutrn parameters for specifiec command. Size depends on command
*/
typedef struct{
	uint8_t num_hci_command_packets;
	uint16_t command_op;
	uint8_t ret[];
} __attribute__ ((packed)) hci_event_command_complete_t;

/* HCI LE Meta Extended Advertising Report (EAR) Definitions */

/**
 * @details
 * Typedef to parse HCI LE Extended Advertsitng Report Event Header
 * Follows Specifications 7.7.65.13 (Page 2269)
 * @param subevent_code		Subevent code of packet (should be 0x0D)
 * @param num_reports		Number of separate reports in packet
 * @param event_start		Pointer to start of event type
*/
typedef struct{
	uint8_t subevent_code;
	uint8_t num_reports;
	uint8_t event_start[];
} __attribute__ ((packed)) hci_le_meta_ear_t;

/**
 * @details
 * Typedef to parse HCI LE Extended Advertising Report Event
 * Follows Specifications 7.7.65.13 (Page 2269-2274)
 * @param event_type	Description of event type
 * @param address_tyoe	Description of address type
 * @param address		Bluetooth Device Address of advertiser
 * @param primary_phy	Description of primary physical channel
 * @param secondary_phy	Description of secondary physical channel
 * @param advertising_sid	Value of advertising set identifier
 * @param tx_power	Transmit power level
 * @param rssi	Received Signal Strength Indicator
 * @param periodic_advertising_interval Describes periodic advertising
 * @param direct_address_type	Type of advertiser's address used in direct advertising
 * @param direct_address	Bluetooth Device Address used in direct advertising
 * @param data_length		Length of advertising data
 * @param data		Advertising data payload
 */
typedef struct{
	uint16_t event_type;
	uint8_t address_type;
	bt_dev_addr_t address;
	uint8_t primary_phy;
	uint8_t secondary_phy;
	uint8_t advertising_sid;
	uint8_t tx_power;
	uint8_t rssi;
	uint16_t periodic_advertising_interval;
	uint8_t direct_address_type;
	bt_dev_addr_t direct_address;
	uint8_t data_length;
	uint8_t data[];
} __attribute__ ((packed)) hci_le_meta_ear_event_t;

#endif