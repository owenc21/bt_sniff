# `bt_sniff`, a Bluetooth Low Energy (BLE) Event Capture API

BLE is a WAN technology succeeding the original Bluetooth technology. BLE connections only last for a short period of time, transferring small amounts of data. This allows compatible devices to use very little energy while transmitting data.

## API Overview

After spending numerous days scouring the internet for proper Bluetooth/HCI documentation within BlueZ, all I came across were some 10-15 year old projects that used BlueZ's wrapper API to initiate an LE Scan.

Thoroughly dismayed by the lack of documentation and clarity within BlueZ, coupled with the fact that BlueZ "deprecated" raw socket support in 2017, I beleive this project serves as the current modern standard for writing and/or using an HCI API.

 BlueZ's wrapper functions, such as `set_le_scan_parameters()` and `set_le_scan_enable()` are riddled with outdated `ioctl()` calls. The provided macros, `typedef`s, and `enum`s in `hci.h` and `bluetooth.h` had little-to-no documentation.

This API implements a very basic LE Extended Scan packet capture loop. More importantly, this API serves as a well-documented backbone for all future HCI API development. 

Firstly, `BT_Sniff()`, the main API class, opens a raw Berkley socket and binds it to the HCI device (if one is found-finding such a device is one of the few areas where BlueZ is still used). This socket is given no filters so as to capture any and all HCI events.

Next, in `utils/bluetoothdef.hpp` is a modernized and well documented set of macros, `typedef`s, and `enum`s that provide a standard moving forward. These are well documented enough for out-of-the-box use and modular enough to easily support more additions. Specifically, the packed `struct` definitions provide an explanation for their packet-capturing structure and provide a refernence to the relevant information in the Bluetooth Core Specificaitons.

The member function `BT_Sniff()::start_le_scan()` provides a very basic outline as to how one could open an end-point for the API. This function provides a basic packet-capture loop and utilizes the thread-friendly, race-condition-free `event_queue` (found in `utils/event_queue.hpp`) to interface with user-space programs. Additionally, basic filtering logic is supplied as well as utility packet processing functions in `utils/utils.hpp`.

## Usage

As mentioned previously, this API serves two purposes:
1. Provide basic out-of-the-box interface ability with user-space programs with an extended BLE Scan
2. Provide a baseline for future HCI APIs

This project is configured such that `CMakeLists.txt` creates a library `bt_sniff` that can be linked in other projects. In other words, this is truly an plug-and-play API, especially with Git submodules. 

The hope is that this can provide a well-documented standard and reference for modern Bluetooth HCI development. There are numerous interesting avenues that have not been explored yet that can be:
1. Issuing HCI Commands
2. Complex Packet Filtering
3. Adding directionality and timestamps to captured packets