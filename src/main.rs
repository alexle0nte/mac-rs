fn main() {
    let mac_addresses = get_mac_addresses();

    if let Some(mac) = mac_addresses.0 {
        println!(
            "WiFi mac_address: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        );
    } else {
        println!("No WiFi address");
    }

    if let Some(mac) = mac_addresses.1 {
        println!(
            "Ethernet mac_address: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        );
    } else {
        println!("No Ethernet address");
    }
}

fn get_mac_addresses() -> (Option<[u8; 6]>, Option<[u8; 6]>) {
    #[cfg(target_os = "linux")]
    {
        linux::get_mac_addresses()
    }

    #[cfg(target_os = "windows")]
    {
        windows::get_mac_addresses()
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        (None, None)
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs;
    use std::path::Path;

    use tracing::warn;

    const IFACE_TYPE_ETHERNET: u16 = 1;
    const IFACE_TYPE_WIFI: u16 = 801;

    fn is_virtual_interface(iface_path: &Path) -> bool {
        // Virtual interfaces usually lack a "device" entry or are under /sys/devices/virtual.
        !iface_path.join("device").exists()
            || fs::canonicalize(iface_path)
                .ok()
                .and_then(|p| p.to_str().map(|s| s.contains("/sys/devices/virtual/")))
                .unwrap_or(false)
    }

    fn read_mac(iface_path: &Path) -> Option<[u8; 6]> {
        // The MAC address is stored in the "address" file of the network interface.
        let mac_str = std::fs::read_to_string(&iface_path.join("address"))
            .ok()?
            .trim()
            .to_string();

        let parts: Vec<&str> = mac_str.split(':').collect();
        if parts.len() != 6 {
            return None;
        }

        let mut mac = [0u8; 6];
        for (i, part) in parts.iter().enumerate() {
            mac[i] = u8::from_str_radix(part, 16).ok()?;
        }

        Some(mac)
    }

    fn get_interface_type(iface_path: &Path) -> Option<u16> {
        // Interface type is stored as a numeric value in the "type" file.
        fs::read_to_string(iface_path.join("type"))
            .ok()
            .and_then(|s| s.trim().parse::<u16>().ok())
    }

    fn is_wireless(iface_path: &Path) -> bool {
        // A wireless interface has a "wireless" subdirectory.
        iface_path.join("wireless").exists()
    }

    pub(crate) fn get_mac_addresses() -> (Option<[u8; 6]>, Option<[u8; 6]>) {
        let mut wifi_mac = None;
        let mut ethernet_mac = None;

        // Root directory for network interfaces metadata on Linux.
        let net_dir = Path::new("/sys/class/net");

        let entries = match fs::read_dir(net_dir) {
            Ok(e) => e,
            Err(_) => {
                warn!("Unable to read {}.", net_dir.display());
                return (None, None);
            }
        };

        // Iterate over each directory entry representing a network interface.
        for entry in entries.flatten() {
            let iface_path = entry.path();

            // Skip if interface is virtual.
            if is_virtual_interface(&iface_path) {
                continue;
            }

            // Skip interface if MAC is invalid or unreadable.
            let mac = match read_mac(&iface_path) {
                Some(mac) => mac,
                None => continue,
            };

            // Skip if interface type is unknown or unparseable.
            let iface_type = match get_interface_type(&iface_path) {
                Some(t) => t,
                None => continue,
            };

            // Classify based on wireless flag and interface type.
            match (is_wireless(&iface_path), iface_type) {
                (true, t) if t == IFACE_TYPE_WIFI => wifi_mac = Some(mac),
                (false, t) if t == IFACE_TYPE_ETHERNET as u16 => ethernet_mac = Some(mac),
                _ => {}
            };
        }

        (wifi_mac, ethernet_mac)
    }

    #[cfg(test)]
    mod tests {
        #[test]
        fn test_mac_address() {
            use super::get_mac_addresses;
            let mac_addresses = get_mac_addresses();

            if let Some(mac) = mac_addresses.0 {
                println!(
                    "WiFi mac_address: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
                );
            } else {
                println!("No WiFi address");
            }

            if let Some(mac) = mac_addresses.1 {
                println!(
                    "Ethernet mac_address: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
                );
            } else {
                println!("No Ethernet address");
            }
        }
    }
}

#[cfg(target_os = "windows")]
mod windows {
    use std::{mem, ptr};

    use tracing::warn;

    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GetIfEntry2, IF_TYPE_ETHERNET_CSMACD, IF_TYPE_IEEE80211,
        IP_ADAPTER_ADDRESSES_LH as IP_ADAPTER_ADDRESSES, MIB_IF_ROW2,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::{
        IfOperStatusUp, NdisPhysicalMedium802_3, NdisPhysicalMediumNative802_11,
    };
    use windows_sys::Win32::Networking::WinSock::AF_UNSPEC;

    // Extracts MAC address from a network interface row if it's up and has a valid 6-byte address.
    fn extract_mac_from_row(row: &MIB_IF_ROW2) -> Option<[u8; 6]> {
        if row.OperStatus == IfOperStatusUp && row.PhysicalAddressLength == 6 {
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&row.PhysicalAddress[..6]);
            Some(mac)
        } else {
            None
        }
    }

    // Traverses the adapter linked list and extracts the first matching Wi-Fi and Ethernet MAC addresses.
    fn process_adapter(
        adapter: *mut IP_ADAPTER_ADDRESSES,
    ) -> (Option<[u8; 6]>, Option<[u8; 6]>) {
        let mut wifi = None;
        let mut ethernet = None;

        let mut current = adapter;
        while !current.is_null() {
            // SAFETY: `current` is a valid pointer to an IP_ADAPTER_ADDRESSES structure.
            // The list is well-formed and terminated with a null pointer.
            let addr = unsafe { &*current };

            // SAFETY: `row` is zero-initialized and safe to pass to GetIfEntry2,
            // which will write valid data into this structure.
            let mut row: MIB_IF_ROW2 = unsafe { mem::zeroed() }; 
            row.InterfaceLuid = addr.Luid;

            // Populate row with interface information based on adapter LUID.
            //
            // SAFETY: GetIfEntry2 is called with a valid pointer to `row`.
            // Return value 0 indicates success.
            if unsafe {
                GetIfEntry2(&mut row)
            } == 0 {
                if let Some(mac) = extract_mac_from_row(&row) {
                    match (row.Type, row.PhysicalMediumType) {
                        // Verify interface type and physical medium.
                        (IF_TYPE_IEEE80211, NdisPhysicalMediumNative802_11) => wifi = Some(mac),
                        (IF_TYPE_ETHERNET_CSMACD, NdisPhysicalMedium802_3) => ethernet = Some(mac),
                        _ => {}
                    }
                }
            }

            // Move to next adapter in the linked list.
            current = addr.Next;
        }

        (wifi, ethernet)
    }

    pub(crate) fn get_mac_addresses() -> (Option<[u8; 6]>, Option<[u8; 6]>) {
        let mut size = 0;

        // SAFETY: First call only fills `size` to determine required buffer size.
        unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                0,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut size,
            );
        }

        let mut buffer = vec![0u8; size as usize];
        let adapter = buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES;

        // SAFETY: `adapter` points to valid buffer of correct size for storing adapter data.
        if unsafe { GetAdaptersAddresses(AF_UNSPEC as u32, 0, ptr::null_mut(), adapter, &mut size) }
            == ERROR_SUCCESS
        {
            process_adapter(adapter)
        } else {
            warn!("Unable to retrieve MAC addresses.");
            (None, None)
        }
    }

    #[cfg(test)]
    mod tests {
        #[test]
        fn test_mac_address() {
            use super::get_mac_addresses;
            let mac_addresses = get_mac_addresses();

            if let Some(mac) = mac_addresses.0 {
                println!(
                    "WiFi mac_address: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
                );
            } else {
                println!("No WiFi address");
            }

            if let Some(mac) = mac_addresses.1 {
                println!(
                    "Ethernet mac_address: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
                );
            } else {
                println!("No Ethernet address");
            }
        }
    }
}
