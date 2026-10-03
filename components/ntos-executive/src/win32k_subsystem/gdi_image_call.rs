//! Captured system-image requests retain the caller target and exact packet across IPC.

use super::*;
use nt_pe_loader::system_image_request::{self, Request};

struct Outstanding {
    next: u64,
    packet: ProviderPoolPacketLease,
    packet_pin: SharedPoolPin,
    output: file_ioctl_target::PinnedIoctlOutput,
    address: u64,
    length: u64,
    map_owner: u64,
    admitted_handle: u64,
}
// Shared pool records, not a shared pointer into a component-private Vec allocation.
static REQUESTS: AtomicU64 = AtomicU64::new(0);

unsafe fn fatal(address: u64, reason: u64) -> ! {
    crate::provider_bugcheck::report(0xc4, [W32_GDI_LOAD_LABEL, address, reason, 0])
}

pub(super) unsafe fn set_information(class: u64, buffer: u64, length: u64) -> i32 {
    let mut stage: &'static [u8] = b"header";
    let status = set_information_inner(class, buffer, length, &mut stage);
    if status < 0 {
        print_str(b"[gdi-image-origin] rejected stage="); print_str(stage);
        print_str(b" status=0x"); print_hex(status as u32);
        print_str(b" class="); print_u64(class);
        print_str(b" buffer=0x"); print_hex_u64(buffer);
        print_str(b" length="); print_u64(length); print_str(b"\n");
    }
    status
}

unsafe fn set_information_inner(class: u64, buffer: u64, length: u64,
    stage: &mut &'static [u8]) -> i32 {
    let expected = match class {
        26 => 0x38,
        27 => 8,
        _ => return 0xc000_0003u32 as i32,
    };
    if length != expected {
        return 0xc000_0004u32 as i32;
    }
    if buffer == 0 || buffer.checked_add(length).is_none() {
        return STATUS_ACCESS_VIOLATION_I32;
    }
    *stage = b"activation";
    let Some(activation) = active_provider_stack_event_activation() else {
        return STATUS_ACCESS_VIOLATION_I32;
    };
    *stage = b"output-pin";
    let output = match file_ioctl_target::pin_output(activation, buffer, length) {
        Ok(pin) => pin,
        Err(status) => return status,
    };
    let request = if class == 27 {
        Request::Unload(read_unaligned(buffer as *const u64))
    } else {
        *stage = b"name-header";
        let name_len = read_unaligned(buffer as *const u16) as u64;
        let maximum = read_unaligned((buffer + 2) as *const u16) as u64;
        let address = read_unaligned((buffer + 8) as *const u64);
        if name_len == 0 || name_len & 1 != 0 || name_len > maximum {
            file_ioctl_target::release_output(output);
            return STATUS_INVALID_PARAMETER_I32;
        }
        *stage = b"name-pin";
        let input = match provider_input::pin_input(activation, address, name_len) {
            Ok(pin) => pin,
            Err(status) => {
                file_ioctl_target::release_output(output);
                return status;
            }
        };
        *stage = b"name-capture";
        let mut leaf = [0u8; GDI_DRIVER_LEAF_CAP];
        let count = gdi_driver_leaf_from_wname(address, name_len as usize, &mut leaf);
        provider_input::release_input(input, W32_GDI_LOAD_LABEL);
        let Some(count) = count else {
            file_ioctl_target::release_output(output);
            return STATUS_INVALID_PARAMETER_I32;
        };
        Request::Load(alloc::string::String::from_utf8_lossy(&leaf[..count]).into_owned())
    };
    *stage = b"encode";
    let Some(bytes) = system_image_request::encode(&request) else {
        file_ioctl_target::release_output(output);
        return STATUS_INVALID_PARAMETER_I32;
    };
    let _durable = crate::allocator::enter_durable();
    *stage = b"packet-allocation";
    let Some((packet, mut storage)) =
        allocate_root_provider_pool_packet(bytes.len() + core::mem::size_of::<Outstanding>())
    else {
        file_ioctl_target::release_output(output);
        return STATUS_INSUFFICIENT_RESOURCES_I32;
    };
    *stage = b"packet-pin";
    let Some(packet_pin) = pin_root_provider_pool_packet(packet) else {
        if !retire_root_provider_pool_packet(packet) {
            fatal(buffer, 2);
        }
        file_ioctl_target::release_output(output);
        return STATUS_INSUFFICIENT_RESOURCES_I32;
    };
    storage[..bytes.len()].copy_from_slice(&bytes);
    *stage = b"packet-publish";
    if !publish_provider_pool_packet(packet, &storage) {
        if !retire_pinned_root_provider_pool_packet(packet, packet_pin) {
            fatal(buffer, 1);
        }
        file_ioctl_target::release_output(output);
        return STATUS_INSUFFICIENT_RESOURCES_I32;
    }
    let row_address = packet.address() + bytes.len() as u64;
    {
        let _metadata = ProviderMetadataGuard::acquire();
        (row_address as *mut Outstanding).write(Outstanding {
            next: REQUESTS.load(Ordering::Acquire),
            packet,
            packet_pin,
            output,
            address: buffer,
            length,
            map_owner: WIN32K_ROOT_IMAGE_MAP_OWNER.load(Ordering::Acquire),
            admitted_handle: 0,
        });
        REQUESTS.store(row_address, Ordering::Release);
    }
    print_str(b"[gdi-image-origin] broker-request class="); print_u64(class);
    print_str(b" buffer=0x"); print_hex_u64(buffer);
    print_str(b" length="); print_u64(length);
    print_str(b" packet=0x"); print_hex_u64(packet.address()); print_str(b"\n");
    *stage = b"broker-result";
    let (words, raw, handle, spare, reserved) = crate::driver_launch::call_on4_raw(
        (W32_GDI_LOAD_LABEL << 12) | 4,
        packet.address(),
        bytes.len() as u64,
        0,
        0,
    );
    if words != 2
        || spare != 0
        || reserved != 0
        || (raw as i32 == 0 && (class != 26 || handle == 0))
        || (raw as i32 != 0 && handle != 0)
    {
        fatal(buffer, 3);
    }
    {
        let _metadata = ProviderMetadataGuard::acquire();
        (*(row_address as *mut Outstanding)).admitted_handle = handle;
    }
    if raw as i32 == 0 {
        let Request::Load(name) = &request else {
            fatal(buffer, 4);
        };
        let Some(driver) = registered_gdi_driver_for_leaf(name.as_bytes()) else {
            fatal(buffer, 5);
        };
        let (pin_snapshot, owner, address, length) = {
            let _metadata = ProviderMetadataGuard::acquire();
            let row = &*(row_address as *const Outstanding);
            let pin = match &row.output {
                file_ioctl_target::PinnedIoctlOutput::None => {
                    file_ioctl_target::PinnedIoctlOutput::None
                }
                file_ioctl_target::PinnedIoctlOutput::Image => {
                    file_ioctl_target::PinnedIoctlOutput::Image
                }
                file_ioctl_target::PinnedIoctlOutput::Stack(pin) => {
                    file_ioctl_target::PinnedIoctlOutput::Stack(*pin)
                }
                file_ioctl_target::PinnedIoctlOutput::Pool(pin) => {
                    file_ioctl_target::PinnedIoctlOutput::Pool(*pin)
                }
            };
            (pin, row.map_owner, row.address, row.length)
        };
        if !source_irp::target_live(&pin_snapshot, owner, address, length) {
            fatal(buffer, 6);
        }
        write_unaligned((buffer + 0x10) as *mut u64, driver.image);
        write_unaligned((buffer + 0x18) as *mut u64, handle);
        write_unaligned((buffer + 0x20) as *mut u64, driver.entry);
        write_unaligned((buffer + 0x28) as *mut u64, driver.expdir);
        write_unaligned((buffer + 0x30) as *mut u32, driver.image_len);
    }
    let output = {
        let _metadata = ProviderMetadataGuard::acquire();
        core::mem::replace(
            &mut (*(row_address as *mut Outstanding)).output,
            file_ioctl_target::PinnedIoctlOutput::None,
        )
    };
    file_ioctl_target::release_output(output);
    {
        let _metadata = ProviderMetadataGuard::acquire();
        let mut previous = 0;
        let mut current = REQUESTS.load(Ordering::Acquire);
        while current != 0 && current != row_address {
            previous = current;
            current = (*(current as *const Outstanding)).next;
        }
        if current != row_address {
            fatal(buffer, 7);
        }
        let next = (*(row_address as *const Outstanding)).next;
        if previous == 0 {
            REQUESTS.store(next, Ordering::Release);
        } else {
            (*(previous as *mut Outstanding)).next = next;
        }
    }
    if !retire_pinned_root_provider_pool_packet(packet, packet_pin) {
        let _metadata = ProviderMetadataGuard::acquire();
        (*(row_address as *mut Outstanding)).next = REQUESTS.load(Ordering::Acquire);
        REQUESTS.store(row_address, Ordering::Release);
        fatal(buffer, 8);
    }
    raw as i32
}
