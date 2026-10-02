//! Authenticated GUI client-info copyout and failure-only boundary diagnostics.

use super::*;

unsafe fn rejected(
    stage: &[u8],
    status: u32,
    channel: &spawn_hosts::PumpChannel,
    packet: Option<&win32k_subsystem::Win32kGuiClientInfoPacket>,
    expected: &[u64],
) -> i32 {
    print_str(b"[gui-clientinfo-rejected] stage=");
    print_str(stage);
    print_str(b" status=");
    print_hex_u64(u64::from(status));
    print_str(b" tcb=");
    print_hex_u64(channel.tcb);
    print_str(b" channel-pi=");
    print_u64(channel.client_pi);
    print_str(b" channel-generation=");
    print_u64(channel.client_generation);
    if let Some(logical) = channel.logical_caller {
        print_str(b" logical[pi,pid,tid,thread-generation,badge]=");
        for value in [
            logical.pi() as u64,
            u64::from(logical.process().pid),
            u64::from(logical.thread().thread_id()),
            logical.thread().generation(),
            logical.badge(),
        ] {
            print_hex_u64(value);
            print_str(b" ");
        }
    }
    if let Some(packet) = packet {
        print_str(b" claimed[magic,dispatch,pi,pid,generation,tid,pti,server,client,bytes,deskinfo,pcti,delta,keyboard,hkl,codepage]=");
        for value in [
            packet.magic,
            packet.dispatch_id,
            packet.client_pi,
            packet.process_id,
            packet.process_generation,
            packet.thread_id,
            packet.thread_info,
            packet.server_base,
            packet.client_base,
            packet.mapping_bytes,
            packet.server_deskinfo,
            packet.server_client_thread_info,
            packet.mapped_delta,
            packet.keyboard_present,
            packet.keyboard_hkl,
            packet.keyboard_codepage,
        ] {
            print_hex_u64(value);
            print_str(b" ");
        }
    }
    print_str(b" expected[pi,pid,generation,tid,pti,dispatch,delta,teb,provider-domain,provider-generation]=");
    for &value in expected {
        print_hex_u64(value);
        print_str(b" ");
    }
    print_str(b"\n");
    status as i32
}

pub(super) unsafe fn service(
    channel: &spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    mi: u64,
    packet_address: u64,
    packet_bytes: u64,
    reserved0: u64,
    reserved1: u64,
) -> i32 {
    use nt_user_host::gui_client_info_snapshot::{
        DesktopClientMapping, GuiClientInfoOwner, GuiClientInfoSnapshot, KeyboardLayoutClientInfo,
    };
    let invalid = nt_process::STATUS_INVALID_PARAMETER as i32;
    let reject = |stage: &[u8], status: i32| rejected(stage, status as u32, channel, None, &[]);
    if reserved0 != 0
        || reserved1 != 0
        || packet_bytes
            != core::mem::size_of::<win32k_subsystem::Win32kGuiClientInfoPacket>() as u64
    {
        return reject(b"request-shape", invalid);
    }
    let (route, dispatch, caller) = match authenticate_win32k_service_request(
        channel,
        reply_cap,
        badge,
        mi,
        (win32k_subsystem::W32_GUI_CLIENT_INFO_LABEL << 12) | 4,
    ) {
        Ok(identity) => identity,
        Err(status) => return reject(b"authentication", status as i32),
    };
    let Some(logical) = channel.logical_caller else {
        return reject(b"logical-caller", invalid);
    };
    let Some(wait_owner) = win32k_glue::current_provider_poll_owner(channel) else {
        return reject(b"poll-owner", invalid);
    };
    let Some(provider) = crate::current_win32k_provider_domain() else {
        return reject(b"provider-domain", invalid);
    };
    if wait_owner.provider_domain != provider.domain
        || wait_owner.provider_generation != provider.generation
        || logical.thread() != caller.original_thread()
        || !validate_provider_logical_caller(logical)
    {
        return rejected(
            b"caller-owner",
            invalid as u32,
            channel,
            None,
            &[
                logical.pi() as u64,
                u64::from(logical.process().pid),
                channel.client_generation,
                u64::from(caller.original_thread().thread_id()),
                0,
                wait_owner.dispatch_id,
                0,
                0,
                provider.domain,
                provider.generation,
            ],
        );
    }
    let (_, bytes) =
        match win32k_subsystem::capture_provider_pool_packet(packet_address, packet_bytes as usize)
        {
            Ok(captured) => captured,
            Err(status) => return reject(b"packet-capture", status as i32),
        };
    let packet = core::ptr::read_unaligned(
        bytes.as_ptr() as *const win32k_subsystem::Win32kGuiClientInfoPacket
    );
    let reject =
        |stage: &[u8], status: i32| rejected(stage, status as u32, channel, Some(&packet), &[]);
    let pi = logical.pi();
    let Some(pml4) = (SERVICE_DELAY_DRAIN_HANDLER.load(Ordering::Acquire) as *mut ExecNtHandler)
        .as_mut()
        .and_then(|handler| handler.hosted_process_vspace(pi))
    else {
        return reject(b"process-vspace", invalid);
    };
    let handler = &mut *(SERVICE_DELAY_DRAIN_HANDLER.load(Ordering::Acquire) as *mut ExecNtHandler);
    let Some(process) = handler.capture_process_identity(pi) else {
        return reject(b"process-identity", invalid);
    };
    let thread = caller.original_thread();
    let thread_info = match ps_object_backing::read_thread_win32(&handler.pm, thread) {
        Ok(thread_info) => thread_info,
        Err(status) => return reject(b"canonical-thread-body", status as i32),
    };
    let expected = [
        pi as u64,
        u64::from(process.pid),
        channel.client_generation,
        u64::from(thread.thread_id()),
        thread_info,
        wait_owner.dispatch_id,
        0,
        0,
        provider.domain,
        provider.generation,
    ];
    let reject = |stage: &[u8], status: i32| {
        rejected(stage, status as u32, channel, Some(&packet), &expected)
    };
    if packet.magic != win32k_subsystem::W32_GUI_CLIENT_INFO_PACKET_MAGIC
        || packet.dispatch_id != wait_owner.dispatch_id
        || packet.client_pi != pi as u64
        || packet.process_id != u64::from(process.pid)
        || packet.process_generation != channel.client_generation
        || packet.thread_id != u64::from(thread.thread_id())
        || logical.process() != process
        || handler.pm.thread_lifetime(thread.thread_id()) != Some(thread)
        || thread_info != packet.thread_info
        || packet.keyboard_present > 1
        || (packet.keyboard_present == 0
            && (packet.keyboard_hkl != 0 || packet.keyboard_codepage != 0))
    {
        return reject(b"packet-owner", invalid);
    }
    let admitted = GuiClientInfoOwner {
        process,
        thread,
        provider,
        dispatch: (route, dispatch, wait_owner.dispatch_id),
    };
    let claimed = GuiClientInfoOwner {
        process: nt_user_host::process_identity::ProcessIdentity {
            pid: packet.process_id as u32,
            generation: nt_user_host::process_identity::ProcessGeneration::Hosted(
                packet.process_generation,
            ),
        },
        ..admitted
    };
    let keyboard = if packet.keyboard_present != 0 {
        let Ok(codepage) = u16::try_from(packet.keyboard_codepage) else {
            return reject(b"keyboard-codepage", invalid);
        };
        Some(KeyboardLayoutClientInfo {
            hkl: packet.keyboard_hkl,
            codepage,
        })
    } else {
        None
    };
    let mapping = DesktopClientMapping {
        server_base: packet.server_base,
        client_base: packet.client_base,
        bytes: packet.mapping_bytes,
        server_deskinfo: packet.server_deskinfo,
        server_client_thread_info: packet.server_client_thread_info,
        mapped_delta: packet.mapped_delta,
    };
    let Ok(snapshot) =
        GuiClientInfoSnapshot::capture(claimed, admitted, packet.thread_info, mapping, keyboard)
    else {
        return reject(b"snapshot-mapping", invalid);
    };
    let client_badge = logical.badge();
    let Some(teb_alias) = hosted_gui_thread_teb_alias_for(
        handler,
        pi,
        client_badge,
        packet.thread_id,
        tp_worker_identity_from_badge(client_badge),
    ) else {
        return reject(b"teb-alias", invalid);
    };
    let Some(mapped_delta) = win32k_glue::map_win32k_user_heap_into_client(handler, pml4, pi)
    else {
        return reject(
            b"heap-mapping",
            nt_process::STATUS_INSUFFICIENT_RESOURCES as i32,
        );
    };
    let current_process = handler.capture_process_identity(pi);
    let current_thread = handler.pm.thread_lifetime(thread.thread_id());
    let current_thread_info = ps_object_backing::read_thread_win32(&handler.pm, thread);
    let current_provider = crate::current_win32k_provider_domain();
    let current_teb_alias = hosted_gui_thread_teb_alias_for(
        handler,
        pi,
        client_badge,
        packet.thread_id,
        tp_worker_identity_from_badge(client_badge),
    );
    if mapped_delta != packet.mapped_delta
        || current_provider != Some(provider)
        || win32k_glue::current_provider_poll_owner(channel) != Some(wait_owner)
        || current_thread != Some(thread)
        || current_process != Some(process)
        || handler.hosted_process_generation(pi) != Some(channel.client_generation)
        || current_thread_info != Ok(packet.thread_info)
        || current_teb_alias != Some(teb_alias)
    {
        let expected = [
            pi as u64,
            current_process.map_or(0, |process| u64::from(process.pid)),
            handler.hosted_process_generation(pi).unwrap_or(0),
            current_thread.map_or(0, |thread| u64::from(thread.thread_id())),
            current_thread_info.unwrap_or(0),
            win32k_glue::current_provider_poll_owner(channel).map_or(0, |owner| owner.dispatch_id),
            mapped_delta,
            current_teb_alias.unwrap_or(0),
            current_provider.map_or(0, |provider| provider.domain),
            current_provider.map_or(0, |provider| provider.generation),
        ];
        return rejected(
            b"post-map-revalidation",
            invalid as u32,
            channel,
            Some(&packet),
            &expected,
        );
    }
    let current = GuiClientInfoOwner {
        process: current_process.expect("revalidated GUI process disappeared"),
        thread: current_thread.expect("revalidated GUI thread disappeared"),
        provider: current_provider.expect("revalidated GUI provider disappeared"),
        dispatch: (route, dispatch, wait_owner.dispatch_id),
    };
    let Ok(values) = snapshot.values_for(current) else {
        return reject(b"snapshot-owner", invalid);
    };
    let old_pti = core::ptr::read_volatile((teb_alias + 0x78) as *const u64);
    core::ptr::write_volatile((teb_alias + 0x78) as *mut u64, values.win32_thread_info);
    core::ptr::write_volatile((teb_alias + 0x820) as *mut u64, values.client_deskinfo);
    core::ptr::write_volatile((teb_alias + 0x828) as *mut u64, values.desktop_delta);
    core::ptr::write_volatile((teb_alias + 0x860) as *mut u64, values.client_thread_info);
    if let Some(keyboard) = values.keyboard_layout {
        core::ptr::write_volatile((teb_alias + 0x890) as *mut u64, keyboard.hkl);
        core::ptr::write_volatile((teb_alias + 0x898) as *mut u16, keyboard.codepage);
    }
    log_refreshed_gui_thread_client_info(
        handler.hosted_process_role(pi) == Some(nt_exe_image::HostedProcessRole::InteractiveLogon),
        pi,
        packet.thread_id,
        teb_alias,
        values.client_deskinfo,
        values.win32_thread_info,
        values.desktop_delta,
        values.client_thread_info,
        old_pti,
    );
    0
}
