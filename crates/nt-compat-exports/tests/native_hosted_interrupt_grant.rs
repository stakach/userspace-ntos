//! Execute the native root grant selector with host-owned PnP, physical and HAL records.
//! The included function is the production function used by interrupt PROVISION/CONNECT.

use std::sync::Mutex;

static TEST_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DomainId(u64);
impl DomainId {
    fn raw(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Domain {
    domain_id: DomainId,
    cookie: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HostedDeviceBinding {
    used: bool,
    driver_id: u64,
    instance: usize,
    projection_instance: usize,
    projection_domain: Domain,
    device_id: u64,
    pdo_object: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Evidence {
    interrupt_vector: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HostedDeviceResourceState {
    pnp_context_lease: Option<u64>,
    interrupt_claim: Option<u64>,
    evidence: Evidence,
    interrupt_line: u32,
    interrupt_irql: u8,
    interrupt_affinity: u64,
    interrupt_shared: bool,
    interrupt_latched: bool,
    interrupt_active_low: bool,
}

#[derive(Clone, Copy)]
struct Physical {
    gsi: u32,
    vector: u32,
    level_sensitive: bool,
    active_low: bool,
    shared: bool,
}

#[derive(Clone, Copy)]
struct Resource {
    kind: u32,
    share: u8,
    resource_id: u64,
    raw_start: u64,
    translated_start: u64,
    vector: u32,
    irql: u8,
    affinity: u32,
    mode: u8,
}
impl Resource {
    fn interrupt_fields(self) -> (u32, u8, u32, u8) {
        (self.vector, self.irql, self.affinity, self.mode)
    }
}

mod nt_hal_abi {
    pub const RES_KIND_INTERRUPT: u32 = 1;
    pub const SHARE_SHARED: u8 = 1;
    pub const INT_MODE_LATCHED: u8 = 1;
    pub const INT_MODE_LEVEL_SENSITIVE: u8 = 0;
}

static mut BINDINGS: Option<Vec<HostedDeviceBinding>> = None;
static mut STATES: Option<Vec<(HostedDeviceBinding, HostedDeviceResourceState)>> = None;
static mut LEASES: Option<Vec<u64>> = None;
static mut CLAIMS: Option<Vec<(u64, Physical)>> = None;
static mut RESOURCES: Option<Vec<(u64, Resource)>> = None;
static mut SHARED_BANK_VECTOR: u32 = 0;

fn bindings() -> &'static mut Vec<HostedDeviceBinding> {
    unsafe { (&mut *std::ptr::addr_of_mut!(BINDINGS)).as_mut().unwrap() }
}
fn states() -> &'static mut Vec<(HostedDeviceBinding, HostedDeviceResourceState)> {
    unsafe { (&mut *std::ptr::addr_of_mut!(STATES)).as_mut().unwrap() }
}
fn leases() -> &'static mut Vec<u64> {
    unsafe { (&mut *std::ptr::addr_of_mut!(LEASES)).as_mut().unwrap() }
}
fn claims() -> &'static mut Vec<(u64, Physical)> {
    unsafe { (&mut *std::ptr::addr_of_mut!(CLAIMS)).as_mut().unwrap() }
}
fn resources() -> &'static mut Vec<(u64, Resource)> {
    unsafe { (&mut *std::ptr::addr_of_mut!(RESOURCES)).as_mut().unwrap() }
}

fn hosted_device_bindings() -> Option<&'static [HostedDeviceBinding]> {
    Some(bindings().as_slice())
}
fn hosted_device_binding_by_device_id(device_id: u64) -> Option<HostedDeviceBinding> {
    bindings()
        .iter()
        .copied()
        .find(|binding| binding.device_id == device_id)
}
unsafe fn retained_hosted_device_resource_state(
    binding: HostedDeviceBinding,
) -> Result<HostedDeviceResourceState, nt_status::NtStatus> {
    states()
        .iter()
        .copied()
        .find(|(owner, _)| *owner == binding)
        .map(|(_, state)| state)
        .ok_or(nt_status::NtStatus::INVALID_HANDLE)
}
fn hosted_pnp_context_lease_is_live(lease: u64) -> bool {
    leases().contains(&lease)
}
fn validate_physical_interrupt_claim(claim: u64) -> Result<Physical, nt_status::NtStatus> {
    claims()
        .iter()
        .copied()
        .find(|(id, _)| *id == claim)
        .map(|(_, physical)| physical)
        .ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)
}
fn hosted_interrupt_resource_id(device_id: u64) -> Option<u64> {
    device_id.checked_add(1000)
}
fn hosted_resource_owner(binding: HostedDeviceBinding) -> u64 {
    binding.device_id
}

struct ResourceManager;
static mut RESOURCE_MANAGER: ResourceManager = ResourceManager;
unsafe fn hosted_resource_manager_mut() -> &'static mut ResourceManager {
    &mut *std::ptr::addr_of_mut!(RESOURCE_MANAGER)
}
impl ResourceManager {
    fn query_resources(&mut self, owner: u64) -> Vec<Resource> {
        resources()
            .iter()
            .filter(|(id, _)| *id == owner)
            .map(|(_, resource)| *resource)
            .collect()
    }
}

#[path = "../../../components/ntos-executive/src/hosted_interrupt_grant.rs"]
mod native;

const DOMAIN: Domain = Domain {
    domain_id: DomainId(21),
    cookie: 9,
};
fn binding(device_id: u64, vector: u32, domain: Domain) -> HostedDeviceBinding {
    HostedDeviceBinding {
        used: true,
        driver_id: 7,
        instance: 4,
        projection_instance: 4,
        projection_domain: domain,
        device_id,
        pdo_object: 0x300 + u64::from(vector),
    }
}
fn publish(device_id: u64, vector: u32, domain: Domain) -> HostedDeviceBinding {
    let binding = binding(device_id, vector, domain);
    let lease = 200 + device_id;
    let claim = 300 + device_id;
    let line = if vector == 11 { 1 } else { 12 };
    let state = HostedDeviceResourceState {
        pnp_context_lease: Some(lease),
        interrupt_claim: Some(claim),
        evidence: Evidence {
            interrupt_vector: vector,
        },
        interrupt_line: line,
        interrupt_irql: 5,
        interrupt_affinity: 1,
        interrupt_shared: true,
        interrupt_latched: false,
        interrupt_active_low: false,
    };
    bindings().push(binding);
    states().push((binding, state));
    leases().push(lease);
    claims().push((
        claim,
        Physical {
            gsi: line,
            vector,
            level_sensitive: true,
            active_low: false,
            shared: true,
        },
    ));
    resources().push((
        device_id,
        Resource {
            kind: nt_hal_abi::RES_KIND_INTERRUPT,
            share: nt_hal_abi::SHARE_SHARED,
            resource_id: hosted_interrupt_resource_id(device_id).unwrap(),
            raw_start: line as u64,
            translated_start: vector as u64,
            vector,
            irql: 5,
            affinity: 1,
            mode: nt_hal_abi::INT_MODE_LEVEL_SENSITIVE,
        },
    ));
    unsafe {
        SHARED_BANK_VECTOR = vector;
    }
    binding
}
fn reset() {
    unsafe {
        BINDINGS = Some(Vec::new());
        STATES = Some(Vec::new());
        LEASES = Some(Vec::new());
        CLAIMS = Some(Vec::new());
        RESOURCES = Some(Vec::new());
        SHARED_BANK_VECTOR = 0;
    }
}

#[test]
fn stale_sibling_bank_cannot_override_exact_root_assignment() {
    let _serial = TEST_LOCK.lock().unwrap();
    reset();
    let keyboard = publish(11, 11, DOMAIN);
    let mouse = publish(12, 12, DOMAIN);
    assert_eq!(
        unsafe { SHARED_BANK_VECTOR },
        12,
        "mouse grant must overwrite the mutable bank before keyboard connects"
    );
    let (selected, state) = unsafe { native::select_hosted_interrupt_grant(mouse, 11, 0) }.unwrap();
    assert_eq!(selected, keyboard);
    assert_eq!(state.evidence.interrupt_vector, 11);
    assert_eq!(
        unsafe { SHARED_BANK_VECTOR },
        12,
        "root selection must not mutate the later sibling's bank"
    );
    assert_eq!(
        unsafe { native::select_hosted_interrupt_grant(mouse, 12, 0) }
            .unwrap()
            .0,
        mouse
    );
    assert_eq!(
        unsafe { native::select_hosted_interrupt_grant(mouse, 0, keyboard.pdo_object) }
            .unwrap()
            .0,
        keyboard
    );
}

#[test]
fn stale_lease_claim_or_assignment_cannot_authorize_sibling() {
    let _serial = TEST_LOCK.lock().unwrap();
    reset();
    let keyboard = publish(11, 11, DOMAIN);
    let mouse = publish(12, 12, DOMAIN);
    let request = || unsafe { native::select_hosted_interrupt_grant(mouse, 11, 0) };
    assert_eq!(request().unwrap().0, keyboard);
    leases().retain(|lease| *lease != 211);
    assert_eq!(
        request().unwrap_err(),
        nt_status::NtStatus::INVALID_DEVICE_REQUEST
    );
    leases().push(211);
    claims()
        .iter_mut()
        .find(|(id, _)| *id == 311)
        .unwrap()
        .1
        .vector = 12;
    assert_eq!(
        request().unwrap_err(),
        nt_status::NtStatus::INVALID_DEVICE_REQUEST
    );
    claims()
        .iter_mut()
        .find(|(id, _)| *id == 311)
        .unwrap()
        .1
        .vector = 11;
    resources()
        .iter_mut()
        .find(|(id, _)| *id == 11)
        .unwrap()
        .1
        .translated_start = 12;
    assert_eq!(
        request().unwrap_err(),
        nt_status::NtStatus::INVALID_DEVICE_REQUEST
    );
}

#[test]
fn foreign_domain_and_ambiguous_grants_are_refused() {
    let _serial = TEST_LOCK.lock().unwrap();
    reset();
    let active = publish(12, 12, DOMAIN);
    let foreign = Domain {
        cookie: 10,
        ..DOMAIN
    };
    publish(11, 11, foreign);
    assert_eq!(
        unsafe { native::select_hosted_interrupt_grant(active, 11, 0) }.unwrap_err(),
        nt_status::NtStatus::INVALID_DEVICE_REQUEST
    );
    publish(13, 11, DOMAIN);
    assert_eq!(
        unsafe { native::select_hosted_interrupt_grant(active, 11, 0) }
            .unwrap()
            .0
            .device_id,
        13
    );
    publish(14, 11, DOMAIN);
    assert_eq!(
        unsafe { native::select_hosted_interrupt_grant(active, 11, 0) }.unwrap_err(),
        nt_status::NtStatus::INVALID_DEVICE_REQUEST
    );
}
