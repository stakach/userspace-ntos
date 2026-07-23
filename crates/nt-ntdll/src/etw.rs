//! Host-tested ETW provider registration and disabled-session semantics.

pub const ERROR_SUCCESS: u32 = 0;
pub const ERROR_INVALID_HANDLE: u32 = 6;
pub const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
pub const ERROR_INVALID_PARAMETER: u32 = 87;
pub const MAX_EVENT_DATA_DESCRIPTORS: u32 = 128;

pub const EVENT_ACTIVITY_CTRL_GET_ID: u32 = 1;
pub const EVENT_ACTIVITY_CTRL_SET_ID: u32 = 2;
pub const EVENT_ACTIVITY_CTRL_CREATE_ID: u32 = 3;
pub const EVENT_ACTIVITY_CTRL_GET_SET_ID: u32 = 4;
pub const EVENT_ACTIVITY_CTRL_CREATE_SET_ID: u32 = 5;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EventDescriptor {
    pub id: u16,
    pub version: u8,
    pub channel: u8,
    pub level: u8,
    pub opcode: u8,
    pub task: u16,
    pub keyword: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EventDataDescriptor {
    pub ptr: u64,
    pub size: u32,
    pub reserved: u32,
}

const _: () = assert!(core::mem::size_of::<Guid>() == 16);
const _: () = assert!(core::mem::size_of::<EventDescriptor>() == 16);
const _: () = assert!(core::mem::size_of::<EventDataDescriptor>() == 16);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ActivityState {
    pub current: Guid,
}

pub fn control_activity_id(
    state: &mut ActivityState,
    control: u32,
    id: &mut Guid,
    generated: Guid,
) -> u32 {
    match control {
        EVENT_ACTIVITY_CTRL_GET_ID => *id = state.current,
        EVENT_ACTIVITY_CTRL_SET_ID => state.current = *id,
        EVENT_ACTIVITY_CTRL_CREATE_ID => *id = generated,
        EVENT_ACTIVITY_CTRL_GET_SET_ID => core::mem::swap(&mut state.current, id),
        EVENT_ACTIVITY_CTRL_CREATE_SET_ID => {
            state.current = generated;
            *id = generated;
        }
        _ => return ERROR_INVALID_PARAMETER,
    }
    ERROR_SUCCESS
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ProviderSlot {
    active: bool,
    generation: u32,
    provider: Guid,
    callback: usize,
    context: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderRegistry<const N: usize> {
    slots: [ProviderSlot; N],
}

impl<const N: usize> ProviderRegistry<N> {
    pub const fn new() -> Self {
        Self {
            slots: [ProviderSlot {
                active: false,
                generation: 0,
                provider: Guid {
                    data1: 0,
                    data2: 0,
                    data3: 0,
                    data4: [0; 8],
                },
                callback: 0,
                context: 0,
            }; N],
        }
    }

    pub fn register(
        &mut self,
        provider: Guid,
        callback: usize,
        context: usize,
    ) -> Result<u64, u32> {
        let Some((index, slot)) = self
            .slots
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| !slot.active)
        else {
            return Err(ERROR_NOT_ENOUGH_MEMORY);
        };
        slot.generation = slot.generation.wrapping_add(1).max(1);
        slot.active = true;
        slot.provider = provider;
        slot.callback = callback;
        slot.context = context;
        Ok(make_handle(index, slot.generation))
    }

    pub fn unregister(&mut self, handle: u64) -> u32 {
        let Some(index) = self.resolve(handle) else {
            return ERROR_INVALID_HANDLE;
        };
        self.slots[index].active = false;
        self.slots[index].provider = Guid::default();
        self.slots[index].callback = 0;
        self.slots[index].context = 0;
        ERROR_SUCCESS
    }

    pub fn contains(&self, handle: u64) -> bool {
        self.resolve(handle).is_some()
    }

    pub fn enabled(&self, handle: u64) -> bool {
        self.contains(handle) && false
    }

    fn resolve(&self, handle: u64) -> Option<usize> {
        let low = handle as u32;
        let generation = (handle >> 32) as u32;
        let index = usize::try_from(low.checked_sub(1)?).ok()?;
        let slot = self.slots.get(index)?;
        (slot.active && slot.generation == generation).then_some(index)
    }
}

impl<const N: usize> Default for ProviderRegistry<N> {
    fn default() -> Self {
        Self::new()
    }
}

fn make_handle(index: usize, generation: u32) -> u64 {
    (u64::from(generation) << 32) | (index as u64 + 1)
}

pub fn validate_event_write(
    registered: bool,
    descriptor_present: bool,
    data_count: u32,
    data_present: bool,
) -> u32 {
    if !registered {
        ERROR_INVALID_HANDLE
    } else if !descriptor_present
        || data_count > MAX_EVENT_DATA_DESCRIPTORS
        || (data_count != 0 && !data_present)
    {
        ERROR_INVALID_PARAMETER
    } else {
        ERROR_SUCCESS
    }
}

pub fn validate_unregistered_event_write(
    provider_present: bool,
    descriptor_present: bool,
    data_count: u32,
    data_present: bool,
) -> u32 {
    if !provider_present
        || !descriptor_present
        || data_count > MAX_EVENT_DATA_DESCRIPTORS
        || (data_count != 0 && !data_present)
    {
        ERROR_INVALID_PARAMETER
    } else {
        ERROR_SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guid(value: u32) -> Guid {
        Guid {
            data1: value,
            data2: value as u16,
            data3: !value as u16,
            data4: [value as u8; 8],
        }
    }

    #[test]
    fn provider_handles_are_nonzero_unique_and_generation_checked() {
        let mut registry = ProviderRegistry::<2>::new();
        let first = registry.register(guid(1), 0x1000, 0x2000).unwrap();
        let second = registry.register(guid(2), 0, 0).unwrap();
        assert_ne!(first, 0);
        assert_ne!(first, second);
        assert!(registry.contains(first));
        assert!(!registry.enabled(first));
        assert_eq!(
            registry.register(guid(3), 0, 0),
            Err(ERROR_NOT_ENOUGH_MEMORY)
        );
        assert_eq!(registry.unregister(first), ERROR_SUCCESS);
        assert_eq!(registry.unregister(first), ERROR_INVALID_HANDLE);
        let replacement = registry.register(guid(3), 0, 0).unwrap();
        assert_ne!(replacement, first);
        assert!(!registry.contains(first));
        assert!(registry.contains(replacement));
    }

    #[test]
    fn event_validation_rejects_invalid_handles_and_shapes() {
        assert_eq!(
            validate_event_write(false, true, 0, false),
            ERROR_INVALID_HANDLE
        );
        assert_eq!(
            validate_event_write(true, false, 0, false),
            ERROR_INVALID_PARAMETER
        );
        assert_eq!(
            validate_event_write(true, true, 129, true),
            ERROR_INVALID_PARAMETER
        );
        assert_eq!(
            validate_event_write(true, true, 1, false),
            ERROR_INVALID_PARAMETER
        );
        assert_eq!(validate_event_write(true, true, 128, true), ERROR_SUCCESS);
        assert_eq!(
            validate_unregistered_event_write(false, true, 0, false),
            ERROR_INVALID_PARAMETER
        );
    }

    #[test]
    fn activity_controls_get_set_create_and_swap() {
        let mut state = ActivityState { current: guid(1) };
        let mut id = Guid::default();
        assert_eq!(
            control_activity_id(&mut state, EVENT_ACTIVITY_CTRL_GET_ID, &mut id, guid(9)),
            ERROR_SUCCESS
        );
        assert_eq!(id, guid(1));
        id = guid(2);
        control_activity_id(&mut state, EVENT_ACTIVITY_CTRL_SET_ID, &mut id, guid(9));
        assert_eq!(state.current, guid(2));
        control_activity_id(&mut state, EVENT_ACTIVITY_CTRL_CREATE_ID, &mut id, guid(3));
        assert_eq!(id, guid(3));
        assert_eq!(state.current, guid(2));
        id = guid(4);
        control_activity_id(&mut state, EVENT_ACTIVITY_CTRL_GET_SET_ID, &mut id, guid(9));
        assert_eq!(id, guid(2));
        assert_eq!(state.current, guid(4));
        control_activity_id(
            &mut state,
            EVENT_ACTIVITY_CTRL_CREATE_SET_ID,
            &mut id,
            guid(5),
        );
        assert_eq!(id, guid(5));
        assert_eq!(state.current, guid(5));
        assert_eq!(
            control_activity_id(&mut state, 0, &mut id, guid(6)),
            ERROR_INVALID_PARAMETER
        );
    }
}
