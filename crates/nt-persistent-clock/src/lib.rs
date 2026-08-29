//! Device-neutral persistent-clock ownership and a capability-backed PC RTC provider.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

const RTC_SECONDS: u8 = 0x00;
const RTC_MINUTES: u8 = 0x02;
const RTC_HOURS: u8 = 0x04;
const RTC_WEEKDAY: u8 = 0x06;
const RTC_DAY: u8 = 0x07;
const RTC_MONTH: u8 = 0x08;
const RTC_YEAR: u8 = 0x09;
const RTC_STATUS_A: u8 = 0x0a;
const RTC_STATUS_B: u8 = 0x0b;
const RTC_STATUS_D: u8 = 0x0d;
const RTC_UPDATE_IN_PROGRESS: u8 = 1 << 7;
const RTC_SET: u8 = 1 << 7;
const RTC_24_HOUR: u8 = 1 << 1;
const RTC_BINARY: u8 = 1 << 2;
const RTC_VALID: u8 = 1 << 7;
const CMOS_NMI_DISABLE: u8 = 1 << 7;
const MAX_UPDATE_POLLS: usize = 128;
const MAX_STABLE_READS: usize = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderIdentity {
    pub id: u64,
    pub cookie: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PcCmosProvider {
    pub io_capability: u64,
    pub index_port: u16,
    pub data_port: u16,
    pub century_register: Option<u8>,
    pub year_hint: i32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderDescriptor {
    PcCmos(PcCmosProvider),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryError {
    InvalidProvider,
    DuplicateProvider,
    UnknownProvider,
    IdentityExhausted,
    OutOfMemory,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockError {
    NoProvider,
    Transport,
    InvalidClock,
    UpdateInProgress,
    UnstableRead,
    TimeOutOfRange,
}

pub trait PortIo {
    fn read8(&mut self, capability: u64, port: u16) -> Result<u8, ()>;
    fn write8(&mut self, capability: u64, port: u16, value: u8) -> Result<(), ()>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProviderRecord {
    identity: ProviderIdentity,
    descriptor: ProviderDescriptor,
}

#[derive(Debug, Default)]
pub struct ClockProviderRegistry {
    providers: Vec<ProviderRecord>,
    active: Option<ProviderIdentity>,
    next_id: u64,
    next_cookie: u64,
}

impl ClockProviderRegistry {
    pub const fn new() -> Self {
        Self {
            providers: Vec::new(),
            active: None,
            next_id: 1,
            next_cookie: 1,
        }
    }

    pub fn register(
        &mut self,
        descriptor: ProviderDescriptor,
    ) -> Result<ProviderIdentity, RegistryError> {
        validate_descriptor(descriptor)?;
        if self
            .providers
            .iter()
            .any(|record| same_provider(record.descriptor, descriptor))
        {
            return Err(RegistryError::DuplicateProvider);
        }
        self.providers
            .try_reserve(1)
            .map_err(|_| RegistryError::OutOfMemory)?;
        let identity = self.allocate_identity()?;
        self.providers.push(ProviderRecord {
            identity,
            descriptor,
        });
        if self.active.is_none() {
            self.active = Some(identity);
        }
        Ok(identity)
    }

    pub fn activate(&mut self, identity: ProviderIdentity) -> Result<(), RegistryError> {
        self.record(identity)
            .ok_or(RegistryError::UnknownProvider)?;
        self.active = Some(identity);
        Ok(())
    }

    pub fn unregister(&mut self, identity: ProviderIdentity) -> Result<(), RegistryError> {
        let index = self
            .providers
            .iter()
            .position(|record| record.identity == identity)
            .ok_or(RegistryError::UnknownProvider)?;
        self.providers.remove(index);
        if self.active == Some(identity) {
            self.active = None;
        }
        Ok(())
    }

    pub fn active(&self) -> Option<ProviderIdentity> {
        self.active
    }

    pub fn provider_count(&self) -> usize {
        self.providers.len()
    }

    pub fn probe_active<T: PortIo>(&mut self, io: &mut T) -> Result<u64, ClockError> {
        let time = self.read_active(io)?;
        Ok(time)
    }

    pub fn read_active<T: PortIo>(&mut self, io: &mut T) -> Result<u64, ClockError> {
        let identity = self.active.ok_or(ClockError::NoProvider)?;
        let descriptor = self
            .record(identity)
            .ok_or(ClockError::NoProvider)?
            .descriptor;
        let (time, year) = match descriptor {
            ProviderDescriptor::PcCmos(provider) => read_pc_cmos(io, provider)?,
        };
        if let Some(record) = self.record_mut(identity) {
            match &mut record.descriptor {
                ProviderDescriptor::PcCmos(provider) => provider.year_hint = year,
            }
        }
        Ok(time)
    }

    pub fn write_active<T: PortIo>(
        &mut self,
        io: &mut T,
        time_100ns: u64,
    ) -> Result<(), ClockError> {
        let identity = self.active.ok_or(ClockError::NoProvider)?;
        let descriptor = self
            .record(identity)
            .ok_or(ClockError::NoProvider)?
            .descriptor;
        let year = match descriptor {
            ProviderDescriptor::PcCmos(provider) => write_pc_cmos(io, provider, time_100ns)?,
        };
        if let Some(record) = self.record_mut(identity) {
            match &mut record.descriptor {
                ProviderDescriptor::PcCmos(provider) => provider.year_hint = year,
            }
        }
        Ok(())
    }

    fn record(&self, identity: ProviderIdentity) -> Option<&ProviderRecord> {
        self.providers
            .iter()
            .find(|record| record.identity == identity)
    }

    fn record_mut(&mut self, identity: ProviderIdentity) -> Option<&mut ProviderRecord> {
        self.providers
            .iter_mut()
            .find(|record| record.identity == identity)
    }

    fn allocate_identity(&mut self) -> Result<ProviderIdentity, RegistryError> {
        if self.next_id == 0 || self.next_cookie == 0 {
            return Err(RegistryError::IdentityExhausted);
        }
        let identity = ProviderIdentity {
            id: self.next_id,
            cookie: self.next_cookie,
        };
        self.next_id = self.next_id.checked_add(1).unwrap_or(0);
        self.next_cookie = self.next_cookie.checked_add(1).unwrap_or(0);
        Ok(identity)
    }
}

fn same_provider(left: ProviderDescriptor, right: ProviderDescriptor) -> bool {
    match (left, right) {
        (ProviderDescriptor::PcCmos(left), ProviderDescriptor::PcCmos(right)) => {
            left.io_capability == right.io_capability
                && left.index_port == right.index_port
                && left.data_port == right.data_port
                && left.century_register == right.century_register
        }
    }
}

fn validate_descriptor(descriptor: ProviderDescriptor) -> Result<(), RegistryError> {
    match descriptor {
        ProviderDescriptor::PcCmos(provider) => {
            if provider.io_capability == 0
                || provider.index_port == provider.data_port
                || !(1601..=9999).contains(&provider.year_hint)
                || provider
                    .century_register
                    .is_some_and(|register| register > 0x7f || is_standard_rtc_register(register))
            {
                return Err(RegistryError::InvalidProvider);
            }
        }
    }
    Ok(())
}

fn is_standard_rtc_register(register: u8) -> bool {
    matches!(
        register,
        RTC_SECONDS
            | RTC_MINUTES
            | RTC_HOURS
            | RTC_WEEKDAY
            | RTC_DAY
            | RTC_MONTH
            | RTC_YEAR
            | RTC_STATUS_A
            | RTC_STATUS_B
            | RTC_STATUS_D
    )
}

fn cmos_read<T: PortIo>(
    io: &mut T,
    provider: PcCmosProvider,
    register: u8,
) -> Result<u8, ClockError> {
    io.write8(
        provider.io_capability,
        provider.index_port,
        register | CMOS_NMI_DISABLE,
    )
    .map_err(|_| ClockError::Transport)?;
    io.read8(provider.io_capability, provider.data_port)
        .map_err(|_| ClockError::Transport)
}

fn cmos_write<T: PortIo>(
    io: &mut T,
    provider: PcCmosProvider,
    register: u8,
    value: u8,
) -> Result<(), ClockError> {
    io.write8(
        provider.io_capability,
        provider.index_port,
        register | CMOS_NMI_DISABLE,
    )
    .map_err(|_| ClockError::Transport)?;
    io.write8(provider.io_capability, provider.data_port, value)
        .map_err(|_| ClockError::Transport)
}

fn finish_cmos<T: PortIo>(io: &mut T, provider: PcCmosProvider) -> Result<(), ClockError> {
    io.write8(provider.io_capability, provider.index_port, 0)
        .map_err(|_| ClockError::Transport)
}

fn wait_for_update<T: PortIo>(io: &mut T, provider: PcCmosProvider) -> Result<(), ClockError> {
    for _ in 0..MAX_UPDATE_POLLS {
        if cmos_read(io, provider, RTC_STATUS_A)? & RTC_UPDATE_IN_PROGRESS == 0 {
            return Ok(());
        }
    }
    Err(ClockError::UpdateInProgress)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RawRtcTime {
    second: u8,
    minute: u8,
    hour: u8,
    day: u8,
    month: u8,
    year: u8,
    century: Option<u8>,
}

fn read_raw<T: PortIo>(io: &mut T, provider: PcCmosProvider) -> Result<RawRtcTime, ClockError> {
    Ok(RawRtcTime {
        second: cmos_read(io, provider, RTC_SECONDS)?,
        minute: cmos_read(io, provider, RTC_MINUTES)?,
        hour: cmos_read(io, provider, RTC_HOURS)?,
        day: cmos_read(io, provider, RTC_DAY)?,
        month: cmos_read(io, provider, RTC_MONTH)?,
        year: cmos_read(io, provider, RTC_YEAR)?,
        century: match provider.century_register {
            Some(register) => Some(cmos_read(io, provider, register)?),
            None => None,
        },
    })
}

fn read_pc_cmos<T: PortIo>(io: &mut T, provider: PcCmosProvider) -> Result<(u64, i32), ClockError> {
    let result = (|| {
        if cmos_read(io, provider, RTC_STATUS_D)? & RTC_VALID == 0 {
            return Err(ClockError::InvalidClock);
        }
        wait_for_update(io, provider)?;
        let status_b = cmos_read(io, provider, RTC_STATUS_B)?;
        for _ in 0..MAX_STABLE_READS {
            let first = read_raw(io, provider)?;
            if cmos_read(io, provider, RTC_STATUS_A)? & RTC_UPDATE_IN_PROGRESS != 0 {
                wait_for_update(io, provider)?;
                continue;
            }
            let second = read_raw(io, provider)?;
            if first == second {
                let value = decode_raw(first, status_b, provider.year_hint)?;
                let time = nt_time::system_time_from_utc_date_time(value)
                    .map_err(|_| ClockError::TimeOutOfRange)?;
                return Ok((time, value.year));
            }
        }
        Err(ClockError::UnstableRead)
    })();
    let finish = finish_cmos(io, provider);
    match (result, finish) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Ok(value), Ok(())) => Ok(value),
    }
}

fn write_pc_cmos<T: PortIo>(
    io: &mut T,
    provider: PcCmosProvider,
    time_100ns: u64,
) -> Result<i32, ClockError> {
    let value = nt_time::utc_date_time_from_system_time(time_100ns)
        .map_err(|_| ClockError::TimeOutOfRange)?;
    let result = (|| {
        if cmos_read(io, provider, RTC_STATUS_D)? & RTC_VALID == 0 {
            return Err(ClockError::InvalidClock);
        }
        wait_for_update(io, provider)?;
        let status_b = cmos_read(io, provider, RTC_STATUS_B)?;
        cmos_write(io, provider, RTC_STATUS_B, status_b | RTC_SET)?;
        let binary = status_b & RTC_BINARY != 0;
        let hour = encode_hour(value.hour, binary, status_b & RTC_24_HOUR != 0);
        let writes = [
            (RTC_SECONDS, encode(value.second, binary)),
            (RTC_MINUTES, encode(value.minute, binary)),
            (RTC_HOURS, hour),
            (RTC_WEEKDAY, encode(value.weekday + 1, binary)),
            (RTC_DAY, encode(value.day, binary)),
            (RTC_MONTH, encode(value.month, binary)),
            (RTC_YEAR, encode((value.year % 100) as u8, binary)),
        ];
        let mut write_result = Ok(());
        for (register, encoded) in writes {
            if let Err(error) = cmos_write(io, provider, register, encoded) {
                write_result = Err(error);
                break;
            }
        }
        if write_result.is_ok() {
            if let Some(register) = provider.century_register {
                write_result = cmos_write(
                    io,
                    provider,
                    register,
                    encode((value.year / 100) as u8, binary),
                );
            }
        }
        let restore_result = cmos_write(io, provider, RTC_STATUS_B, status_b & !RTC_SET);
        write_result.and(restore_result)?;
        Ok(value.year)
    })();
    let finish = finish_cmos(io, provider);
    match (result, finish) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Ok(value), Ok(())) => Ok(value),
    }
}

fn decode_raw(
    raw: RawRtcTime,
    status_b: u8,
    year_hint: i32,
) -> Result<nt_time::UtcDateTime, ClockError> {
    let binary = status_b & RTC_BINARY != 0;
    let second = decode(raw.second, binary)?;
    let minute = decode(raw.minute, binary)?;
    let hour = decode_hour(raw.hour, binary, status_b & RTC_24_HOUR != 0)?;
    let day = decode(raw.day, binary)?;
    let month = decode(raw.month, binary)?;
    let low_year = i32::from(decode(raw.year, binary)?);
    let year = match raw.century {
        Some(raw_century) => i32::from(decode(raw_century, binary)?) * 100 + low_year,
        None => expand_year(low_year, year_hint),
    };
    let candidate = nt_time::UtcDateTime {
        year,
        month,
        day,
        hour,
        minute,
        second,
        weekday: 0,
    };
    let time =
        nt_time::system_time_from_utc_date_time(candidate).map_err(|_| ClockError::InvalidClock)?;
    nt_time::utc_date_time_from_system_time(time).map_err(|_| ClockError::InvalidClock)
}

fn expand_year(low_year: i32, year_hint: i32) -> i32 {
    let mut year = year_hint.div_euclid(100) * 100 + low_year;
    if year - year_hint > 50 {
        year -= 100;
    } else if year_hint - year > 50 {
        year += 100;
    }
    year
}

fn decode(value: u8, binary: bool) -> Result<u8, ClockError> {
    if binary {
        return Ok(value);
    }
    let high = value >> 4;
    let low = value & 0x0f;
    if high > 9 || low > 9 {
        return Err(ClockError::InvalidClock);
    }
    Ok(high * 10 + low)
}

fn encode(value: u8, binary: bool) -> u8 {
    if binary {
        value
    } else {
        (value / 10) << 4 | value % 10
    }
}

fn decode_hour(raw: u8, binary: bool, twenty_four_hour: bool) -> Result<u8, ClockError> {
    if twenty_four_hour {
        return decode(raw, binary);
    }
    let pm = raw & 0x80 != 0;
    let hour = decode(raw & 0x7f, binary)?;
    if !(1..=12).contains(&hour) {
        return Err(ClockError::InvalidClock);
    }
    Ok(match (hour, pm) {
        (12, false) => 0,
        (12, true) => 12,
        (_, true) => hour + 12,
        _ => hour,
    })
}

fn encode_hour(hour: u8, binary: bool, twenty_four_hour: bool) -> u8 {
    if twenty_four_hour {
        return encode(hour, binary);
    }
    let pm = hour >= 12;
    let twelve_hour = match hour % 12 {
        0 => 12,
        value => value,
    };
    encode(twelve_hour, binary) | if pm { 0x80 } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeIo {
        registers: [u8; 128],
        selected: u8,
        fail_capability: Option<u64>,
        last_capability: Option<u64>,
    }

    impl FakeIo {
        fn bcd_time() -> Self {
            let mut registers = [0; 128];
            registers[RTC_STATUS_B as usize] = RTC_24_HOUR;
            registers[RTC_STATUS_D as usize] = RTC_VALID;
            registers[RTC_SECONDS as usize] = 0x56;
            registers[RTC_MINUTES as usize] = 0x34;
            registers[RTC_HOURS as usize] = 0x12;
            registers[RTC_DAY as usize] = 0x29;
            registers[RTC_MONTH as usize] = 0x02;
            registers[RTC_YEAR as usize] = 0x24;
            registers[0x32] = 0x20;
            Self {
                registers,
                selected: 0,
                fail_capability: None,
                last_capability: None,
            }
        }
    }

    impl PortIo for FakeIo {
        fn read8(&mut self, capability: u64, port: u16) -> Result<u8, ()> {
            self.last_capability = Some(capability);
            if self.fail_capability == Some(capability) || port != 0x71 {
                return Err(());
            }
            Ok(self.registers[self.selected as usize])
        }

        fn write8(&mut self, capability: u64, port: u16, value: u8) -> Result<(), ()> {
            self.last_capability = Some(capability);
            if self.fail_capability == Some(capability) {
                return Err(());
            }
            match port {
                0x70 => self.selected = value & 0x7f,
                0x71 => self.registers[self.selected as usize] = value,
                _ => return Err(()),
            }
            Ok(())
        }
    }

    fn provider(century_register: Option<u8>) -> ProviderDescriptor {
        ProviderDescriptor::PcCmos(PcCmosProvider {
            io_capability: 44,
            index_port: 0x70,
            data_port: 0x71,
            century_register,
            year_hint: 2026,
        })
    }

    #[test]
    fn registry_requires_explicit_replacement_after_active_removal() {
        let mut registry = ClockProviderRegistry::new();
        let first = registry.register(provider(Some(0x32))).unwrap();
        let mut duplicate = match provider(Some(0x32)) {
            ProviderDescriptor::PcCmos(value) => value,
        };
        duplicate.year_hint = 2030;
        assert_eq!(
            registry.register(ProviderDescriptor::PcCmos(duplicate)),
            Err(RegistryError::DuplicateProvider)
        );
        let second = registry
            .register(ProviderDescriptor::PcCmos(PcCmosProvider {
                io_capability: 45,
                ..match provider(None) {
                    ProviderDescriptor::PcCmos(value) => value,
                }
            }))
            .unwrap();
        assert_eq!(registry.active(), Some(first));
        registry.unregister(first).unwrap();
        assert_eq!(registry.active(), None);
        registry.activate(second).unwrap();
        assert_eq!(registry.active(), Some(second));

        let mut exhausted = ClockProviderRegistry::new();
        exhausted.next_id = 0;
        assert_eq!(
            exhausted.register(provider(None)),
            Err(RegistryError::IdentityExhausted)
        );
    }

    #[test]
    fn reads_bcd_24_hour_clock_with_century() {
        let mut registry = ClockProviderRegistry::new();
        registry.register(provider(Some(0x32))).unwrap();
        let mut io = FakeIo::bcd_time();
        let time = registry.read_active(&mut io).unwrap();
        assert_eq!(
            nt_time::utc_date_time_from_system_time(time).unwrap(),
            nt_time::UtcDateTime {
                year: 2024,
                month: 2,
                day: 29,
                hour: 12,
                minute: 34,
                second: 56,
                weekday: 4,
            }
        );
    }

    #[test]
    fn reads_binary_twelve_hour_clock_using_year_hint() {
        let mut registry = ClockProviderRegistry::new();
        registry.register(provider(None)).unwrap();
        let mut io = FakeIo::bcd_time();
        io.registers[RTC_STATUS_B as usize] = RTC_BINARY;
        io.registers[RTC_SECONDS as usize] = 1;
        io.registers[RTC_MINUTES as usize] = 2;
        io.registers[RTC_HOURS as usize] = 0x80 | 11;
        io.registers[RTC_DAY as usize] = 31;
        io.registers[RTC_MONTH as usize] = 12;
        io.registers[RTC_YEAR as usize] = 99;
        let time = registry.read_active(&mut io).unwrap();
        let value = nt_time::utc_date_time_from_system_time(time).unwrap();
        assert_eq!((value.year, value.hour), (1999, 23));
    }

    #[test]
    fn writes_and_reads_back_in_the_existing_rtc_format() {
        let mut registry = ClockProviderRegistry::new();
        registry.register(provider(Some(0x32))).unwrap();
        let mut io = FakeIo::bcd_time();
        let value = nt_time::UtcDateTime {
            year: 2032,
            month: 7,
            day: 8,
            hour: 19,
            minute: 6,
            second: 5,
            weekday: 4,
        };
        let time = nt_time::system_time_from_utc_date_time(value).unwrap();
        registry.write_active(&mut io, time).unwrap();
        assert_eq!(io.registers[RTC_STATUS_B as usize] & RTC_SET, 0);
        assert_eq!(registry.read_active(&mut io).unwrap(), time);
    }

    #[test]
    fn transport_and_invalid_hardware_fail_without_an_alternate_provider_retry() {
        let mut registry = ClockProviderRegistry::new();
        registry.register(provider(Some(0x32))).unwrap();
        registry
            .register(ProviderDescriptor::PcCmos(PcCmosProvider {
                io_capability: 45,
                ..match provider(None) {
                    ProviderDescriptor::PcCmos(value) => value,
                }
            }))
            .unwrap();
        let mut io = FakeIo::bcd_time();
        io.fail_capability = Some(44);
        assert_eq!(registry.read_active(&mut io), Err(ClockError::Transport));
        assert_eq!(io.last_capability, Some(44));
        io.fail_capability = None;
        io.registers[RTC_STATUS_D as usize] = 0;
        assert_eq!(registry.read_active(&mut io), Err(ClockError::InvalidClock));
        assert_eq!(io.last_capability, Some(44));
    }
}
