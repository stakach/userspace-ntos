//! I/O-Manager-facing helpers: `Driver`, `Device`, and `File` objects (spec
//! §18.1, §22 M8). The Object Manager owns their canonical identity, name, type,
//! and lifetime; the I/O Manager owns the real object internals, reached through
//! the body's `owner`/`owner_local_id` routing (spec §13.2). These are the
//! primitives an `IoCreateDevice` / `IoCreateSymbolicLink` MVP builds on.

use nt_status::NtStatus;
use nt_types::rights;
use nt_types::{AccessMask, GenericMapping, ObjectId, ObjectTypeId, UnicodeString};

use crate::store::ObjectRef;
use crate::types::{ComponentId, DeviceBody, DriverBody, FileBody, ObjectBody, ObjectTypeDef};
use crate::ObjectManager;

const DRIVER_TYPE_NAME: &str = "Driver";
const DEVICE_TYPE_NAME: &str = "Device";
const FILE_TYPE_NAME: &str = "File";

impl ObjectManager {
    fn ensure_driver_type(&mut self) -> Result<ObjectTypeId, NtStatus> {
        if let Some(id) = self.driver_type {
            return Ok(id);
        }
        let id = self.register_type(ObjectTypeDef {
            name: DRIVER_TYPE_NAME,
            valid_access: rights::driver::ALL_ACCESS,
            generic_mapping: GenericMapping {
                generic_read: AccessMask::STANDARD_RIGHTS_READ,
                generic_write: AccessMask::STANDARD_RIGHTS_WRITE,
                generic_execute: AccessMask::STANDARD_RIGHTS_EXECUTE,
                generic_all: rights::driver::ALL_ACCESS,
            },
            delete: None,
        })?;
        self.driver_type = Some(id);
        Ok(id)
    }

    fn ensure_device_type(&mut self) -> Result<ObjectTypeId, NtStatus> {
        if let Some(id) = self.device_type {
            return Ok(id);
        }
        use rights::device as dev;
        let id = self.register_type(ObjectTypeDef {
            name: DEVICE_TYPE_NAME,
            valid_access: dev::ALL_ACCESS,
            generic_mapping: GenericMapping {
                generic_read: AccessMask::STANDARD_RIGHTS_READ
                    | AccessMask::SYNCHRONIZE
                    | dev::READ,
                generic_write: AccessMask::STANDARD_RIGHTS_WRITE
                    | AccessMask::SYNCHRONIZE
                    | dev::WRITE,
                generic_execute: AccessMask::STANDARD_RIGHTS_EXECUTE
                    | AccessMask::SYNCHRONIZE
                    | dev::EXECUTE,
                generic_all: dev::ALL_ACCESS,
            },
            delete: None,
        })?;
        self.device_type = Some(id);
        Ok(id)
    }

    fn ensure_file_type(&mut self) -> Result<ObjectTypeId, NtStatus> {
        if let Some(id) = self.file_type {
            return Ok(id);
        }
        use rights::file as f;
        let id = self.register_type(ObjectTypeDef {
            name: FILE_TYPE_NAME,
            valid_access: f::ALL_ACCESS,
            generic_mapping: GenericMapping {
                generic_read: AccessMask::STANDARD_RIGHTS_READ
                    | AccessMask::SYNCHRONIZE
                    | f::READ_DATA,
                generic_write: AccessMask::STANDARD_RIGHTS_WRITE
                    | AccessMask::SYNCHRONIZE
                    | f::WRITE_DATA,
                generic_execute: AccessMask::STANDARD_RIGHTS_EXECUTE | AccessMask::SYNCHRONIZE,
                generic_all: f::ALL_ACCESS,
            },
            delete: None,
        })?;
        self.file_type = Some(id);
        Ok(id)
    }

    /// The Driver / Device / File type ids (once first created).
    pub fn driver_type(&self) -> Option<ObjectTypeId> {
        self.driver_type
    }
    pub fn device_type(&self) -> Option<ObjectTypeId> {
        self.device_type
    }
    pub fn file_type(&self) -> Option<ObjectTypeId> {
        self.file_type
    }

    /// Create a driver object named `name` inside `parent` (typically `\Driver`),
    /// owned by `owner`. `IoCreateDriver`-style primitive.
    pub fn create_driver(
        &mut self,
        parent: &ObjectRef,
        name: &UnicodeString,
        owner: ComponentId,
        owner_local_id: u64,
        permanent: bool,
    ) -> Result<ObjectRef, NtStatus> {
        let ty = self.ensure_driver_type()?;
        self.create_named_object(
            ty,
            ObjectBody::Driver(DriverBody {
                owner,
                owner_local_id,
            }),
            parent,
            name,
            permanent,
        )
    }

    /// Create a device object named `name` inside `parent` (typically `\Device`),
    /// owned by `owner`. `IoCreateDevice`-style primitive.
    pub fn create_device(
        &mut self,
        parent: &ObjectRef,
        name: &UnicodeString,
        owner: ComponentId,
        owner_local_id: u64,
        permanent: bool,
    ) -> Result<ObjectRef, NtStatus> {
        let ty = self.ensure_device_type()?;
        self.create_named_object(
            ty,
            ObjectBody::Device(DeviceBody {
                owner,
                owner_local_id,
            }),
            parent,
            name,
            permanent,
        )
    }

    /// Create an (unnamed) file object targeting `device`, owned by `owner`.
    pub fn create_file(
        &mut self,
        owner: ComponentId,
        owner_local_id: u64,
        device: ObjectId,
    ) -> Result<ObjectRef, NtStatus> {
        let ty = self.ensure_file_type()?;
        self.create_object(
            ty,
            ObjectBody::File(FileBody {
                owner,
                owner_local_id,
                device,
            }),
        )
    }
}
