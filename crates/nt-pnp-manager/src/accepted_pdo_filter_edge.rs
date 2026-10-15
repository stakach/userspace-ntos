//! One-use proof bridge for a function FDO's native FILTER forward to its accepted PDO.
//!
//! The accepted PDO provider has already executed for the original PDO-origin PnP
//! request. The nested FDO IRP is a separate canonical dispatch; this edge binds
//! it to that original request without invoking the accepted provider again.

use nt_io_manager::{
    retained_query_path_forward::SourceIrpTicket, HostedDevicePointerRegistration, IoManager, IrpId,
};
use nt_status::NtStatus;
use nt_types::ClientId;

use crate::{
    AcceptedPdoLowerFilterProof, AcceptedPdoPnpIdentity, AcceptedPdoProviderCatalog,
    BusRelationTable, PnpManager,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcceptedPdoFilterEdgeError {
    WrongOuter,
    WrongNested,
    WrongStack,
    WrongProvider,
    WrongSource,
    WrongProof,
    Consumed,
}

/// Retained by the native adapter from before lower-FDO entry through its source
/// completion acknowledgement. It contains canonical IDs and generation-bearing
/// device/provider authority; raw native pointers never establish parentage.
#[derive(Debug)]
#[must_use = "retain until the nested source completion has been acknowledged"]
pub struct AcceptedPdoFilterEdge {
    original: AcceptedPdoPnpIdentity,
    nested_irp: IrpId,
    fdo: HostedDevicePointerRegistration,
    pdo: HostedDevicePointerRegistration,
    class_source: SourceIrpTicket,
    client: ClientId,
    requestor_tid: u64,
    nested_source: Option<SourceIrpTicket>,
    consumed: bool,
}

impl AcceptedPdoFilterEdge {
    #[allow(clippy::too_many_arguments)]
    pub fn capture<P>(
        pnp: &PnpManager,
        relations: &BusRelationTable,
        providers: &AcceptedPdoProviderCatalog,
        io: &IoManager<P>,
        outer_irp: IrpId,
        nested_irp: IrpId,
        fdo: HostedDevicePointerRegistration,
        pdo: HostedDevicePointerRegistration,
        class_source: SourceIrpTicket,
        client: ClientId,
        requestor_tid: u64,
    ) -> Result<Self, AcceptedPdoFilterEdgeError> {
        if outer_irp == nested_irp || class_source.domain == fdo.domain() {
            return Err(AcceptedPdoFilterEdgeError::WrongSource);
        }
        let original = AcceptedPdoPnpIdentity {
            outer_irp,
            pdo: pdo.device_id(),
            minor: nt_pnp_abi::IRP_MN_FILTER_RESOURCE_REQUIREMENTS,
            provider: providers
                .resolve(pnp, relations, io, pdo.device_id().raw())
                .map_err(|_| AcceptedPdoFilterEdgeError::WrongProvider)?,
        };
        let edge = Self {
            original,
            nested_irp,
            fdo,
            pdo,
            class_source,
            client,
            requestor_tid,
            nested_source: None,
            consumed: false,
        };
        edge.validate_current(pnp, relations, providers, io)?;
        Ok(edge)
    }

    fn validate_current<P>(
        &self,
        pnp: &PnpManager,
        relations: &BusRelationTable,
        providers: &AcceptedPdoProviderCatalog,
        io: &IoManager<P>,
    ) -> Result<(), AcceptedPdoFilterEdgeError> {
        let original = io
            .irp(self.original.outer_irp)
            .ok_or(AcceptedPdoFilterEdgeError::WrongOuter)?;
        if original.client_id != self.client
            || original.file_id.is_some()
            || original.origin_major != nt_pnp_abi::IRP_MJ_PNP
            || original.origin_minor != nt_pnp_abi::IRP_MN_FILTER_RESOURCE_REQUIREMENTS
            || original.origin_device_id != self.pdo.device_id()
        {
            return Err(AcceptedPdoFilterEdgeError::WrongOuter);
        }
        let nested = io
            .irp(self.nested_irp)
            .ok_or(AcceptedPdoFilterEdgeError::WrongNested)?;
        if nested.client_id != self.client
            || nested.file_id.is_some()
            || nested.origin_major != nt_pnp_abi::IRP_MJ_PNP
            || nested.origin_minor != nt_pnp_abi::IRP_MN_FILTER_RESOURCE_REQUIREMENTS
            || nested.origin_device_id != self.fdo.device_id()
            || nested.requestor_tid != self.requestor_tid
            || nested.current_stack().map(|frame| frame.device_id) != Some(self.fdo.device_id())
        {
            return Err(AcceptedPdoFilterEdgeError::WrongNested);
        }
        if self.fdo.domain() != self.pdo.domain()
            || self.class_source.domain == self.fdo.domain()
            || io.hosted_device_pointer_registration(self.fdo.domain(), self.fdo.address())
                != Some(self.fdo)
            || io.hosted_device_pointer_registration(self.pdo.domain(), self.pdo.address())
                != Some(self.pdo)
            || io
                .device(self.fdo.device_id())
                .and_then(|device| device.attached_to)
                != Some(self.pdo.device_id())
            || pnp
                .devnode_for_pdo(self.pdo.device_id().raw())
                .and_then(|node| pnp.fdo(node))
                != Some(self.fdo.device_id().raw())
        {
            return Err(AcceptedPdoFilterEdgeError::WrongStack);
        }
        let provider = providers
            .resolve(pnp, relations, io, self.pdo.device_id().raw())
            .map_err(|_| AcceptedPdoFilterEdgeError::WrongProvider)?;
        if provider != self.original.provider || provider.provider().domain() == self.fdo.domain() {
            return Err(AcceptedPdoFilterEdgeError::WrongProvider);
        }
        Ok(())
    }

    pub const fn original_identity(&self) -> AcceptedPdoPnpIdentity {
        self.original
    }

    pub const fn nested_irp(&self) -> IrpId {
        self.nested_irp
    }

    /// Called after the native source ledger authenticates the nested IRP's
    /// physical allocation and generation at op3 ingress.
    pub fn bind_nested_source(
        &mut self,
        observed_irp: IrpId,
        source: SourceIrpTicket,
    ) -> Result<(), AcceptedPdoFilterEdgeError> {
        if observed_irp != self.nested_irp || source.domain != self.fdo.domain() {
            return Err(AcceptedPdoFilterEdgeError::WrongSource);
        }
        match self.nested_source {
            None => self.nested_source = Some(source),
            Some(current) if current == source => {}
            Some(_) => return Err(AcceptedPdoFilterEdgeError::WrongSource),
        }
        Ok(())
    }

    /// Consume only the original provider's exact one-use terminal proof. This
    /// method never enters the provider; a mismatch leaves proof ownership intact.
    #[allow(clippy::too_many_arguments)]
    pub fn consume_proof<P>(
        &mut self,
        pnp: &PnpManager,
        relations: &BusRelationTable,
        providers: &AcceptedPdoProviderCatalog,
        io: &IoManager<P>,
        observed_irp: IrpId,
        observed_source: SourceIrpTicket,
        proof: &mut AcceptedPdoLowerFilterProof,
    ) -> Result<NtStatus, AcceptedPdoFilterEdgeError> {
        if self.consumed {
            return Err(AcceptedPdoFilterEdgeError::Consumed);
        }
        if observed_irp != self.nested_irp || self.nested_source != Some(observed_source) {
            return Err(AcceptedPdoFilterEdgeError::WrongSource);
        }
        self.validate_current(pnp, relations, providers, io)?;
        let status = proof
            .take_for(self.original)
            .map_err(|_| AcceptedPdoFilterEdgeError::WrongProof)?;
        self.consumed = true;
        Ok(status)
    }

    pub const fn proof_consumed(&self) -> bool {
        self.consumed
    }
}
