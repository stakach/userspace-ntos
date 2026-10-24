//! One-use proof for a function FDO forwarding its original FILTER IRP to its PDO.
//!
//! Unlike a nested class-filter forward, this call remains on the original
//! PDO-origin canonical IRP. The provider already ran on its own exact IRP.

use nt_io_manager::{
    retained_query_path_forward::SourceIrpTicket, HostedDevicePointerRegistration, IoManager,
    IrpId,
};
use nt_status::NtStatus;
use nt_types::ClientId;

use crate::{
    AcceptedPdoFilterEdgeError, AcceptedPdoLowerFilterProof, AcceptedPdoPnpIdentity,
    AcceptedPdoProviderCatalog, BusRelationTable, PnpManager,
};

#[derive(Debug)]
#[must_use = "retain until the original source completion has been acknowledged"]
pub struct AcceptedPdoDirectFilterEdge {
    original: AcceptedPdoPnpIdentity,
    fdo: HostedDevicePointerRegistration,
    pdo: HostedDevicePointerRegistration,
    client: ClientId,
    requestor_tid: u64,
    source: Option<SourceIrpTicket>,
    consumed: bool,
}

impl AcceptedPdoDirectFilterEdge {
    #[allow(clippy::too_many_arguments)]
    pub fn capture<P>(
        pnp: &PnpManager,
        relations: &BusRelationTable,
        providers: &AcceptedPdoProviderCatalog,
        io: &IoManager<P>,
        outer_irp: IrpId,
        fdo: HostedDevicePointerRegistration,
        pdo: HostedDevicePointerRegistration,
        client: ClientId,
        requestor_tid: u64,
    ) -> Result<Self, AcceptedPdoFilterEdgeError> {
        let original = AcceptedPdoPnpIdentity {
            outer_irp,
            pdo: pdo.device_id(),
            minor: nt_pnp_abi::IRP_MN_FILTER_RESOURCE_REQUIREMENTS,
            provider: providers
                .resolve(pnp, relations, io, pdo.device_id().raw())
                .map_err(|_| AcceptedPdoFilterEdgeError::WrongProvider)?,
        };
        let edge = Self {
            original, fdo, pdo, client, requestor_tid, source: None, consumed: false,
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
        let outer = io.irp(self.original.outer_irp)
            .ok_or(AcceptedPdoFilterEdgeError::WrongOuter)?;
        if outer.client_id != self.client
            || outer.file_id.is_some()
            || outer.origin_major != nt_pnp_abi::IRP_MJ_PNP
            || outer.origin_minor != nt_pnp_abi::IRP_MN_FILTER_RESOURCE_REQUIREMENTS
            || outer.origin_device_id != self.pdo.device_id()
            || outer.requestor_tid != self.requestor_tid
            || outer.current_stack().map(|frame| frame.device_id) != Some(self.fdo.device_id())
        {
            return Err(AcceptedPdoFilterEdgeError::WrongOuter);
        }
        if self.fdo.domain() != self.pdo.domain()
            || io.hosted_device_pointer_registration(self.fdo.domain(), self.fdo.address())
                != Some(self.fdo)
            || io.hosted_device_pointer_registration(self.pdo.domain(), self.pdo.address())
                != Some(self.pdo)
            || io.device(self.fdo.device_id()).and_then(|device| device.attached_to)
                != Some(self.pdo.device_id())
            || pnp.devnode_for_pdo(self.pdo.device_id().raw())
                .and_then(|node| pnp.fdo(node)) != Some(self.fdo.device_id().raw())
        {
            return Err(AcceptedPdoFilterEdgeError::WrongStack);
        }
        let provider = providers.resolve(pnp, relations, io, self.pdo.device_id().raw())
            .map_err(|_| AcceptedPdoFilterEdgeError::WrongProvider)?;
        if provider != self.original.provider || provider.provider().domain() == self.fdo.domain() {
            return Err(AcceptedPdoFilterEdgeError::WrongProvider);
        }
        Ok(())
    }

    pub const fn original_identity(&self) -> AcceptedPdoPnpIdentity { self.original }

    pub fn bind_source(
        &mut self,
        observed_irp: IrpId,
        source: SourceIrpTicket,
    ) -> Result<(), AcceptedPdoFilterEdgeError> {
        if observed_irp != self.original.outer_irp || source.domain != self.fdo.domain() {
            return Err(AcceptedPdoFilterEdgeError::WrongSource);
        }
        match self.source {
            None => self.source = Some(source),
            Some(current) if current == source => (),
            Some(_) => return Err(AcceptedPdoFilterEdgeError::WrongSource),
        }
        Ok(())
    }

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
        if self.consumed { return Err(AcceptedPdoFilterEdgeError::Consumed); }
        if observed_irp != self.original.outer_irp || self.source != Some(observed_source) {
            return Err(AcceptedPdoFilterEdgeError::WrongSource);
        }
        self.validate_current(pnp, relations, providers, io)?;
        let status = proof.take_for(self.original)
            .map_err(|_| AcceptedPdoFilterEdgeError::WrongProof)?;
        self.consumed = true;
        Ok(status)
    }
}
