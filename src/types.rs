pub use crate::path::{PathKind, WirePath};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Context {
    pub workspace_id: String,
    pub client_id: String,
    pub target_binding: String,
    pub runtime_generation: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub major: u32,
    pub minor: u32,
    pub request_id: u64,
    #[serde(deserialize_with = "required_option")]
    pub context: Option<Context>,
    #[serde(deserialize_with = "required_option")]
    pub operation_id: Option<String>,
    #[serde(deserialize_with = "required_option")]
    pub stream_id: Option<String>,
    #[serde(deserialize_with = "required_option")]
    pub sequence: Option<u64>,
    #[serde(flatten)]
    pub message: Message,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "metadata", deny_unknown_fields)]
pub enum Message {
    #[serde(rename = "proof.lookup.begin")]
    ProofLookupBegin {
        transfer_id: String,
        total_length: u64,
        action: ProofAction,
        lease_id: String,
    },
    #[serde(rename = "proof.lookup.ready")]
    ProofLookupReady { credit: u32 },
    #[serde(rename = "proof.ready")]
    ProofReady {
        original_transfer_id: String,
        approvals_transfer_id: String,
    },
    #[serde(rename = "proof.observe.begin")]
    ProofObserveBegin {
        transfer_id: String,
        total_length: u64,
        lease_id: String,
        worktree: crate::services::Worktree,
    },
    #[serde(rename = "proof.approvals.begin")]
    ProofApprovalsBegin {
        transfer_id: String,
        total_length: u64,
        proof_id: String,
        alias_digest: String,
    },
    #[serde(rename = "proof.output.begin")]
    ProofOutputBegin {
        transfer_id: String,
        total_length: u64,
    },
    #[serde(rename = "proof.prepared")]
    ProofPrepared { plan_id: String },
    #[serde(rename = "proof.existing")]
    ProofExisting { receipt: crate::services::Receipt },
    #[serde(rename = "proof.missing")]
    ProofMissing {},
    #[serde(rename = "proof.cancel")]
    ProofCancel { lease_id: String, plan_id: String },
    #[serde(rename = "proof.release")]
    ProofRelease {
        lease_id: String,
        observation_id: String,
    },
    #[serde(rename = "proof.lookup.chunk")]
    ProofLookupChunk { transfer_id: String, offset: u64 },
    #[serde(rename = "proof.lookup.end")]
    ProofLookupEnd { transfer_id: String, sha256: String },
    #[serde(rename = "proof.original.chunk")]
    ProofOriginalChunk { transfer_id: String, offset: u64 },
    #[serde(rename = "proof.original.end")]
    ProofOriginalEnd { transfer_id: String, sha256: String },
    #[serde(rename = "proof.approvals.chunk")]
    ProofApprovalsChunk { transfer_id: String, offset: u64 },
    #[serde(rename = "proof.approvals.end")]
    ProofApprovalsEnd { transfer_id: String, sha256: String },
    #[serde(rename = "proof.aliases.chunk")]
    ProofAliasesChunk { transfer_id: String, offset: u64 },
    #[serde(rename = "proof.aliases.end")]
    ProofAliasesEnd { transfer_id: String, sha256: String },
    #[serde(rename = "proof.output.chunk")]
    ProofOutputChunk { transfer_id: String, offset: u64 },
    #[serde(rename = "proof.output.end")]
    ProofOutputEnd { transfer_id: String, sha256: String },
    #[serde(rename = "hello")]
    Hello {
        capabilities: Vec<String>,
        max_header: u32,
        max_payload: u32,
    },
    #[serde(rename = "welcome")]
    Welcome {
        capabilities: Vec<String>,
        max_header: u32,
        max_payload: u32,
        initial_credit: u32,
        target_binding: String,
        runtime_generation: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        container_start_base64: Option<String>,
    },
    #[serde(rename = "lease.register")]
    Register {
        lease_id: String,
        client_id: String,
        workspace_id: String,
        target_binding: String,
        runtime_generation: String,
    },
    #[serde(rename = "lease.release")]
    Release {
        lease_id: String,
        intent: ReleaseIntent,
    },
    #[serde(rename = "connection.authentication")]
    Authentication {
        #[serde(deserialize_with = "required_option")]
        ssh_auth_sock: Option<String>,
    },
    #[serde(rename = "ack")]
    Ack {},
    #[serde(rename = "stream.credit")]
    Credit { bytes: u32 },
    #[serde(rename = "file.read")]
    Read { path_base64: String },
    #[serde(rename = "operation.receipt")]
    Receipt {
        state: ReceiptState,
        #[serde(deserialize_with = "required_option")]
        saved_version: Option<WireVersion>,
        #[serde(deserialize_with = "required_option")]
        saved_revision: Option<u64>,
        safe_message: String,
        #[serde(deserialize_with = "required_option")]
        failure: Option<WireFailure>,
        observed: WireObservation,
    },
    #[serde(rename = "cancel.result")]
    Cancellation { outcome: CancelOutcome },
    #[serde(rename = "service.call")]
    ServiceCall { call: crate::services::Call },
    #[serde(rename = "service.event")]
    ServiceEvent {
        offset: u64,
        total_length: u64,
        sha256: String,
        terminal: bool,
    },
    #[serde(rename = "file.list")]
    FileList { path_base64: String },
    #[serde(rename = "file.read.begin")]
    ReadBegin {
        transfer_id: String,
        path_base64: String,
        version: String,
        total_length: u64,
    },
    #[serde(rename = "file.read.chunk")]
    ReadChunk { transfer_id: String, offset: u64 },
    #[serde(rename = "file.read.end")]
    ReadEnd { transfer_id: String, sha256: String },
    #[serde(rename = "file.upload.begin")]
    UploadBegin {
        transfer_id: String,
        path_base64: String,
        total_length: u64,
    },
    #[serde(rename = "file.upload.chunk")]
    UploadChunk { transfer_id: String, offset: u64 },
    #[serde(rename = "file.upload.end")]
    UploadEnd { transfer_id: String, sha256: String },
    #[serde(rename = "file.create.commit")]
    CreateCommit { transfer_id: String },
    #[serde(rename = "file.save.commit")]
    SaveCommit {
        transfer_id: String,
        submitted_revision: u64,
        #[serde(deserialize_with = "required_option")]
        expected_version: Option<String>,
    },
    #[serde(rename = "file.save.commit_owned")]
    SaveCommitOwned {
        transfer_id: String,
        lease_id: String,
        submitted_revision: u64,
        #[serde(deserialize_with = "required_option")]
        expected_version: Option<String>,
    },
    #[serde(rename = "operation.inspect")]
    Inspect { operation_id: String },
    #[serde(rename = "terminal.output")]
    TerminalOutput { session_id: String },
    #[serde(rename = "cancel")]
    Cancel { request_id: u64 },
    #[serde(rename = "error")]
    Error { code: String, safe_message: String },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofAction {
    Lookup,
    Prepare,
    Execute,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseIntent {
    ViewDetachment,
    ResolvedWorkspaceClosure,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptState {
    Accepted,
    Running,
    Confirmed,
    Failed,
    Unknown,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireVersion {
    pub opaque_token: String,
    pub content_digest: String,
    pub file_identity: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CancelOutcome {
    ConfirmedCancel,
    Unknown,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WireEffect {
    ProvenNoEffect,
    PossiblePartialEffects,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireFailure {
    pub code: String,
    pub effect: WireEffect,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WireObservation {
    Unobserved,
    File {
        path_base64: String,
        #[serde(deserialize_with = "required_option")]
        version: Option<WireVersion>,
        #[serde(deserialize_with = "required_option")]
        digest: Option<String>,
    },
}
pub fn decode_path(value: &str) -> Result<Vec<u8>, &'static str> {
    let bytes = STANDARD.decode(value).map_err(|_| "invalid base64 path")?;
    if bytes.first() != Some(&b'/') || bytes.contains(&0) {
        return Err("invalid absolute POSIX path");
    }
    Ok(bytes)
}
pub fn uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) {
                c == b'-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
}
impl Header {
    pub fn validate(&self, payload: usize, expected: Option<&Context>) -> Result<(), &'static str> {
        if self.major != 1 {
            return Err("unsupported major");
        }
        if self.request_id == 0 {
            return Err("missing request ID");
        }
        if let Message::Hello {
            max_header,
            max_payload,
            ..
        } = &self.message
        {
            if self.context.is_some()
                || self.operation_id.is_some()
                || self.stream_id.is_some()
                || self.sequence.is_some()
                || payload != 0
                || *max_header == 0
                || *max_header > 65536
                || *max_payload == 0
                || *max_payload > 1048576
            {
                return Err("invalid negotiation limits");
            }
            return Ok(());
        }
        if let Message::Welcome {
            max_header,
            max_payload,
            initial_credit,
            target_binding,
            runtime_generation,
            container_start_base64,
            capabilities,
            ..
        } = &self.message
        {
            if self.context.is_some()
                || self.operation_id.is_some()
                || self.stream_id.is_some()
                || self.sequence.is_some()
                || payload != 0
                || *max_header == 0
                || *max_header > 65536
                || *max_payload == 0
                || *max_payload > 1048576
                || *initial_credit != 524288
                || target_binding.is_empty()
                || !uuid(runtime_generation)
                || decode_container_start(container_start_base64.as_deref()).is_err()
                || container_start_base64.is_some()
                    && !capabilities.iter().any(|c| c == "container.binding.v1")
            {
                return Err("invalid welcome");
            }
            return Ok(());
        }
        if let Message::Register {
            lease_id,
            client_id,
            workspace_id,
            target_binding,
            runtime_generation,
        } = &self.message
        {
            if self.context.is_some()
                || self.operation_id.is_some()
                || self.stream_id.is_some()
                || self.sequence.is_some()
                || payload != 0
                || !uuid(lease_id)
                || !uuid(client_id)
                || !uuid(workspace_id)
                || target_binding.is_empty()
                || !uuid(runtime_generation)
            {
                return Err("invalid registration");
            }
            // The supervisor verifies the binding/runtime against its own identity before registration.
            return Ok(());
        }
        let context = self.context.as_ref().ok_or("missing scoped context")?;
        if Some(context) != expected {
            return Err("mismatched authenticated context");
        }
        if !uuid(&context.workspace_id)
            || !uuid(&context.client_id)
            || context.target_binding.is_empty()
            || context.runtime_generation.is_empty()
        {
            return Err("invalid scoped IDs");
        }
        for id in [&self.operation_id, &self.stream_id].into_iter().flatten() {
            if !uuid(id) {
                return Err("invalid ID");
            }
        }
        let raw = matches!(
            self.message,
            Message::ServiceEvent { .. }
                | Message::ProofLookupChunk { .. }
                | Message::ProofOriginalChunk { .. }
                | Message::ProofApprovalsChunk { .. }
                | Message::ProofAliasesChunk { .. }
                | Message::ProofOutputChunk { .. }
                | Message::ReadChunk { .. }
                | Message::UploadChunk { .. }
                | Message::TerminalOutput { .. }
                | Message::ServiceCall {
                    call: crate::services::Call::TerminalInput { .. }
                }
        );
        if payload != 0 && !raw {
            return Err("unexpected payload");
        }
        if raw && payload > 65536 {
            return Err("chunk too large");
        }
        match &self.message {
            Message::ProofLookupBegin {
                transfer_id,
                lease_id,
                ..
            } => {
                if !uuid(lease_id)
                    || self.operation_id.is_none()
                    || self.sequence.is_some()
                    || self.stream_id.as_ref() != Some(transfer_id)
                {
                    return Err("invalid proof lookup identity");
                }
            }
            Message::ProofObserveBegin {
                transfer_id,
                lease_id,
                ..
            } => {
                if !uuid(lease_id)
                    || self.operation_id.is_some()
                    || self.sequence.is_some()
                    || self.stream_id.as_ref() != Some(transfer_id)
                {
                    return Err("invalid observation identity");
                }
            }
            Message::ProofApprovalsBegin {
                transfer_id,
                proof_id,
                alias_digest,
                ..
            } => {
                if !uuid(proof_id)
                    || !hex_digest(alias_digest)
                    || self.operation_id.is_none()
                    || self.sequence.is_some()
                    || self.stream_id.as_ref() != Some(transfer_id)
                {
                    return Err("invalid approval identity");
                }
            }
            Message::ProofLookupReady { credit }
                if *credit != 65536 || self.stream_id.is_none() || self.operation_id.is_none() =>
            {
                return Err("invalid lookup credit");
            }
            Message::ProofReady {
                original_transfer_id,
                approvals_transfer_id,
            } => {
                if !uuid(original_transfer_id)
                    || !uuid(approvals_transfer_id)
                    || original_transfer_id == approvals_transfer_id
                    || self.operation_id.is_none()
                {
                    return Err("invalid proof ready identity");
                }
            }
            Message::ProofOutputBegin { transfer_id, .. }
                if self.stream_id.as_ref() != Some(transfer_id) || self.operation_id.is_some() =>
            {
                return Err("invalid proof output identity");
            }
            Message::ProofPrepared { plan_id } if !uuid(plan_id) || self.operation_id.is_none() => {
                return Err("invalid plan identity");
            }
            Message::ProofExisting { .. } if self.operation_id.is_none() => {
                return Err("missing proof receipt operation");
            }
            Message::ProofMissing {}
                if self.operation_id.is_none()
                    || self.stream_id.is_none()
                    || self.sequence.is_some() =>
            {
                return Err("invalid missing-original reply identity");
            }
            Message::ProofCancel { lease_id, plan_id } => {
                if !uuid(lease_id)
                    || !uuid(plan_id)
                    || self.operation_id.is_some()
                    || self.stream_id.is_some()
                    || self.sequence.is_some()
                {
                    return Err("invalid plan cancellation");
                }
            }
            Message::ProofRelease {
                lease_id,
                observation_id,
            } => {
                if !uuid(lease_id)
                    || !uuid(observation_id)
                    || self.operation_id.is_some()
                    || self.stream_id.is_some()
                    || self.sequence.is_some()
                {
                    return Err("invalid observation release");
                }
            }
            Message::ProofLookupChunk { transfer_id, .. }
            | Message::ProofOriginalChunk { transfer_id, .. }
            | Message::ProofApprovalsChunk { transfer_id, .. }
            | Message::ProofAliasesChunk { transfer_id, .. }
            | Message::ProofOutputChunk { transfer_id, .. } => {
                if self.stream_id.as_ref() != Some(transfer_id)
                    || self.sequence.is_none()
                    || payload == 0
                    || payload > 65536
                {
                    return Err("invalid proof frame");
                }
                if matches!(
                    self.message,
                    Message::ProofLookupChunk { .. }
                        | Message::ProofOriginalChunk { .. }
                        | Message::ProofApprovalsChunk { .. }
                ) && self.operation_id.is_none()
                {
                    return Err("missing original operation");
                }
            }
            Message::ProofLookupEnd {
                transfer_id,
                sha256,
            }
            | Message::ProofOriginalEnd {
                transfer_id,
                sha256,
            }
            | Message::ProofApprovalsEnd {
                transfer_id,
                sha256,
            }
            | Message::ProofAliasesEnd {
                transfer_id,
                sha256,
            }
            | Message::ProofOutputEnd {
                transfer_id,
                sha256,
            } => {
                if self.stream_id.as_ref() != Some(transfer_id)
                    || self.sequence.is_none()
                    || !hex_digest(sha256)
                {
                    return Err("invalid proof frame");
                }
                if matches!(
                    self.message,
                    Message::ProofLookupEnd { .. }
                        | Message::ProofOriginalEnd { .. }
                        | Message::ProofApprovalsEnd { .. }
                ) && self.operation_id.is_none()
                {
                    return Err("missing original operation");
                }
            }
            Message::Authentication {
                ssh_auth_sock: Some(path),
            } => {
                decode_path(path)?;
            }
            Message::ServiceCall {
                call: crate::services::Call::LeaseObserve { owner },
            } => {
                owner.validate().map_err(|_| "invalid observed owner")?;
                if self.operation_id.is_some()
                    || self.stream_id.is_some()
                    || self.sequence.is_some()
                {
                    return Err("unexpected observation metadata");
                }
            }
            Message::ServiceCall { call }
                if (call.mutating()
                    || matches!(
                        call,
                        crate::services::Call::Inspect | crate::services::Call::GitExisting { .. }
                    ))
                    && self.operation_id.is_none() =>
            {
                return Err("missing service operation ID");
            }
            Message::ServiceEvent {
                offset,
                total_length,
                sha256,
                ..
            } if self.stream_id.is_none()
                || self.sequence.is_none()
                || *total_length > 32 * 1024 * 1024
                || offset.saturating_add(payload as u64) > *total_length
                || sha256.len() != 64
                || !sha256.bytes().all(|b| b.is_ascii_hexdigit()) =>
            {
                return Err("invalid service event");
            }
            Message::Release { lease_id, .. } if !uuid(lease_id) => return Err("invalid lease ID"),
            Message::Credit { bytes }
                if *bytes == 0 || *bytes > 524288 || self.stream_id.is_none() =>
            {
                return Err("invalid stream credit");
            }
            Message::Receipt { .. } if self.operation_id.is_none() => {
                return Err("missing receipt operation");
            }
            Message::Cancel { request_id: 0 } => return Err("invalid cancellation target ID"),
            Message::ReadBegin {
                transfer_id,
                path_base64,
                ..
            }
            | Message::UploadBegin {
                transfer_id,
                path_base64,
                ..
            } => {
                if !uuid(transfer_id) {
                    return Err("invalid transfer ID");
                }
                decode_path(path_base64)?;
            }
            Message::FileList { path_base64 } | Message::Read { path_base64 } => {
                decode_path(path_base64)?;
            }
            Message::ReadChunk { transfer_id, .. }
            | Message::UploadChunk { transfer_id, .. }
            | Message::CreateCommit { transfer_id }
            | Message::SaveCommit { transfer_id, .. } => {
                if !uuid(transfer_id) {
                    return Err("invalid transfer ID");
                }
            }
            Message::SaveCommitOwned {
                transfer_id,
                lease_id,
                ..
            } => {
                if !uuid(transfer_id) || !uuid(lease_id) {
                    return Err("invalid owned save transfer or lease ID");
                }
            }
            Message::ReadEnd {
                transfer_id,
                sha256,
            }
            | Message::UploadEnd {
                transfer_id,
                sha256,
            } => {
                if !uuid(transfer_id)
                    || sha256.len() != 64
                    || !sha256.bytes().all(|b| b.is_ascii_hexdigit())
                {
                    return Err("invalid transfer digest");
                }
            }
            Message::Inspect { operation_id } => {
                if !uuid(operation_id) || self.operation_id.as_ref() != Some(operation_id) {
                    return Err("mismatched operation ID");
                }
            }
            Message::TerminalOutput { session_id }
                if (!uuid(session_id) || self.sequence.is_none() || self.stream_id.is_none()) =>
            {
                return Err("invalid terminal stream");
            }
            _ => {}
        }
        if matches!(
            self.message,
            Message::UploadBegin { .. }
                | Message::UploadChunk { .. }
                | Message::UploadEnd { .. }
                | Message::CreateCommit { .. }
                | Message::SaveCommit { .. }
                | Message::SaveCommitOwned { .. }
        ) && self.operation_id.is_none()
        {
            return Err("missing operation ID");
        }
        Ok(())
    }
}
pub fn decode_container_start(value: Option<&str>) -> Result<Option<Vec<u8>>, &'static str> {
    value
        .map(|s| {
            if s.len() > 344 {
                return Err("container start generation exceeded its bound");
            }
            let bytes = STANDARD
                .decode(s)
                .map_err(|_| "invalid container start generation")?;
            if bytes.is_empty() || bytes.len() > 256 {
                return Err("invalid container start generation length");
            }
            Ok(bytes)
        })
        .transpose()
}

pub(crate) fn required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

fn hex_digest(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}
