//! Target-scoped DTOs. Paths are lossless base64; target authority comes only from Context.
use crate::types::{WireVersion, decode_path};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use buntrail_core::contracts as c;
use serde::{Deserialize, Serialize};

pub fn invalid() -> c::CoreError {
    c::CoreError::new(c::ErrorCode::InvalidArgument, "Invalid service wire value")
}
pub fn path(p: &c::TargetPath) -> Result<String, c::CoreError> {
    match p {
        c::TargetPath::PosixBytes(b) => {
            c::TargetPath::posix(b.clone())?;
            Ok(B64.encode(b))
        }
        _ => Err(invalid()),
    }
}
pub fn target_path(p: &str) -> Result<c::TargetPath, c::CoreError> {
    c::TargetPath::posix(decode_path(p).map_err(|_| invalid())?)
}
pub fn uuid(b: [u8; 16]) -> String {
    let s: String = b.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &s[..8],
        &s[8..12],
        &s[12..16],
        &s[16..20],
        &s[20..]
    )
}
pub fn id(s: &str) -> Result<[u8; 16], c::CoreError> {
    if !crate::types::uuid(s) {
        return Err(invalid());
    }
    let s = s.replace('-', "");
    let mut b = [0; 16];
    for (i, v) in b.iter_mut().enumerate() {
        *v = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| invalid())?;
    }
    Ok(b)
}
pub fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}
pub fn digest(s: &str) -> Result<[u8; 32], c::CoreError> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid());
    }
    let mut b = [0; 32];
    for (i, v) in b.iter_mut().enumerate() {
        *v = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| invalid())?;
    }
    Ok(b)
}
pub fn version(v: &c::FileVersion) -> WireVersion {
    WireVersion {
        opaque_token: B64.encode(&v.opaque_token),
        content_digest: hex(&v.content_digest),
        file_identity: B64.encode(&v.file_identity),
    }
}
impl WireVersion {
    pub fn core(&self, t: &c::TargetIdentity) -> Result<c::FileVersion, c::CoreError> {
        Ok(c::FileVersion {
            target: t.clone(),
            opaque_token: B64.decode(&self.opaque_token).map_err(|_| invalid())?,
            content_digest: digest(&self.content_digest)?,
            file_identity: B64.decode(&self.file_identity).map_err(|_| invalid())?,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct File {
    pub path_base64: String,
    #[serde(deserialize_with = "crate::types::required_option")]
    pub resolved_identity: Option<String>,
}
impl File {
    pub fn from_core(f: &c::FileRef) -> Result<Self, c::CoreError> {
        Ok(Self {
            path_base64: path(&f.path)?,
            resolved_identity: f.resolved_identity.as_ref().map(|b| B64.encode(b)),
        })
    }
    pub fn core(&self, t: &c::TargetIdentity) -> Result<c::FileRef, c::CoreError> {
        Ok(c::FileRef {
            target: t.clone(),
            path: target_path(&self.path_base64)?,
            resolved_identity: self
                .resolved_identity
                .as_ref()
                .map(|s| B64.decode(s).map_err(|_| invalid()))
                .transpose()?,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Worktree {
    pub path_base64: String,
    pub common_directory_base64: String,
}
impl Worktree {
    pub fn from_core(w: &c::WorktreeIdentity) -> Result<Self, c::CoreError> {
        Ok(Self {
            path_base64: path(&w.canonical_path)?,
            common_directory_base64: B64.encode(&w.common_git_directory_identity),
        })
    }
    pub fn core(&self, t: &c::TargetIdentity) -> Result<c::WorktreeIdentity, c::CoreError> {
        Ok(c::WorktreeIdentity {
            target: t.clone(),
            canonical_path: target_path(&self.path_base64)?,
            common_git_directory_identity: B64
                .decode(&self.common_directory_base64)
                .map_err(|_| invalid())?,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Head {
    Branch { name_base64: String, oid: String },
    Detached { oid: String },
    Unborn { name_base64: String },
}
impl Head {
    fn from_core(h: &c::GitHead) -> Self {
        match h {
            c::GitHead::Branch { name, oid } => Self::Branch {
                name_base64: B64.encode(name),
                oid: oid.clone(),
            },
            c::GitHead::Detached(oid) => Self::Detached { oid: oid.clone() },
            c::GitHead::Unborn(name) => Self::Unborn {
                name_base64: B64.encode(name),
            },
        }
    }
    fn core(&self) -> Result<c::GitHead, c::CoreError> {
        Ok(match self {
            Self::Branch { name_base64, oid } => c::GitHead::Branch {
                name: B64.decode(name_base64).map_err(|_| invalid())?,
                oid: oid.clone(),
            },
            Self::Detached { oid } => c::GitHead::Detached(oid.clone()),
            Self::Unborn { name_base64 } => {
                c::GitHead::Unborn(B64.decode(name_base64).map_err(|_| invalid())?)
            }
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitState {
    pub head: Head,
    pub index_digest: String,
    pub worktree_digest: String,
}
impl GitState {
    pub fn from_core(s: &c::GitExpectedState) -> Self {
        Self {
            head: Head::from_core(&s.head),
            index_digest: hex(&s.index_fingerprint),
            worktree_digest: hex(&s.worktree_fingerprint),
        }
    }
    pub fn core(&self) -> Result<c::GitExpectedState, c::CoreError> {
        Ok(c::GitExpectedState {
            head: self.head.core()?,
            index_fingerprint: digest(&self.index_digest)?,
            worktree_fingerprint: digest(&self.worktree_digest)?,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum GitCommand {
    Repository { action: c::RepositoryAction },
    Stage { paths: Vec<String> },
    Unstage { paths: Vec<String> },
    Commit { message: String },
    Checkout { reference: String },
    Fetch { remote: String },
    Push { remote: String, reference: String },
    PullFastForward { remote: String, reference: String },
}
impl GitCommand {
    pub fn from_core(c: &c::GitMutation) -> Result<Self, c::CoreError> {
        Ok(match c {
            c::GitMutation::Repository(action) => Self::Repository {
                action: action.clone(),
            },
            c::GitMutation::Stage(p) => Self::Stage {
                paths: p.iter().map(path).collect::<Result<_, _>>()?,
            },
            c::GitMutation::Unstage(p) => Self::Unstage {
                paths: p.iter().map(path).collect::<Result<_, _>>()?,
            },
            c::GitMutation::Commit { message } => Self::Commit {
                message: message.clone(),
            },
            c::GitMutation::Checkout { reference } => Self::Checkout {
                reference: B64.encode(reference),
            },
            c::GitMutation::Fetch { remote } => Self::Fetch {
                remote: B64.encode(remote),
            },
            c::GitMutation::Push { remote, reference } => Self::Push {
                remote: B64.encode(remote),
                reference: B64.encode(reference),
            },
            c::GitMutation::PullFastForward { remote, reference } => Self::PullFastForward {
                remote: B64.encode(remote),
                reference: B64.encode(reference),
            },
        })
    }
    pub fn core(&self) -> Result<c::GitMutation, c::CoreError> {
        let b = |s: &str| B64.decode(s).map_err(|_| invalid());
        Ok(match self {
            Self::Repository { action } => c::GitMutation::Repository(action.clone()),
            Self::Stage { paths } => c::GitMutation::Stage(
                paths
                    .iter()
                    .map(|p| target_path(p))
                    .collect::<Result<_, _>>()?,
            ),
            Self::Unstage { paths } => c::GitMutation::Unstage(
                paths
                    .iter()
                    .map(|p| target_path(p))
                    .collect::<Result<_, _>>()?,
            ),
            Self::Commit { message } => c::GitMutation::Commit {
                message: message.clone(),
            },
            Self::Checkout { reference } => c::GitMutation::Checkout {
                reference: b(reference)?,
            },
            Self::Fetch { remote } => c::GitMutation::Fetch { remote: b(remote)? },
            Self::Push { remote, reference } => c::GitMutation::Push {
                remote: b(remote)?,
                reference: b(reference)?,
            },
            Self::PullFastForward { remote, reference } => c::GitMutation::PullFastForward {
                remote: b(remote)?,
                reference: b(reference)?,
            },
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FileCommand {
    CreateDirectory,
    Rename {
        destination: String,
    },
    Move {
        destination: String,
    },
    Remove {
        confirmed_target: String,
        confirmed_path: String,
    },
    Delete {
        confirmed_target: String,
        confirmed_path: String,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Search {
    pub root: File,
    pub expression: String,
    pub regex: bool,
    pub case_sensitive: bool,
    pub whole_word: bool,
    pub includes: Vec<String>,
    pub excludes: Vec<String>,
    pub hidden: bool,
    pub ignored: bool,
}
impl Search {
    pub fn from_core(r: &c::SearchRequest) -> Result<Self, c::CoreError> {
        Ok(Self {
            root: File::from_core(&r.root)?,
            expression: r.expression.clone(),
            regex: matches!(r.mode, c::SearchMode::Regex),
            case_sensitive: r.case_sensitive,
            whole_word: r.whole_word,
            includes: r.includes.clone(),
            excludes: r.excludes.clone(),
            hidden: r.hidden,
            ignored: r.ignored,
        })
    }
    pub fn core(&self, t: &c::TargetIdentity, id: u64) -> Result<c::SearchRequest, c::CoreError> {
        Ok(c::SearchRequest {
            request: c::RequestId(id),
            root: self.root.core(t)?,
            expression: self.expression.clone(),
            mode: if self.regex {
                c::SearchMode::Regex
            } else {
                c::SearchMode::Literal
            },
            case_sensitive: self.case_sensitive,
            whole_word: self.whole_word,
            includes: self.includes.clone(),
            excludes: self.excludes.clone(),
            hidden: self.hidden,
            ignored: self.ignored,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseOwner {
    pub client_id: String,
    pub workspace_id: String,
    pub lease_id: String,
    pub target_binding: String,
    pub runtime_generation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_start_base64: Option<String>,
}
impl LeaseOwner {
    pub fn from_core(
        owner: &c::WorkspaceLease,
        target: &c::TargetIdentity,
    ) -> Result<Self, c::CoreError> {
        use sha2::Digest;
        if owner
            .runtime
            .container_start
            .as_ref()
            .is_some_and(|s| s.is_empty() || s.len() > 256)
        {
            return Err(invalid());
        }
        Ok(Self {
            client_id: uuid(owner.client.0),
            workspace_id: uuid(owner.workspace.0),
            lease_id: uuid(owner.lease.0),
            target_binding: hex(&sha2::Sha256::digest(
                serde_json::to_vec(target).map_err(|_| invalid())?,
            )),
            runtime_generation: uuid(owner.runtime.supervisor_boot),
            container_start_base64: owner
                .runtime
                .container_start
                .as_ref()
                .map(|s| B64.encode(s)),
        })
    }
    pub fn context(&self) -> crate::types::Context {
        crate::types::Context {
            client_id: self.client_id.clone(),
            workspace_id: self.workspace_id.clone(),
            target_binding: self.target_binding.clone(),
            runtime_generation: self.runtime_generation.clone(),
        }
    }
    pub fn validate(&self) -> Result<(), c::CoreError> {
        id(&self.client_id)?;
        id(&self.workspace_id)?;
        id(&self.lease_id)?;
        id(&self.runtime_generation)?;
        digest(&self.target_binding)?;
        self.container_start()?;
        Ok(())
    }
    pub fn container_start(&self) -> Result<Option<Vec<u8>>, c::CoreError> {
        crate::types::decode_container_start(self.container_start_base64.as_deref())
            .map_err(|_| invalid())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum OwnerPresence {
    Active {},
    Detached { remaining_millis: u64 },
    Absent {},
    RuntimeLost {},
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub enum Call {
    Repository {
        worktree: Worktree,
    },
    Commit {
        worktree: Worktree,
        oid: String,
        cursor: Option<u64>,
    },
    FilteredHistory {
        worktree: Worktree,
        refs: Vec<String>,
        cursor: Option<String>,
        filter: c::HistoryFilter,
    },
    LeaseObserve {
        owner: LeaseOwner,
    },
    FileResolve {
        root: File,
        purpose: ResolvePurpose,
    },
    TerminalOpen {
        lease_id: String,
        session_id: String,
        directory_base64: String,
        shell_base64: String,
        columns: u16,
        rows: u16,
    },
    TerminalAttach {
        lease_id: String,
        session_id: String,
        last_output_sequence: u64,
    },
    TerminalInput {
        lease_id: String,
        session_id: String,
    },
    TerminalResize {
        lease_id: String,
        session_id: String,
        columns: u16,
        rows: u16,
    },
    TerminalEnd {
        lease_id: String,
        session_id: String,
        intent: crate::terminal::EndIntent,
    },
    List {
        file: File,
    },
    PathVersion {
        file: File,
    },
    Watch {
        file: File,
    },
    Search {
        request: Search,
    },
    FileMutate {
        file: File,
        #[serde(deserialize_with = "crate::types::required_option")]
        expected: Option<WireVersion>,
        command: FileCommand,
    },
    Discover {
        file: File,
    },
    Contains {
        worktree: Worktree,
        file: File,
    },
    GitRead {
        worktree: Worktree,
        query: c::GitRead,
    },
    Status {
        worktree: Worktree,
    },
    Diff {
        worktree: Worktree,
        path_base64: String,
        source: DiffSource,
    },
    History {
        worktree: Worktree,
        refs: Vec<String>,
        #[serde(deserialize_with = "crate::types::required_option")]
        cursor: Option<String>,
    },
    GitMutate {
        worktree: Worktree,
        expected: GitState,
        command: GitCommand,
    },
    GitExisting {
        worktree: Worktree,
        expected: GitState,
        command: GitCommand,
    },
    Inspect,
}
impl Call {
    pub fn requires_repository(&self) -> bool {
        matches!(
            self,
            Self::Repository { .. }
                | Self::Commit { .. }
                | Self::FilteredHistory { .. }
                | Self::GitMutate {
                    command: GitCommand::Repository { .. },
                    ..
                }
                | Self::GitExisting {
                    command: GitCommand::Repository { .. },
                    ..
                }
                | Self::Diff {
                    source: DiffSource::Commit { .. },
                    ..
                }
        )
    }

    pub fn terminal_lease(&self) -> Option<&str> {
        match self {
            Self::TerminalOpen { lease_id, .. }
            | Self::TerminalAttach { lease_id, .. }
            | Self::TerminalInput { lease_id, .. }
            | Self::TerminalResize { lease_id, .. }
            | Self::TerminalEnd { lease_id, .. } => Some(lease_id),
            _ => None,
        }
    }
    pub fn effectful(&self) -> bool {
        self.mutating()
            || matches!(
                self,
                Self::TerminalInput { .. } | Self::TerminalResize { .. } | Self::TerminalEnd { .. }
            )
    }

    pub fn unprepared_worktree_mutation(&self) -> bool {
        match self {
            Self::GitMutate { command, .. } => command.core().is_ok_and(|v| v.changes_worktree()),
            _ => false,
        }
    }

    pub fn mutating(&self) -> bool {
        matches!(
            self,
            Self::FileMutate { .. } | Self::GitMutate { .. } | Self::TerminalOpen { .. }
        )
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DiffSource {
    Index,
    Worktree,
    Commit { oid: String },
}
impl DiffSource {
    pub fn from_core(s: &c::DiffSource) -> Self {
        match s {
            c::DiffSource::Index => Self::Index,
            c::DiffSource::Worktree => Self::Worktree,
            c::DiffSource::Commit(oid) => Self::Commit { oid: oid.clone() },
        }
    }
    pub fn core(&self) -> c::DiffSource {
        match self {
            Self::Index => c::DiffSource::Index,
            Self::Worktree => c::DiffSource::Worktree,
            Self::Commit { oid } => c::DiffSource::Commit(oid.clone()),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub file: File,
    pub display_name: String,
    pub kind: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitEntry {
    pub path_base64: String,
    #[serde(deserialize_with = "crate::types::required_option")]
    pub previous_path: Option<String>,
    pub status: String,
}
impl GitEntry {
    pub fn from_core(e: &c::GitEntry) -> Result<Self, c::CoreError> {
        Ok(Self {
            path_base64: path(&e.path)?,
            previous_path: e.previous_path.as_ref().map(path).transpose()?,
            status: e.status.clone(),
        })
    }
    pub fn core(&self) -> Result<c::GitEntry, c::CoreError> {
        Ok(c::GitEntry {
            path: target_path(&self.path_base64)?,
            previous_path: self.previous_path.as_deref().map(target_path).transpose()?,
            status: self.status.clone(),
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Commit {
    pub lane: u32,
    pub parent_lanes: Vec<u32>,
    pub author: String,
    pub authored_at: String,
    pub message: String,
    pub oid: String,
    pub parents: Vec<String>,
    pub decorations: Vec<String>,
    pub subject: String,
}
impl Commit {
    pub fn from_core(c: &c::GraphCommit) -> Self {
        Self {
            lane: c.lane,
            parent_lanes: c.parent_lanes.clone(),
            author: c.author.clone(),
            authored_at: c.authored_at.clone(),
            message: c.message.clone(),
            oid: c.oid.clone(),
            parents: c.parents.clone(),
            decorations: c.decorations.iter().map(|b| B64.encode(b)).collect(),
            subject: c.subject.clone(),
        }
    }
    pub fn core(&self) -> Result<c::GraphCommit, c::CoreError> {
        Ok(c::GraphCommit {
            lane: self.lane,
            parent_lanes: self.parent_lanes.clone(),
            author: self.author.clone(),
            authored_at: self.authored_at.clone(),
            message: self.message.clone(),
            oid: self.oid.clone(),
            parents: self.parents.clone(),
            decorations: self
                .decorations
                .iter()
                .map(|b| B64.decode(b).map_err(|_| invalid()))
                .collect::<Result<_, _>>()?,
            subject: self.subject.clone(),
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Reply {
    Repository {
        snapshot: Box<c::GitRepositorySnapshot>,
    },
    Commit {
        page: c::CommitPage,
    },
    GitRead {
        stdout_base64: String,
        stderr_base64: String,
        success: bool,
    },
    LeaseObserved {
        owner: LeaseOwner,
        runtime_generation: String,
        presence: OwnerPresence,
        workers_retired: bool,
    },
    FileResolved {
        root: File,
        file: File,
        resolved_path: String,
        #[serde(deserialize_with = "crate::types::required_option")]
        node_kind: Option<String>,
        #[serde(deserialize_with = "crate::types::required_option")]
        version: Option<WireVersion>,
    },
    TerminalAck,
    Terminal {
        event: crate::terminal::Event,
    },
    List {
        entries: Vec<Entry>,
    },
    Version {
        version: WireVersion,
    },
    Watch {
        file: File,
        event: String,
    },
    SearchMatch {
        file: File,
        line: u64,
        column_utf8: u64,
        preview: String,
        version: WireVersion,
        digest: String,
    },
    SearchProgress {
        files: u64,
        matches: u64,
    },
    SearchComplete,
    SearchCancelled,
    SearchLimited {
        maximum: u64,
    },
    Discovered {
        #[serde(deserialize_with = "crate::types::required_option")]
        worktree: Option<Worktree>,
    },
    Contains {
        value: bool,
    },
    Status {
        worktree: Worktree,
        state: GitState,
        staged: Vec<GitEntry>,
        unstaged: Vec<GitEntry>,
        untracked: Vec<GitEntry>,
        conflicts: Vec<GitEntry>,
    },
    Diff {
        source: DiffSource,
        content: String,
        #[serde(deserialize_with = "crate::types::required_option")]
        unavailable: Option<String>,
        change: String,
        #[serde(deserialize_with = "crate::types::required_option")]
        previous_path: Option<String>,
        expected: GitState,
        bytes_base64: String,
    },
    History {
        commits: Vec<Commit>,
        continuation_edges: Vec<(String, String)>,
        #[serde(deserialize_with = "crate::types::required_option")]
        next_cursor: Option<String>,
    },
    Receipt {
        receipt: Receipt,
    },
    GitExisting {
        #[serde(deserialize_with = "crate::types::required_option")]
        receipt: Option<Receipt>,
    },
    Error {
        code: String,
        message: String,
    },
}
impl Reply {
    pub fn error(e: c::CoreError) -> Self {
        Self::Error {
            code: format!("{:?}", e.code),
            message: e.message,
        }
    }
    pub fn search(e: c::SearchEvent) -> Result<Self, c::CoreError> {
        Ok(match e {
            c::SearchEvent::Match(m) => Self::SearchMatch {
                file: File::from_core(&m.file)?,
                line: m.line,
                column_utf8: m.preview_column_utf8,
                preview: m.preview,
                version: version(&m.searched_version),
                digest: hex(&m.searched_digest),
            },
            c::SearchEvent::Progress { files, matches } => Self::SearchProgress { files, matches },
            c::SearchEvent::Complete => Self::SearchComplete,
            c::SearchEvent::Cancelled => Self::SearchCancelled,
            c::SearchEvent::Limited { maximum } => Self::SearchLimited { maximum },
            c::SearchEvent::Failed(e) => Self::error(e),
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Observation {
    Unobserved,
    File {
        file: File,
        #[serde(deserialize_with = "crate::types::required_option")]
        version: Option<WireVersion>,
        #[serde(deserialize_with = "crate::types::required_option")]
        digest: Option<String>,
    },
    Git {
        worktree: Worktree,
        state: GitState,
    },
    GitNetwork {
        worktree: Worktree,
        state: GitState,
        intent: Box<NetworkIntent>,
        #[serde(deserialize_with = "crate::types::required_option")]
        observation: Option<NetworkObservation>,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkIntent {
    pub action: String,
    pub remote: String,
    pub reference: String,
    #[serde(deserialize_with = "crate::types::required_option")]
    pub endpoint_fingerprint: Option<String>,
    pub push_mapping_unconfigured: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkObservation {
    #[serde(deserialize_with = "crate::types::required_option")]
    pub remote_oid: Option<String>,
    pub remote_refs: String,
    pub local_refs: String,
    pub fetch_head: String,
    pub fetch_head_oids: String,
}
impl Observation {
    pub fn from_core(o: &c::ObservedState) -> Result<Self, c::CoreError> {
        Ok(match o {
            c::ObservedState::Unobserved => Self::Unobserved,
            c::ObservedState::File {
                file,
                version: v,
                digest: d,
            } => Self::File {
                file: File::from_core(file)?,
                version: v.as_ref().map(version),
                digest: d.as_ref().map(|b| hex(b)),
            },
            c::ObservedState::Git { worktree, state } => Self::Git {
                worktree: Worktree::from_core(worktree)?,
                state: GitState::from_core(state),
            },
            c::ObservedState::GitNetwork {
                worktree,
                state,
                intent,
                observation,
            } => Self::GitNetwork {
                worktree: Worktree::from_core(worktree)?,
                state: GitState::from_core(state),
                intent: Box::new(NetworkIntent {
                    action: format!("{:?}", intent.action),
                    remote: B64.encode(&intent.remote),
                    reference: B64.encode(&intent.reference),
                    endpoint_fingerprint: intent.endpoint_fingerprint.as_ref().map(|b| hex(b)),
                    push_mapping_unconfigured: intent.push_mapping_unconfigured,
                }),
                observation: observation.as_ref().map(|o| NetworkObservation {
                    remote_oid: o.remote_oid.clone(),
                    remote_refs: hex(&o.remote_refs_fingerprint),
                    local_refs: hex(&o.local_refs_fingerprint),
                    fetch_head: hex(&o.fetch_head_fingerprint),
                    fetch_head_oids: B64.encode(&o.fetch_head_oids),
                }),
            },
            _ => return Err(invalid()),
        })
    }
    pub fn core(&self, t: &c::TargetIdentity) -> Result<c::ObservedState, c::CoreError> {
        Ok(match self {
            Self::Unobserved => c::ObservedState::Unobserved,
            Self::File {
                file,
                version,
                digest: d,
            } => c::ObservedState::File {
                file: file.core(t)?,
                version: version.as_ref().map(|v| v.core(t)).transpose()?,
                digest: d.as_deref().map(digest).transpose()?,
            },
            Self::Git { worktree, state } => c::ObservedState::Git {
                worktree: worktree.core(t)?,
                state: state.core()?,
            },
            Self::GitNetwork {
                worktree,
                state,
                intent: i,
                observation: o,
            } => c::ObservedState::GitNetwork {
                worktree: worktree.core(t)?,
                state: state.core()?,
                intent: c::GitNetworkIntent {
                    action: match i.action.as_str() {
                        "Fetch" => c::GitNetworkAction::Fetch,
                        "Push" => c::GitNetworkAction::Push,
                        "PullFastForward" => c::GitNetworkAction::PullFastForward,
                        _ => return Err(invalid()),
                    },
                    remote: B64.decode(&i.remote).map_err(|_| invalid())?,
                    reference: B64.decode(&i.reference).map_err(|_| invalid())?,
                    endpoint_fingerprint: i
                        .endpoint_fingerprint
                        .as_deref()
                        .map(digest)
                        .transpose()?,
                    push_mapping_unconfigured: i.push_mapping_unconfigured,
                },
                observation: o
                    .as_ref()
                    .map(|o| {
                        Ok(c::GitNetworkObservation {
                            remote_oid: o.remote_oid.clone(),
                            remote_refs_fingerprint: digest(&o.remote_refs)?,
                            local_refs_fingerprint: digest(&o.local_refs)?,
                            fetch_head_fingerprint: digest(&o.fetch_head)?,
                            fetch_head_oids: B64
                                .decode(&o.fetch_head_oids)
                                .map_err(|_| invalid())?,
                        })
                    })
                    .transpose()?,
            },
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResultValue {
    TerminalOpened {
        session_id: String,
        runtime_generation: String,
        #[serde(deserialize_with = "crate::types::required_option")]
        container_start_base64: Option<String>,
    },
    Saved {
        revision: u64,
        version: WireVersion,
    },
    FileChanged {
        file: File,
        #[serde(deserialize_with = "crate::types::required_option")]
        version: Option<WireVersion>,
    },
    GitChanged {
        worktree: Worktree,
        state: GitState,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        outcome: Option<Box<c::RepositoryOutcome>>,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub operation_id: String,
    pub state: String,
    #[serde(deserialize_with = "crate::types::required_option")]
    pub result: Option<ResultValue>,
    #[serde(deserialize_with = "crate::types::required_option")]
    pub code: Option<String>,
    pub message: String,
    pub possible_effects: bool,
    pub observed: Box<Observation>,
}
impl Receipt {
    pub fn from_core(r: &c::OperationReceipt) -> Result<Self, c::CoreError> {
        let mut w = Self {
            operation_id: uuid(r.id.0),
            state: String::new(),
            result: None,
            code: None,
            message: String::new(),
            possible_effects: false,
            observed: Box::new(Observation::Unobserved),
        };
        w.state = match &r.state {
            c::OperationState::Accepted => "accepted",
            c::OperationState::Running => "running",
            c::OperationState::Confirmed(r) => {
                w.result = Some(match r {
                    c::MutationResult::Saved(s) => ResultValue::Saved {
                        revision: s.saved_revision.0,
                        version: version(&s.version),
                    },
                    c::MutationResult::FileChanged { file, version: v } => {
                        ResultValue::FileChanged {
                            file: File::from_core(file)?,
                            version: v.as_ref().map(version),
                        }
                    }
                    c::MutationResult::GitChanged {
                        worktree,
                        state,
                        outcome,
                    } => ResultValue::GitChanged {
                        outcome: outcome.clone(),
                        worktree: Worktree::from_core(worktree)?,
                        state: GitState::from_core(state),
                    },
                    c::MutationResult::TerminalOpened { session, runtime } => {
                        ResultValue::TerminalOpened {
                            session_id: uuid(session.0),
                            runtime_generation: uuid(runtime.supervisor_boot),
                            container_start_base64: runtime
                                .container_start
                                .as_ref()
                                .map(|s| B64.encode(s)),
                        }
                    }
                });
                "confirmed"
            }
            c::OperationState::Failed(f) => {
                w.code = Some(format!("{:?}", f.error.code));
                w.message = f.error.message.clone();
                w.possible_effects = f.effect == c::FailureEffect::PossiblePartialEffects;
                w.observed = Box::new(Observation::from_core(&f.observed)?);
                "failed"
            }
            c::OperationState::Unknown(e) => {
                w.message = e.explanation.clone();
                w.possible_effects = true;
                w.observed = Box::new(Observation::from_core(&e.observed)?);
                "unknown"
            }
        }
        .into();
        Ok(w)
    }
    pub fn core(&self, t: &c::TargetIdentity) -> Result<c::OperationReceipt, c::CoreError> {
        Ok(c::OperationReceipt {
            id: c::OperationID(id(&self.operation_id)?),
            state: match self.state.as_str() {
                "accepted" => c::OperationState::Accepted,
                "running" => c::OperationState::Running,
                "confirmed" => c::OperationState::Confirmed(
                    match self.result.as_ref().ok_or_else(invalid)? {
                        ResultValue::TerminalOpened {
                            session_id,
                            runtime_generation,
                            container_start_base64,
                        } => c::MutationResult::TerminalOpened {
                            session: c::TerminalSessionID(id(session_id)?),
                            runtime: c::RuntimeGeneration {
                                supervisor_boot: id(runtime_generation)?,
                                container_start: container_start_base64
                                    .as_ref()
                                    .map(|s| B64.decode(s).map_err(|_| invalid()))
                                    .transpose()?,
                            },
                        },
                        ResultValue::Saved { revision, version } => {
                            c::MutationResult::Saved(c::SaveResult {
                                saved_revision: c::BufferRevision(*revision),
                                version: version.core(t)?,
                            })
                        }
                        ResultValue::FileChanged { file, version } => {
                            c::MutationResult::FileChanged {
                                file: file.core(t)?,
                                version: version.as_ref().map(|v| v.core(t)).transpose()?,
                            }
                        }
                        ResultValue::GitChanged {
                            worktree,
                            state,
                            outcome,
                        } => c::MutationResult::GitChanged {
                            outcome: outcome.clone(),
                            worktree: worktree.core(t)?,
                            state: state.core()?,
                        },
                    },
                ),
                "failed" => c::OperationState::Failed(c::OperationFailure {
                    error: core_error(self.code.as_deref().ok_or_else(invalid)?, &self.message),
                    target: t.clone(),
                    observed: self.observed.core(t)?,
                    effect: if self.possible_effects {
                        c::FailureEffect::PossiblePartialEffects
                    } else {
                        c::FailureEffect::ProvenNoEffect
                    },
                }),
                "unknown" => c::OperationState::Unknown(c::ReconciliationEvidence {
                    target: t.clone(),
                    observed: self.observed.core(t)?,
                    explanation: self.message.clone(),
                }),
                _ => return Err(invalid()),
            },
        })
    }
}
pub fn core_error(code: &str, message: &str) -> c::CoreError {
    use c::ErrorCode::*;
    c::CoreError::new(
        match code {
            "InvalidArgument" | "invalid_argument" => InvalidArgument,
            "StaleRevision" => StaleRevision,
            "Unavailable" | "unavailable" => Unavailable,
            "Busy" | "busy" => Busy,
            "Cancelled" => Cancelled,
            "Unknown" => Unknown,
            "TargetChanged" => TargetChanged,
            "Closed" => Closed,
            "Io" => Io,
            _ => Unknown,
        },
        message,
    )
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResolvePurpose {
    Root,
    OpenChild { path_base64: String },
    MutationNode { path_base64: String },
}
impl ResolvePurpose {
    pub fn from_core(value: &c::FileResolvePurpose) -> Result<Self, c::CoreError> {
        Ok(match value {
            c::FileResolvePurpose::Root => Self::Root,
            c::FileResolvePurpose::OpenChild(p) => Self::OpenChild {
                path_base64: path(p)?,
            },
            c::FileResolvePurpose::MutationNode(p) => Self::MutationNode {
                path_base64: path(p)?,
            },
        })
    }
    pub fn core(&self) -> Result<c::FileResolvePurpose, c::CoreError> {
        Ok(match self {
            Self::Root => c::FileResolvePurpose::Root,
            Self::OpenChild { path_base64 } => {
                c::FileResolvePurpose::OpenChild(target_path(path_base64)?)
            }
            Self::MutationNode { path_base64 } => {
                c::FileResolvePurpose::MutationNode(target_path(path_base64)?)
            }
        })
    }
}
