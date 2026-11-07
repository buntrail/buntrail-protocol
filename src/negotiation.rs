use crate::{frame::*, types::*};
pub const INITIAL_CREDIT: usize = 512 * 1024;
pub const CAPABILITIES: &[&str] = &[
    "container.binding.v1",
    "leases",
    "leases.retirement",
    "leases.observe",
    "operations",
    "file.read",
    "file.resolve",
    "file.remove",
    "file.save",
    "file.save_proof",
    "services",
    "git.read",
    "git.existing",
    "git.worktree_proof",
    "git.original_lookup",
    "terminal",
    "terminal.ordered_controls",
];
#[derive(Clone)]
pub struct Negotiated {
    pub minor: u32,
    pub capabilities: Vec<String>,
    pub max_header: usize,
    pub max_payload: usize,
}
impl Negotiated {
    pub fn from_hello(header: &Header) -> Result<Self, &'static str> {
        header.validate(0, None)?;
        let Message::Hello {
            capabilities,
            max_header,
            max_payload,
        } = &header.message
        else {
            return Err("hello required");
        };
        if *max_header < 1024 || *max_payload < 65536 {
            return Err("limits cannot support required control and chunk frames");
        }
        Ok(Self {
            minor: MINOR,
            capabilities: CAPABILITIES
                .iter()
                .filter(|c| capabilities.iter().any(|v| v == **c))
                .map(|s| s.to_string())
                .collect(),
            max_header: *max_header as usize,
            max_payload: *max_payload as usize,
        })
    }
    pub fn supports(&self, name: &str) -> bool {
        self.capabilities.iter().any(|s| s == name)
    }
}
