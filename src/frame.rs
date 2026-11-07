use crate::types::{Context, Header};
pub const MAJOR: u32 = 1;
pub const MINOR: u32 = 0;
pub const MAX_HEADER: usize = 65536;
pub const MAX_PAYLOAD: usize = 1048576;
#[derive(Debug)]
pub struct Frame {
    pub header: Header,
    pub payload: Vec<u8>,
}
#[derive(Default)]
pub struct Decoder {
    prefix: Vec<u8>,
    header: Vec<u8>,
    payload: Vec<u8>,
    lengths: Option<(usize, usize)>,
    parsed: Option<(Header, bool)>,
    failed: bool,
}

impl Decoder {
    pub fn buffered_payload_bytes(&self) -> usize {
        self.payload.capacity()
    }
    pub fn push(
        &mut self,
        bytes: &[u8],
        context: Option<&Context>,
    ) -> Result<Vec<Frame>, &'static str> {
        self.push_authorized(bytes, |candidate| Some(candidate) == context)
    }
    /// Authorize only contexts registered by the authenticated connection owner, never a header's own claims.
    pub fn push_authorized(
        &mut self,
        bytes: &[u8],
        authorize: impl Fn(&Context) -> bool,
    ) -> Result<Vec<Frame>, &'static str> {
        self.push_validated(bytes, |header, payload| {
            let expected = header.context.as_ref().filter(|context| authorize(context));
            header.validate(payload, expected)?;
            Ok(true)
        })
    }
    /// Helper requests: retired controls retain only the pinned bridge identity, never new-work authority.
    pub fn push_helper_requests(
        &mut self,
        bytes: &[u8],
        authorize: impl Fn(&Context) -> bool,
        bridge: Option<&Context>,
    ) -> Result<Vec<Frame>, &'static str> {
        use crate::types::Message;
        self.push_validated(bytes, |header, payload| {
            let control = matches!(
                header.message,
                Message::Credit { .. } | Message::Cancel { .. }
            );
            let expected = header.context.as_ref().filter(|context| {
                authorize(context)
                    || (control
                        && bridge.is_some_and(|bridge| {
                            bridge.client_id == context.client_id
                                && bridge.target_binding == context.target_binding
                                && bridge.runtime_generation == context.runtime_generation
                        }))
            });
            header.validate(payload, expected)?;
            if control
                && (header.sequence.is_some()
                    || (matches!(header.message, Message::Cancel { .. })
                        && (header.operation_id.is_some() || header.stream_id.is_some())))
            {
                return Err("invalid helper control identity");
            }
            Ok(true)
        })
    }
    /// Client replies only: unknown request IDs are structurally checked and discarded,
    /// never delivered or treated as authenticated state. Request decoders do not use this.
    pub fn push_replies(
        &mut self,
        bytes: &[u8],
        owner: impl Fn(u64) -> Option<(Context, Option<String>)>,
    ) -> Result<Vec<Frame>, &'static str> {
        use crate::types::Message;
        self.push_validated(bytes, |header, payload| {
            if !matches!(
                header.message,
                Message::ProofLookupReady { .. }
                    | Message::ProofReady { .. }
                    | Message::ProofOutputBegin { .. }
                    | Message::ProofOutputChunk { .. }
                    | Message::ProofOutputEnd { .. }
                    | Message::ProofPrepared { .. }
                    | Message::ProofExisting { .. }
                    | Message::ProofMissing { .. }
                    | Message::Ack { .. }
                    | Message::Error { .. }
                    | Message::Credit { .. }
                    | Message::Receipt { .. }
                    | Message::Cancellation { .. }
                    | Message::ServiceEvent { .. }
                    | Message::ReadBegin { .. }
                    | Message::ReadChunk { .. }
                    | Message::ReadEnd { .. }
                    | Message::TerminalOutput { .. }
            ) {
                return Err("unexpected client reply direction");
            }
            if let Some((context, operation)) = owner(header.request_id) {
                header.validate(payload, Some(&context))?;
                if header.operation_id != operation {
                    return Err("reply operation mismatch");
                }
                Ok(true)
            } else {
                header.validate(payload, header.context.as_ref())?;
                Ok(false)
            }
        })
    }
    fn push_validated(
        &mut self,
        mut bytes: &[u8],
        validate: impl Fn(&Header, usize) -> Result<bool, &'static str>,
    ) -> Result<Vec<Frame>, &'static str> {
        if bytes.len() > MAX_HEADER + MAX_PAYLOAD + 8 {
            self.failed = true;
            return Err("input window exceeds frame bound");
        }
        if self.failed {
            return Err("decoder failed; close connection");
        }
        let result = (|| {
            let mut frames = Vec::new();
            while !bytes.is_empty() {
                if self.lengths.is_none() {
                    take(&mut self.prefix, &mut bytes, 8);
                    if self.prefix.len() < 8 {
                        break;
                    }
                    let h = u32::from_be_bytes(self.prefix[..4].try_into().unwrap()) as usize;
                    let p = u32::from_be_bytes(self.prefix[4..].try_into().unwrap()) as usize;
                    if h == 0 || h > MAX_HEADER || p > MAX_PAYLOAD {
                        return Err("frame length exceeds limit");
                    }
                    self.lengths = Some((h, p));
                }
                let (h, p) = self.lengths.unwrap();
                if self.parsed.is_none() {
                    take(&mut self.header, &mut bytes, h);
                    if self.header.len() < h {
                        break;
                    }
                    let header: Header = serde_json::from_slice(&self.header)
                        .map_err(|_| "invalid header schema")?;
                    let deliver = validate(&header, p)?;
                    self.parsed = Some((header, deliver));
                }
                take(&mut self.payload, &mut bytes, p);
                if self.payload.len() < p {
                    break;
                }
                let (header, deliver) = self.parsed.take().unwrap();
                if deliver {
                    frames.push(Frame {
                        header,
                        payload: std::mem::take(&mut self.payload),
                    });
                } else {
                    self.payload.clear();
                }
                self.prefix.clear();
                self.header.clear();
                self.lengths = None;
            }
            Ok(frames)
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    pub fn finish(&self) -> Result<(), &'static str> {
        if self.failed || !self.prefix.is_empty() {
            Err("incomplete or invalid frame")
        } else {
            Ok(())
        }
    }
}
fn take(destination: &mut Vec<u8>, input: &mut &[u8], total: usize) {
    let n = (total - destination.len()).min(input.len());
    destination.extend_from_slice(&input[..n]);
    *input = &input[n..];
}

/// Transfer integrity only: staging and durable commit remain the file service's responsibility.
pub struct TransferVerifier {
    id: String,
    total: u64,
    offset: u64,
    hash: sha2::Sha256,
    ended: bool,
}
impl TransferVerifier {
    pub fn new(id: String, total: u64) -> Result<Self, &'static str> {
        use sha2::Digest;
        if !crate::types::uuid(&id) {
            return Err("invalid transfer ID");
        }
        Ok(Self {
            id,
            total,
            offset: 0,
            hash: sha2::Sha256::new(),
            ended: false,
        })
    }
    pub fn chunk(&mut self, id: &str, offset: u64, bytes: &[u8]) -> Result<(), &'static str> {
        use sha2::Digest;
        if self.ended
            || id != self.id
            || offset != self.offset
            || bytes.len() > 65536
            || bytes.is_empty()
            || bytes.len() as u64 > self.total - self.offset
        {
            return Err("invalid transfer chunk");
        }
        self.hash.update(bytes);
        self.offset += bytes.len() as u64;
        Ok(())
    }
    pub fn end(&mut self, id: &str, digest: [u8; 32]) -> Result<(), &'static str> {
        use sha2::Digest;
        if self.ended
            || id != self.id
            || self.offset != self.total
            || self.hash.clone().finalize().as_slice() != digest
        {
            return Err("invalid transfer completion");
        }
        self.ended = true;
        Ok(())
    }
}

impl Frame {
    pub fn encode(&self) -> Result<Vec<u8>, &'static str> {
        let header = serde_json::to_vec(&self.header).map_err(|_| "invalid header")?;
        if header.is_empty() || header.len() > MAX_HEADER || self.payload.len() > MAX_PAYLOAD {
            return Err("frame length exceeds limit");
        }
        let mut bytes = Vec::with_capacity(8 + header.len() + self.payload.len());
        bytes.extend((header.len() as u32).to_be_bytes());
        bytes.extend((self.payload.len() as u32).to_be_bytes());
        bytes.extend(header);
        bytes.extend(&self.payload);
        Ok(bytes)
    }
}
