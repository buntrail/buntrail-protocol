use base64::{Engine as _, engine::general_purpose::STANDARD};
use buntrail_core::contracts::{CoreError, ErrorCode, TargetPath};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathKind {
    Posix,
    Windows,
}

/// A validated, lossless target filesystem path; display strings never grant authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WirePath(TargetPath);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EncodedPath {
    kind: PathKind,
    base64: String,
}

impl WirePath {
    pub fn from_core(path: &TargetPath) -> Result<Self, CoreError> {
        Ok(Self(match path {
            TargetPath::PosixBytes(bytes) => TargetPath::posix(bytes.clone())?,
            TargetPath::WindowsWide(units) => TargetPath::windows(units.clone())?,
        }))
    }

    pub fn core(&self) -> TargetPath {
        self.0.clone()
    }

    pub fn kind(&self) -> PathKind {
        match self.0 {
            TargetPath::PosixBytes(_) => PathKind::Posix,
            TargetPath::WindowsWide(_) => PathKind::Windows,
        }
    }
}

impl Serialize for WirePath {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let bytes = match &self.0 {
            TargetPath::PosixBytes(bytes) => bytes.clone(),
            TargetPath::WindowsWide(units) => units.iter().flat_map(|u| u.to_le_bytes()).collect(),
        };
        EncodedPath {
            kind: self.kind(),
            base64: STANDARD.encode(bytes),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for WirePath {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        let encoded = EncodedPath::deserialize(deserializer)?;
        let bytes = STANDARD.decode(encoded.base64).map_err(D::Error::custom)?;
        let path = match encoded.kind {
            PathKind::Posix => TargetPath::posix(bytes),
            PathKind::Windows if bytes.len() % 2 == 0 => TargetPath::windows(
                bytes
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|u| u16::from_le_bytes([u[0], u[1]]))
                    .collect(),
            ),
            PathKind::Windows => Err(CoreError::new(
                ErrorCode::InvalidArgument,
                "odd Windows path byte length",
            )),
        };
        Ok(Self(path.map_err(|e| D::Error::custom(e.message))?))
    }
}
