use serde::{Deserialize, Serialize};

/// Data source for characterized values (vendor, model, hostname).
/// Priority order: UserSet > DeviceReported > NetworkInferred > PatternMatched
/// This provides a single source of truth for how we decide which value to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DataSource {
    /// User explicitly set this value (highest priority)
    UserSet = 4,
    /// Device self-reported via SSDP, mDNS, or similar
    DeviceReported = 3,
    /// Inferred from network data (MAC OUI, DHCP options)
    NetworkInferred = 2,
    /// Matched via hostname/model patterns (heuristic)
    PatternMatched = 1,
}

impl DataSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            DataSource::UserSet => "user",
            DataSource::DeviceReported => "device",
            DataSource::NetworkInferred => "network",
            DataSource::PatternMatched => "pattern",
        }
    }
}

impl std::fmt::Display for DataSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A value with its source for debugging and priority resolution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Characterized<T> {
    pub value: T,
    pub source: DataSource,
}

impl<T> Characterized<T> {
    pub fn new(value: T, source: DataSource) -> Self {
        Self { value, source }
    }

    pub fn user_set(value: T) -> Self {
        Self::new(value, DataSource::UserSet)
    }

    pub fn device_reported(value: T) -> Self {
        Self::new(value, DataSource::DeviceReported)
    }

    pub fn network_inferred(value: T) -> Self {
        Self::new(value, DataSource::NetworkInferred)
    }

    pub fn pattern_matched(value: T) -> Self {
        Self::new(value, DataSource::PatternMatched)
    }
}

/// Pick the highest priority value from a list of characterized options.
pub fn pick_best<T: Clone>(options: &[Option<Characterized<T>>]) -> Option<Characterized<T>> {
    options
        .iter()
        .filter_map(|o| o.as_ref())
        .max_by_key(|c| c.source)
        .cloned()
}

#[derive(Debug)]
pub enum InsertEndpointError {
    BothMacAndIpNone,
    ConstraintViolation,
    /// IP is an internet destination - recorded in internet_destinations table instead
    InternetDestination,
    DatabaseError(rusqlite::Error),
}

impl From<rusqlite::Error> for InsertEndpointError {
    fn from(err: rusqlite::Error) -> Self {
        match err {
            rusqlite::Error::SqliteFailure(err, Some(_))
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                InsertEndpointError::ConstraintViolation
            }
            _ => InsertEndpointError::DatabaseError(err),
        }
    }
}

/// Represents an internet destination (external host) tracked separately from local endpoints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternetDestination {
    pub id: i64,
    pub hostname: String,
    pub first_seen_at: i64,
    pub last_seen_at: i64,
    pub packet_count: i64,
    pub bytes_in: i64,
    pub bytes_out: i64,
}
