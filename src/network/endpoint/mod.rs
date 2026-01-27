mod classification;
mod constants;
mod detection;
mod endpoint_ops;
mod mac_vendors;
mod model;
mod patterns;
mod types;
mod vendor;

// Re-exports to preserve public API (some may only be used externally)
#[allow(unused_imports)]
pub use constants::{
    extract_mac_from_ipv6_eui64, is_ipv6_link_local, is_locally_administered_mac, is_uuid_like,
    is_valid_display_name, strip_local_suffix,
};
pub use endpoint_ops::EndPoint;
pub use model::{
    characterize_model, get_model_from_hostname, get_model_from_mac,
    get_model_from_vendor_and_type, infer_model_with_context, normalize_model_name,
};
#[allow(unused_imports)]
pub use types::{Characterized, DataSource, InsertEndpointError, InternetDestination, pick_best};
pub use vendor::{characterize_vendor, get_hostname_vendor, get_mac_vendor, get_vendor_from_model};
