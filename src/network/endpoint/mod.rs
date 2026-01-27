//! Endpoint module. Re-exports public APIs for endpoint classification,
//! vendor characterization, and model identification.

mod classification;
mod constants;
mod detection;
mod endpoint_ops;
mod mac_vendors;
mod model;
mod patterns;
mod types;
mod vendor;

// Re-exports to preserve public API
pub use constants::{is_valid_display_name, strip_local_suffix};
pub use endpoint_ops::EndPoint;
pub use model::{
    characterize_model, get_model_from_hostname, get_model_from_mac,
    get_model_from_vendor_and_type, infer_model_with_context, normalize_model_name,
};
pub use types::{InsertEndpointError, InternetDestination};
pub use vendor::{characterize_vendor, get_hostname_vendor, get_mac_vendor, get_vendor_from_model};
