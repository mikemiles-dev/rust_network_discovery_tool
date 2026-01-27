mod types;
mod constants;
mod patterns;
mod mac_vendors;
mod detection;
mod vendor;
mod model;
mod classification;
mod endpoint_ops;

// Re-exports to preserve public API (some may only be used externally)
#[allow(unused_imports)]
pub use types::{DataSource, Characterized, pick_best, InsertEndpointError, InternetDestination};
#[allow(unused_imports)]
pub use constants::{strip_local_suffix, is_valid_display_name, is_uuid_like,
                    is_locally_administered_mac, is_ipv6_link_local, extract_mac_from_ipv6_eui64};
pub use vendor::{get_mac_vendor, get_hostname_vendor, get_vendor_from_model, characterize_vendor};
pub use model::{normalize_model_name, get_model_from_hostname, get_model_from_mac,
                get_model_from_vendor_and_type, infer_model_with_context, characterize_model};
pub use endpoint_ops::EndPoint;
