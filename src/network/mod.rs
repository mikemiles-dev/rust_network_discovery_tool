//! Network module. Exports submodules for packet processing, endpoint management,
//! device control, and protocol handling.

pub mod communication;
pub mod device_control;
pub mod endpoint;
pub mod endpoint_attribute;
pub mod mdns_lookup;
pub mod packet_wrapper;
pub mod protocol;
