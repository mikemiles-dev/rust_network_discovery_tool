//! Device control module. Provides controllers for managing smart home and media
//! devices (LG TVs, Samsung TVs, Roku, LG ThinQ appliances) via their network APIs.

mod controller;
mod lg;
mod lg_thinq;
mod roku;
mod samsung;
mod types;

pub use controller::DeviceController;
