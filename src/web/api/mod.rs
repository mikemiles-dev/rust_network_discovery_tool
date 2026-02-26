//! API handlers for the `/api/*` HTTP endpoints.
//! Split into domain-specific modules for maintainability.

mod devices;
mod dns;
mod endpoints;
mod export;
mod scanning;
mod settings;

// Re-export all public items so `use api::*` in web/mod.rs continues to work.
pub use devices::*;
pub use dns::*;
pub use endpoints::*;
pub use export::*;
pub use scanning::*;
pub use settings::*;
