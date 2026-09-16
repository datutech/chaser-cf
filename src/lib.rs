//! # chaser-cf
//!
//! High-performance Cloudflare bypass library with stealth browser automation.
//!
//! ## Features
//!
//! - **WAF Session**: Extract cookies and headers for authenticated requests
//! - **Turnstile Solver**: Solve Cloudflare Turnstile captchas (min and max modes)
//! - **Page Source**: Get HTML source from CF-protected pages
//! - **Stealth Profiles**: Windows, Linux, macOS fingerprint profiles
//!
//! ## Usage (Rust)
//!
//! ```rust,no_run
//! use chaser_cf::{ChaserCF, ChaserConfig, Profile};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     // Initialize with default config
//!     let chaser = ChaserCF::new(ChaserConfig::default()).await?;
//!
//!     // Solve WAF session
//!     let session = chaser.solve_waf_session("https://example.com", None).await?;
//!     println!("Cookies: {:?}", session.cookies);
//!
//!     // Get page source
//!     let source = chaser.get_source("https://example.com", None).await?;
//!     println!("HTML length: {}", source.len());
//!
//!     // Solve Turnstile
//!     let token = chaser.solve_turnstile("https://example.com", None).await?;
//!     println!("Token: {}", token);
//!
//!     // Explicit shutdown (or let it drop)
//!     chaser.shutdown().await;
//!
//!     Ok(())
//! }
//! ```
//!
//! ## C FFI Usage
//!
//! ```c
//! #include "chaser_cf.h"
//!
//! void on_result(const char* result, void* user_data) {
//!     printf("Result: %s\n", result);
//! }
//!
//! int main() {
//!     chaser_init(NULL);
//!     chaser_solve_waf_async("https://example.com", NULL, NULL, on_result);
//!     // ... wait for callback
//!     chaser_shutdown();
//!     return 0;
//! }
//! ```

pub mod core;
pub mod error;
pub mod models;

#[cfg(feature = "ffi")]
pub mod ffi;

// Re-export main types at crate root
pub use core::{ChaserCF, ChaserConfig};
pub use error::ChaserError;
pub use models::{Cookie, Profile, ProxyConfig, WafSession, WafSessionOptions};
