pub mod desktop;
mod server;
mod volume;

pub use desktop::DesktopDatabase;
pub use server::{AfpServer, AfpServerConfig};
pub use tailtalk_packets::afp::{FinderFlags, FinderInfo};
pub use volume::{read_finder_info, write_finder_info, Volume};
