pub mod desktop;
mod server;
mod volume;

pub use desktop::DesktopDatabase;
pub(crate) use server::AfpServer;
pub use server::AfpServerConfig;

pub use tailtalk_packets::afp::{FinderFlags, FinderInfo};
pub use volume::{
    icon_cr_on_disk_name, read_finder_info, write_finder_info, Volume, ICON_CR_NAME,
};
