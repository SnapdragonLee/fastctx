//! The guest manager receives only the protected registration's owner and paths.

use super::config::Config;
use crate::service::{
    Kind,
    guests::{Identity, Manager},
};

pub(super) fn manager(config: &Config) -> anyhow::Result<Manager> {
    anyhow::ensure!(config.kind == Kind::Node, "a hub cannot own guest accounts");
    let owner = fastctx_platform::unix_account::lookup(config.uid)?
        .ok_or_else(|| anyhow::anyhow!("guardian owner no longer exists"))?;
    Ok(Manager {
        root: config.root(),
        homes: config.root().join("homes"),
        registration: config.name.clone(),
        owner: Identity::Unix { uid: owner.uid, gid: owner.gid },
    })
}

pub(super) fn maintain(config: &Config) {
    if config.kind != Kind::Node {
        return;
    }
    let config = config.clone();
    std::thread::spawn(move || {
        let mut previous = None;
        loop {
            let error = manager(&config).and_then(|manager| manager.maintain()).err().map(|error| format!("{error:#}"));
            if error != previous {
                if let Some(error) = &error {
                    eprintln!("fastctx guardian guest maintenance: {error}");
                }
                previous = error;
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    });
}

pub(crate) fn retire(service: &crate::service::Service) -> anyhow::Result<()> {
    let config = Config::new(service)?;
    if config.kind == Kind::Node && config.root().try_exists()? {
        let config = Config::read(&config.name)?;
        manager(&config)?.handle(&crate::service::guests::Request::Retire)?;
    }
    Ok(())
}
