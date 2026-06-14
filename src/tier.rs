use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    Secret,
    Confidential,
    TopSecret,
}

pub struct TierPaths {
    pub private_key: PathBuf,
    pub public_key: PathBuf,
    pub store: PathBuf,
}

impl TierPaths {
    pub fn from_base(base: &Path, tier: Tier) -> Self {
        let tier_dir = base.join(tier.dir_name());
        Self {
            private_key: tier_dir.join("identity.private.enc"),
            public_key: tier_dir.join("identity.pub"),
            store: tier_dir.join("store"),
        }
    }
}

impl Tier {
    pub fn dir_name(&self) -> &str {
        match self {
            Tier::Secret => "secret",
            Tier::Confidential => "confidential",
            Tier::TopSecret => "top-secret",
        }
    }

    pub fn is_initialized(&self, base: &Path) -> bool {
        let paths = TierPaths::from_base(base, *self);
        paths.public_key.exists()
    }

    pub fn default_top_key_path(base: &Path) -> PathBuf {
        base.join("top.key")
    }

    pub fn daemon_socket_path(&self, base: &Path) -> PathBuf {
        match self {
            Tier::Secret => panic!("Secret tier has no daemon"),
            Tier::Confidential => base.join("keyboxd.sock"),
            Tier::TopSecret => base.join("keyboxd-top.sock"),
        }
    }
}
