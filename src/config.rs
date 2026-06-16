
pub struct ServerConfig {
    pub listen_addr: String,
}

pub struct FirewallConfig {
    pub listen_addr: String,
    pub server_addr: String,
}

pub struct ClientConfig {
    pub firewall_addr: String,
}

impl ServerConfig {
    pub fn from_env() -> Self {
        Self {
            listen_addr: std::env::var("SERVER_ADDR")
                .unwrap_or_else(|_| "0.0.0.0:9090".to_string()),
        }
    }
}

impl FirewallConfig {
    pub fn from_env() -> Self {
        Self {
            listen_addr: std::env::var("FIREWALL_LISTEN")
                .unwrap_or_else(|_| "0.0.0.0:8080".to_string()),
            server_addr: std::env::var("FIREWALL_SERVER_ADDR")
                .unwrap_or_else(|_| "127.0.0.1:9090".to_string()),
        }
    }
}

impl ClientConfig {
    pub fn from_env() -> Self {
        Self {
            firewall_addr: std::env::var("CLIENT_ADDR")
                .unwrap_or_else(|_| "127.0.0.1:8080".to_string()),
        }
    }
}