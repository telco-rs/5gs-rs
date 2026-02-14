#[derive(Debug, serde::Deserialize)]
pub struct NrfConfig {
    pub subscriptions: Subscriptions,
}

#[derive(Debug, serde::Deserialize)]
pub struct Subscriptions {

    pub upstream: Option<String>,
}