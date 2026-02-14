use validator::Validate;

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Validate)]
pub struct ProblemDetails {
    #[serde(rename = "type")]
    // pub type_: Option<Url>,
    pub title: Option<String>,
    pub status: u16,
    pub detail: String,
}