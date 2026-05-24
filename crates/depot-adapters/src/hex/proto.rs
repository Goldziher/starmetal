#[derive(Clone, PartialEq, prost::Message)]
pub struct Signed {
    #[prost(bytes = "vec", required, tag = "1")]
    pub payload: Vec<u8>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub signature: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Package {
    #[prost(message, repeated, tag = "1")]
    pub releases: Vec<Release>,
    #[prost(string, required, tag = "2")]
    pub name: String,
    #[prost(string, required, tag = "3")]
    pub repository: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Release {
    #[prost(string, required, tag = "1")]
    pub version: String,
    #[prost(bytes = "vec", required, tag = "2")]
    pub inner_checksum: Vec<u8>,
    #[prost(bytes = "vec", optional, tag = "5")]
    pub outer_checksum: Option<Vec<u8>>,
}
