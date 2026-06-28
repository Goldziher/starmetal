use bytes::{Bytes, BytesMut};
use serde::de::DeserializeOwned;
use starmetal_core::error::{Result, StarmetalError};

#[allow(dead_code)]
pub(crate) async fn bytes_limited(
    mut response: reqwest::Response,
    max_bytes: u64,
    context: &str,
) -> Result<Bytes> {
    if let Some(content_length) = response.content_length()
        && content_length > max_bytes
    {
        return Err(StarmetalError::Upstream(format!(
            "{context} exceeded configured max_response_bytes"
        )));
    }

    let mut total = 0_u64;
    let mut body = BytesMut::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|err| StarmetalError::Upstream(err.to_string()))?
    {
        total = total.saturating_add(chunk.len() as u64);
        if total > max_bytes {
            return Err(StarmetalError::Upstream(format!(
                "{context} exceeded configured max_response_bytes"
            )));
        }
        body.extend_from_slice(&chunk);
    }

    Ok(body.freeze())
}

#[allow(dead_code)]
pub(crate) async fn text_limited(
    response: reqwest::Response,
    max_bytes: u64,
    context: &str,
) -> Result<String> {
    let bytes = bytes_limited(response, max_bytes, context).await?;
    String::from_utf8(bytes.to_vec()).map_err(|err| StarmetalError::Upstream(err.to_string()))
}

#[allow(dead_code)]
pub(crate) async fn json_limited<T>(
    response: reqwest::Response,
    max_bytes: u64,
    context: &str,
) -> Result<T>
where
    T: DeserializeOwned,
{
    let bytes = bytes_limited(response, max_bytes, context).await?;
    serde_json::from_slice(&bytes).map_err(StarmetalError::from)
}
