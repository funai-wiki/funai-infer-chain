use libllm::InferStatus;
use regex::{Captures, Regex};
use funai_common::types::net::PeerHost;
use crate::net::http::{Error, HttpRequest, HttpRequestContents, HttpRequestPreamble, HttpResponse, HttpResponseContents, HttpResponsePayload, HttpResponsePreamble, HttpServerError, parse_json};
use crate::net::httpcore::{RPCRequestHandler, FunaiHttpRequest, FunaiHttpResponse};
use crate::net::{Error as NetError, FunaiNodeState};
use crate::net::http::response::HttpResponseClone;
use crate::util_lib::db::{Error as db_error};

/// The request to GET /v2/infer_res/{txid}
#[derive(Clone)]
pub struct RPCInferResultRequestHandler {
    pub tx_id: Option<String>,
}

impl RPCInferResultRequestHandler {
    pub fn new() -> Self {
        RPCInferResultRequestHandler { tx_id: None }
    }
}

/// The data we return on GET /v2/infer_res/{txid}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RPCInferResultData {
    pub txid: String,
    pub status: InferStatus,
    pub input: String,
    pub output: String,
    pub output_hash: String,
}

impl RPCInferResultData {
    pub fn from_llm(
        tx_id: String,
    ) -> Result<RPCInferResultData, NetError> {
        let result = libllm::query(tx_id.clone())
            .map_err(|e| NetError::DBError(db_error::NotFoundError))?;
        Ok(RPCInferResultData {
            txid: tx_id,
            status: result.status,
            input: result.input,
            output: result.output,
            output_hash: result.output_hash,
        })
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct InferResultStream {
    /// tx id
    pub tx_id: String,
}

/// Decode the HTTP request
impl HttpRequest for RPCInferResultRequestHandler {
    fn verb(&self) -> &'static str {
        "GET"
    }

    fn path_regex(&self) -> Regex {
        Regex::new(r#"^/v2/infer_res/(?P<tx_id>[0-9a-zA-Z]+)$"#).unwrap()
    }

    fn metrics_identifier(&self) -> &str {
        "/v2/infer_res/:tx_id"
    }

    /// Try to decode this request.
    /// There's nothing to load here, so just make sure the request is well-formed.
    fn try_parse_request(
        &mut self,
        preamble: &HttpRequestPreamble,
        captures: &Captures,
        query: Option<&str>,
        _body: &[u8],
    ) -> Result<HttpRequestContents, Error> {
        if preamble.get_content_length() != 0 {
            return Err(Error::DecodeError(
                "Invalid Http request: expected 0-length body".to_string(),
            ));
        }

        let tx_id = captures
            .name("tx_id")
            .ok_or(Error::DecodeError(
                "Missing tx_id".to_string()
            ))?
            .as_str()
            .to_string();

        self.tx_id = Some(tx_id);

        Ok(HttpRequestContents::new().query_string(query))
    }
}

impl RPCRequestHandler for RPCInferResultRequestHandler {
    /// Reset internal state
    fn restart(&mut self) {
        self.tx_id = None;
    }

    /// Make the response
    fn try_handle_request(
        &mut self,
        preamble: HttpRequestPreamble,
        _contents: HttpRequestContents,
        node: &mut FunaiNodeState,
    ) -> Result<(HttpResponsePreamble, HttpResponseContents), NetError> {
        let tx_id = self
            .tx_id
            .take()
            .ok_or(NetError::SendError("Missing tx_id".to_string()))?;

        let result =
            node.with_node_state(|_network, _sortdb, _chainstate, _mempool, _rpc_args| {
                RPCInferResultData::from_llm(tx_id.clone())
            });

        info!("Infer result for tx_id:{} infer_res:{:?}", tx_id, result);

        let infer_result = match result {
            Ok(infer_res) => infer_res,
            Err(e) => {
                return FunaiHttpResponse::new_error(
                    &preamble,
                    &HttpServerError::new(format!("Failed to load infer result: {:?}", &e)),
                )
                    .try_into_contents()
                    .map_err(NetError::from);
            }
        };

        let mut preamble = HttpResponsePreamble::ok_json(&preamble);
        let body = HttpResponseContents::try_from_json(&infer_result)?;
        Ok((preamble, body))
    }
}

/// Decode the HTTP response
impl HttpResponse for RPCInferResultRequestHandler {
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        let infer_res: RPCInferResultData = parse_json(preamble, body)?;
        Ok(HttpResponsePayload::try_from_json(infer_res)?)
    }
}

impl FunaiHttpRequest {
    /// Make a new getinferresult request to this endpoint
    pub fn new_getinferresult(host: PeerHost, tx_id: String) -> Self {
        FunaiHttpRequest::new_for_peer(
            host,
            "GET".into(),
            format!("/v2/infer_res/{}", tx_id),
            HttpRequestContents::new(),
        )
            .expect("Failed to construct request from infallible data")
    }
}

impl FunaiHttpResponse {
    pub fn decode_rpc_get_infer_result(self) -> Result<RPCInferResultData, Error> {
        let contents = self.get_http_payload_ok()?;
        let response_json: serde_json::Value = contents.try_into()?;
        let infer_res: RPCInferResultData = serde_json::from_value(response_json)
            .map_err(|_e| Error::DecodeError("Failed to decode JSON".to_string()))?;
        Ok(infer_res)
    }
}