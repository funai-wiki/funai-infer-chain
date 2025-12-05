// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2023 Funai Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::io::{Read, Write};

use regex::{Captures, Regex};
use serde::de::Error as de_Error;
use funai_common::types::chainstate::FunaiBlockId;
use funai_common::types::net::PeerHost;
use funai_common::util::hash::to_hex;
use {serde, serde_json};

use crate::chainstate::funai::db::{ExtendedFunaiHeader, FunaiChainState};
use crate::chainstate::funai::Error as ChainError;
use crate::net::http::{
    parse_json, Error, HttpBadRequest, HttpChunkGenerator, HttpContentType, HttpNotFound,
    HttpRequest, HttpRequestContents, HttpRequestPreamble, HttpResponse, HttpResponseContents,
    HttpResponsePayload, HttpResponsePreamble, HttpServerError,
};
use crate::net::httpcore::{
    request, HttpRequestContentsExtensions, RPCRequestHandler, FunaiHttp, FunaiHttpRequest,
    FunaiHttpResponse,
};
use crate::net::{Error as NetError, FunaiNodeState, TipRequest, MAX_HEADERS};
use crate::util_lib::db::{DBConn, Error as DBError};

#[derive(Clone)]
pub struct RPCHeadersRequestHandler {
    pub quantity: Option<u32>,
}

impl RPCHeadersRequestHandler {
    pub fn new() -> Self {
        Self { quantity: None }
    }
}

#[derive(Debug)]
pub struct FunaiHeaderStream {
    /// index block hash of the block to download
    pub index_block_hash: FunaiBlockId,
    /// offset into whatever is being read (the blob, or the file in the chunk store)
    pub offset: u64,
    /// total number of bytes read.
    pub total_bytes: u64,
    /// number of headers remaining to stream
    pub num_headers: u32,

    /// header buffer data
    pub end_of_stream: bool,
    pub corked: bool,

    /// connection to the underlying chainstate
    chainstate_db: DBConn,
    blocks_path: String,
}

impl FunaiHeaderStream {
    pub fn new(
        chainstate: &FunaiChainState,
        tip: &FunaiBlockId,
        num_headers_requested: u32,
    ) -> Result<Self, ChainError> {
        let header_info = FunaiChainState::load_staging_block_info(chainstate.db(), tip)?
            .ok_or(ChainError::NoSuchBlockError)?;

        let num_headers = if header_info.height < (num_headers_requested as u64) {
            header_info.height as u32
        } else {
            num_headers_requested
        };

        let db = chainstate.reopen_db()?;
        let blocks_path = chainstate.blocks_path.clone();

        Ok(FunaiHeaderStream {
            index_block_hash: tip.clone(),
            offset: 0,
            total_bytes: 0,
            num_headers: num_headers,
            end_of_stream: false,
            corked: false,
            chainstate_db: db,
            blocks_path,
        })
    }
}

/// Decode the HTTP request
impl HttpRequest for RPCHeadersRequestHandler {
    fn verb(&self) -> &'static str {
        "GET"
    }

    fn path_regex(&self) -> Regex {
        Regex::new(r#"^/v2/headers/(?P<quantity>[0-9]+)$"#).unwrap()
    }

    fn metrics_identifier(&self) -> &str {
        "/v2/headers/:height"
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
                "Invalid Http request: expected 0-length body for GetInfo".to_string(),
            ));
        }

        let quantity = request::get_u32(captures, "quantity")?;
        self.quantity = Some(quantity);

        let contents = HttpRequestContents::new().query_string(query);

        Ok(contents)
    }
}

impl RPCRequestHandler for RPCHeadersRequestHandler {
    /// Reset internal state
    fn restart(&mut self) {
        self.quantity = None;
    }

    /// Make the response
    fn try_handle_request(
        &mut self,
        preamble: HttpRequestPreamble,
        contents: HttpRequestContents,
        node: &mut FunaiNodeState,
    ) -> Result<(HttpResponsePreamble, HttpResponseContents), NetError> {
        let quantity = self
            .quantity
            .take()
            .ok_or(NetError::SendError("`quantity` not set".to_string()))?;
        if (quantity as usize) > MAX_HEADERS {
            return FunaiHttpResponse::new_error(
                &preamble,
                &HttpBadRequest::new(format!(
                    "Invalid request: requested more than {} headers\n",
                    MAX_HEADERS
                )),
            )
            .try_into_contents()
            .map_err(NetError::from);
        }

        // find requested chain tip
        let tip = match node.load_funai_chain_tip(&preamble, &contents) {
            Ok(tip) => tip,
            Err(error_resp) => {
                return error_resp.try_into_contents().map_err(NetError::from);
            }
        };

        let stream_res =
            node.with_node_state(|_network, _sortdb, chainstate, _mempool, _rpc_args| {
                FunaiHeaderStream::new(chainstate, &tip, quantity)
            });

        // start loading headers
        let stream = match stream_res {
            Ok(stream) => stream,
            Err(ChainError::NoSuchBlockError) => {
                return FunaiHttpResponse::new_error(
                    &preamble,
                    &HttpNotFound::new(format!("No such block {:?}\n", &tip)),
                )
                .try_into_contents()
                .map_err(NetError::from)
            }
            Err(e) => {
                // nope -- error trying to check
                let msg = format!("Failed to load block header: {:?}\n", &e);
                warn!("{}", &msg);
                return FunaiHttpResponse::new_error(&preamble, &HttpServerError::new(msg))
                    .try_into_contents()
                    .map_err(NetError::from);
            }
        };

        let resp_preamble = HttpResponsePreamble::from_http_request_preamble(
            &preamble,
            200,
            "OK",
            None,
            HttpContentType::JSON,
        );

        Ok((
            resp_preamble,
            HttpResponseContents::from_stream(Box::new(stream)),
        ))
    }
}

/// Decode the HTTP response
impl HttpResponse for RPCHeadersRequestHandler {
    /// Decode this response from a byte stream.  This is called by the client to decode this
    /// message
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        let headers: Vec<ExtendedFunaiHeader> = parse_json(preamble, body)?;
        Ok(HttpResponsePayload::try_from_json(headers)?)
    }
}

/// Stream implementation for HeaderStreamData
impl HttpChunkGenerator for FunaiHeaderStream {
    fn hint_chunk_size(&self) -> usize {
        4096
    }

    #[cfg_attr(test, mutants::skip)]
    fn generate_next_chunk(&mut self) -> Result<Vec<u8>, String> {
        if self.total_bytes == 0 {
            // headers are a JSON array.  Start by writing '[', then write each header, and
            // then write ']'
            test_debug!("Opening header stream");
            self.total_bytes += 1;
            return Ok(vec!['[' as u8]);
        }
        if self.num_headers == 0 {
            test_debug!("End of header stream");
            self.end_of_stream = true;
        }
        if self.total_bytes > 0 && !self.end_of_stream && !self.corked {
            // have more data to send.
            // read next header as JSON
            match FunaiChainState::read_extended_header(
                &self.chainstate_db,
                &self.blocks_path,
                &self.index_block_hash,
            ) {
                Ok(extended_header) => {
                    // serialize
                    let mut header_bytes = vec![];
                    serde_json::to_writer(&mut header_bytes, &extended_header).map_err(|e| {
                        let msg = format!("Failed to encoded Funai header: {:?}", &e);
                        warn!("{}", &msg);
                        msg
                    })?;

                    // advance
                    self.index_block_hash = extended_header.parent_block_id;
                    self.num_headers -= 1;

                    if self.num_headers > 0 {
                        header_bytes.push(',' as u8);
                    } else {
                        self.end_of_stream = true;
                    }

                    self.total_bytes += header_bytes.len() as u64;
                    return Ok(header_bytes);
                }
                Err(ChainError::DBError(DBError::NotFoundError)) => {
                    // end of headers
                    test_debug!("Header not found; ending stream");
                    self.end_of_stream = true;
                }
                Err(e) => {
                    warn!("Header DB error: {:?}", &e);
                    self.end_of_stream = true;
                    return Err(format!(
                        "Failed to read extended header {}: {:?}",
                        &self.index_block_hash, &e
                    ));
                }
            };
        }
        if self.end_of_stream && !self.corked {
            // sent all the headers we're gonna send.
            test_debug!("Corking header stream");
            self.corked = true;
            self.total_bytes += 1;
            return Ok(vec![']' as u8]);
        }

        test_debug!("Header stream terminated");
        // end of stream and corked. we're done!
        return Ok(vec![]);
    }
}

impl FunaiHttpRequest {
    pub fn new_getheaders(host: PeerHost, quantity: u64, tip_req: TipRequest) -> FunaiHttpRequest {
        FunaiHttpRequest::new_for_peer(
            host,
            "GET".into(),
            format!("/v2/headers/{}", quantity),
            HttpRequestContents::new().for_tip(tip_req),
        )
        .expect("FATAL: failed to construct request from infallible data")
    }
}

impl FunaiHttpResponse {
    pub fn decode_funai_headers(self) -> Result<Vec<ExtendedFunaiHeader>, NetError> {
        let contents = self.get_http_payload_ok()?;
        let response_json: serde_json::Value = contents.try_into()?;
        let headers: Vec<ExtendedFunaiHeader> = serde_json::from_value(response_json)
            .map_err(|_e| Error::DecodeError("Failed to decode JSON".to_string()))?;
        Ok(headers)
    }
}
