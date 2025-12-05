// Copyright (C) 2024 Funai Open Internet Foundation
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
use regex::{Captures, Regex};
use serde_json::json;
use funai_common::types::chainstate::FunaiBlockId;
use funai_common::types::net::PeerHost;
use funai_common::util::hash::Sha256Sum;

use crate::burnchains::Burnchain;
use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::coordinator::OnChainRewardSetProvider;
use crate::chainstate::funai::boot::{
    PoxVersions, RewardSet, POX_1_NAME, POX_2_NAME, POX_3_NAME, POX_4_NAME,
};
use crate::chainstate::funai::db::FunaiChainState;
use crate::chainstate::funai::Error as ChainError;
use crate::core::mempool::MemPoolDB;
use crate::net::http::{
    parse_json, Error, HttpBadRequest, HttpNotFound, HttpRequest, HttpRequestContents,
    HttpRequestPreamble, HttpResponse, HttpResponseContents, HttpResponsePayload,
    HttpResponsePreamble, HttpServerError,
};
use crate::net::httpcore::{
    HttpPreambleExtensions, HttpRequestContentsExtensions, RPCRequestHandler, FunaiHttp,
    FunaiHttpRequest, FunaiHttpResponse,
};
use crate::net::p2p::PeerNetwork;
use crate::net::{Error as NetError, FunaiNodeState, TipRequest};
use crate::util_lib::boot::boot_code_id;
use crate::util_lib::db::Error as DBError;

#[derive(Clone, Default)]
pub struct GetFunaisRequestHandler {
    cycle_number: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetFunaisResponse {
    pub funai_set: RewardSet,
}

impl GetFunaisResponse {
    pub fn load(
        sortdb: &SortitionDB,
        chainstate: &mut FunaiChainState,
        tip: &FunaiBlockId,
        burnchain: &Burnchain,
        cycle_number: u64,
    ) -> Result<Self, String> {
        let cycle_start_height = burnchain.reward_cycle_to_block_height(cycle_number);

        let pox_contract_name = burnchain
            .pox_constants
            .active_pox_contract(cycle_start_height);
        let pox_version = PoxVersions::lookup_by_name(pox_contract_name)
            .ok_or("Failed to lookup PoX contract version at tip")?;
        if !matches!(pox_version, PoxVersions::Pox4) {
            return Err(
                "Active PoX contract version at tip is Pre-PoX-4, the signer set is not fetchable"
                    .into(),
            );
        }

        let provider = OnChainRewardSetProvider::new();
        let funai_set = provider.read_reward_set_nakamoto(
            cycle_start_height,
            chainstate,
            burnchain,
            sortdb,
            tip,
            true,
        ).map_err(
            |e| format!("Could not read reward set. Prepare phase may not have started for this cycle yet. Cycle = {cycle_number}, Err = {e:?}")
        )?;

        Ok(Self { funai_set })
    }
}

/// Decode the HTTP request
impl HttpRequest for GetFunaisRequestHandler {
    fn verb(&self) -> &'static str {
        "GET"
    }

    fn path_regex(&self) -> Regex {
        Regex::new(r#"^/v2/funai_set/(?P<cycle_num>[0-9]{1,20})$"#).unwrap()
    }

    fn metrics_identifier(&self) -> &str {
        "/v2/funai_set/:cycle_num"
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
                "Invalid Http request: expected 0-length body".into(),
            ));
        }

        let Some(cycle_num_str) = captures.name("cycle_num") else {
            return Err(Error::DecodeError(
                "Missing in request path: `cycle_num`".into(),
            ));
        };
        let cycle_num = u64::from_str_radix(cycle_num_str.into(), 10)
            .map_err(|e| Error::DecodeError(format!("Failed to parse cycle number: {e}")))?;

        self.cycle_number = Some(cycle_num);

        Ok(HttpRequestContents::new().query_string(query))
    }
}

impl RPCRequestHandler for GetFunaisRequestHandler {
    /// Reset internal state
    fn restart(&mut self) {
        self.cycle_number = None;
    }

    /// Make the response
    fn try_handle_request(
        &mut self,
        preamble: HttpRequestPreamble,
        contents: HttpRequestContents,
        node: &mut FunaiNodeState,
    ) -> Result<(HttpResponsePreamble, HttpResponseContents), NetError> {
        let tip = match node.load_funai_chain_tip(&preamble, &contents) {
            Ok(tip) => tip,
            Err(error_resp) => {
                return error_resp.try_into_contents().map_err(NetError::from);
            }
        };
        let Some(cycle_number) = self.cycle_number.clone() else {
            return FunaiHttpResponse::new_error(
                    &preamble,
                    &HttpBadRequest::new_json(json!({"response": "error", "err_msg": "Failed to read cycle number in request"}))
                )
                    .try_into_contents()
                    .map_err(NetError::from);
        };

        let funai_response =
            node.with_node_state(|network, sortdb, chainstate, _mempool, _rpc_args| {
                GetFunaisResponse::load(
                    sortdb,
                    chainstate,
                    &tip,
                    network.get_burnchain(),
                    cycle_number,
                )
            });

        let response = match funai_response {
            Ok(response) => response,
            Err(err_str) => {
                return FunaiHttpResponse::new_error(
                    &preamble,
                    &HttpBadRequest::new_json(json!({"response": "error", "err_msg": err_str})),
                )
                .try_into_contents()
                .map_err(NetError::from)
            }
        };

        let mut preamble = HttpResponsePreamble::ok_json(&preamble);
        preamble.set_canonical_funai_tip_height(Some(node.canonical_funai_tip_height()));
        let body = HttpResponseContents::try_from_json(&response)?;
        Ok((preamble, body))
    }
}

impl HttpResponse for GetFunaisRequestHandler {
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        let response: GetFunaisResponse = parse_json(preamble, body)?;
        Ok(HttpResponsePayload::try_from_json(response)?)
    }
}

impl FunaiHttpRequest {
    /// Make a new getinfo request to this endpoint
    pub fn new_getfunais(
        host: PeerHost,
        cycle_num: u64,
        tip_req: TipRequest,
    ) -> FunaiHttpRequest {
        FunaiHttpRequest::new_for_peer(
            host,
            "GET".into(),
            format!("/v2/funai_set/{cycle_num}"),
            HttpRequestContents::new().for_tip(tip_req),
        )
        .expect("FATAL: failed to construct request from infallible data")
    }
}

impl FunaiHttpResponse {
    pub fn decode_funai_set(self) -> Result<GetFunaisResponse, NetError> {
        let contents = self.get_http_payload_ok()?;
        let response_json: serde_json::Value = contents.try_into()?;
        let response: GetFunaisResponse = serde_json::from_value(response_json)
            .map_err(|_e| Error::DecodeError("Failed to decode JSON".to_string()))?;
        Ok(response)
    }
}
