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
use funai_common::types::chainstate::{
    BlockHeaderHash, ConsensusHash, FunaiBlockId, FunaiPublicKey,
};
use funai_common::types::net::PeerHost;
use funai_common::types::FunaiPublicKeyBuffer;
use funai_common::util::hash::{Hash160, Sha256Sum};

use crate::burnchains::affirmation::AffirmationMap;
use crate::burnchains::Txid;
use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::funai::db::FunaiChainState;
use crate::core::mempool::MemPoolDB;
use crate::net::http::{
    parse_json, Error, HttpRequest, HttpRequestContents, HttpRequestPreamble, HttpResponse,
    HttpResponseContents, HttpResponsePayload, HttpResponsePreamble,
};
use crate::net::httpcore::{
    HttpPreambleExtensions, RPCRequestHandler, FunaiHttpRequest, FunaiHttpResponse,
};
use crate::net::p2p::PeerNetwork;
use crate::net::{Error as NetError, FunaiNodeState};
use crate::version_string;

/// The request to GET /v2/info
#[derive(Clone)]
pub struct RPCPeerInfoRequestHandler {}
impl RPCPeerInfoRequestHandler {
    pub fn new() -> Self {
        Self {}
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RPCAffirmationData {
    pub heaviest: AffirmationMap,
    pub funai_tip: AffirmationMap,
    pub sortition_tip: AffirmationMap,
    pub tentative_best: AffirmationMap,
}

/// Information about the last PoX anchor block
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RPCLastPoxAnchorData {
    pub anchor_block_hash: BlockHeaderHash,
    pub anchor_block_txid: Txid,
}

/// The response to GET /v2/info
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RPCPeerInfoData {
    pub peer_version: u32,
    pub pox_consensus: ConsensusHash,
    pub burn_block_height: u64,
    pub stable_pox_consensus: ConsensusHash,
    pub stable_burn_block_height: u64,
    pub server_version: String,
    pub network_id: u32,
    pub parent_network_id: u32,
    pub funai_tip_height: u64,
    pub funai_tip: BlockHeaderHash,
    pub funai_tip_consensus_hash: ConsensusHash,
    pub genesis_chainstate_hash: Sha256Sum,
    pub unanchored_tip: Option<FunaiBlockId>,
    pub unanchored_seq: Option<u16>,
    pub exit_at_block_height: Option<u64>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_public_key: Option<FunaiPublicKeyBuffer>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_public_key_hash: Option<Hash160>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub affirmations: Option<RPCAffirmationData>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_pox_anchor: Option<RPCLastPoxAnchorData>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub funaidbs: Option<Vec<String>>,
}

impl RPCPeerInfoData {
    pub fn from_network(
        network: &PeerNetwork,
        chainstate: &FunaiChainState,
        exit_at_block_height: Option<u64>,
        genesis_chainstate_hash: &Sha256Sum,
    ) -> RPCPeerInfoData {
        let server_version = version_string(
            "funai-node",
            option_env!("STACKS_NODE_VERSION")
                .or(option_env!("CARGO_PKG_VERSION"))
                .unwrap_or("0.0.0.0"),
        );
        let (unconfirmed_tip, unconfirmed_seq) = match chainstate.unconfirmed_state {
            Some(ref unconfirmed) => {
                if unconfirmed.num_mined_txs() > 0 {
                    (
                        Some(unconfirmed.unconfirmed_chain_tip.clone()),
                        Some(unconfirmed.last_mblock_seq),
                    )
                } else {
                    (None, None)
                }
            }
            None => (None, None),
        };

        let public_key = FunaiPublicKey::from_private(&network.get_local_peer().private_key);
        let public_key_buf = FunaiPublicKeyBuffer::from_public_key(&public_key);
        let public_key_hash = Hash160::from_node_public_key(&public_key);
        let funaidb_contract_ids = network.get_local_peer().funai_dbs.clone();

        RPCPeerInfoData {
            peer_version: network.burnchain.peer_version,
            pox_consensus: network.burnchain_tip.consensus_hash.clone(),
            burn_block_height: network.chain_view.burn_block_height,
            stable_pox_consensus: network.chain_view_stable_consensus_hash.clone(),
            stable_burn_block_height: network.chain_view.burn_stable_block_height,
            server_version,
            network_id: network.local_peer.network_id,
            parent_network_id: network.local_peer.parent_network_id,
            funai_tip_height: network.funai_tip.2,
            funai_tip: network.funai_tip.1.clone(),
            funai_tip_consensus_hash: network.funai_tip.0.clone(),
            unanchored_tip: unconfirmed_tip,
            unanchored_seq: unconfirmed_seq,
            exit_at_block_height: exit_at_block_height,
            genesis_chainstate_hash: genesis_chainstate_hash.clone(),
            node_public_key: Some(public_key_buf),
            node_public_key_hash: Some(public_key_hash),
            affirmations: Some(RPCAffirmationData {
                heaviest: network.heaviest_affirmation_map.clone(),
                funai_tip: network.funai_tip_affirmation_map.clone(),
                sortition_tip: network.sortition_tip_affirmation_map.clone(),
                tentative_best: network.tentative_best_affirmation_map.clone(),
            }),
            last_pox_anchor: Some(RPCLastPoxAnchorData {
                anchor_block_hash: network.last_anchor_block_hash.clone(),
                anchor_block_txid: network.last_anchor_block_txid.clone(),
            }),
            funaidbs: Some(
                funaidb_contract_ids
                    .into_iter()
                    .map(|cid| format!("{}", cid))
                    .collect(),
            ),
        }
    }
}

/// Decode the HTTP request
impl HttpRequest for RPCPeerInfoRequestHandler {
    fn verb(&self) -> &'static str {
        "GET"
    }

    fn path_regex(&self) -> Regex {
        Regex::new(r#"^/v2/info$"#).unwrap()
    }

    fn metrics_identifier(&self) -> &str {
        "/v2/info"
    }

    /// Try to decode this request.
    /// There's nothing to load here, so just make sure the request is well-formed.
    fn try_parse_request(
        &mut self,
        preamble: &HttpRequestPreamble,
        _captures: &Captures,
        query: Option<&str>,
        _body: &[u8],
    ) -> Result<HttpRequestContents, Error> {
        if preamble.get_content_length() != 0 {
            return Err(Error::DecodeError(
                "Invalid Http request: expected 0-length body for GetInfo".to_string(),
            ));
        }
        Ok(HttpRequestContents::new().query_string(query))
    }
}

impl RPCRequestHandler for RPCPeerInfoRequestHandler {
    /// Reset internal state
    fn restart(&mut self) {}

    /// Make the response
    fn try_handle_request(
        &mut self,
        preamble: HttpRequestPreamble,
        _contents: HttpRequestContents,
        node: &mut FunaiNodeState,
    ) -> Result<(HttpResponsePreamble, HttpResponseContents), NetError> {
        let rpc_peer_info =
            node.with_node_state(|network, _sortdb, chainstate, _mempool, rpc_args| {
                RPCPeerInfoData::from_network(
                    network,
                    chainstate,
                    rpc_args.exit_at_block_height.clone(),
                    &rpc_args.genesis_chainstate_hash,
                )
            });
        let mut preamble = HttpResponsePreamble::ok_json(&preamble);
        preamble.set_canonical_funai_tip_height(Some(node.canonical_funai_tip_height()));
        let body = HttpResponseContents::try_from_json(&rpc_peer_info)?;
        Ok((preamble, body))
    }
}

/// Decode the HTTP response
impl HttpResponse for RPCPeerInfoRequestHandler {
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        let peer_info: RPCPeerInfoData = parse_json(preamble, body)?;
        Ok(HttpResponsePayload::try_from_json(peer_info)?)
    }
}

impl FunaiHttpRequest {
    /// Make a new getinfo request to this endpoint
    pub fn new_getinfo(host: PeerHost, funai_height: Option<u32>) -> FunaiHttpRequest {
        let mut req = FunaiHttpRequest::new_for_peer(
            host,
            "GET".into(),
            "/v2/info".into(),
            HttpRequestContents::new(),
        )
        .expect("FATAL: failed to construct request from infallible data");
        req.preamble_mut()
            .set_canonical_funai_tip_height(funai_height);
        req
    }
}

impl FunaiHttpResponse {
    pub fn decode_peer_info(self) -> Result<RPCPeerInfoData, NetError> {
        let contents = self.get_http_payload_ok()?;
        let response_json: serde_json::Value = contents.try_into()?;
        let peer_info: RPCPeerInfoData = serde_json::from_value(response_json)
            .map_err(|_e| Error::DecodeError("Failed to decode JSON".to_string()))?;
        Ok(peer_info)
    }
}
