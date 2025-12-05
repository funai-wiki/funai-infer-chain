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

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier, FunaiAddressExtensions};
use clarity::vm::{ClarityName, ContractName, Value};
use funai_common::codec::FunaiMessageCodec;
use funai_common::types::chainstate::{
    ConsensusHash, FunaiAddress, FunaiBlockId, FunaiPrivateKey,
};
use funai_common::types::net::PeerHost;
use funai_common::types::Address;

use super::TestRPC;
use crate::chainstate::funai::db::blocks::test::*;
use crate::chainstate::funai::db::test::instantiate_chainstate;
use crate::chainstate::funai::db::{ExtendedFunaiHeader, FunaiChainState};
use crate::chainstate::funai::{
    Error as chainstate_error, FunaiBlock, FunaiBlockHeader, FunaiMicroblock,
};
use crate::core::BLOCK_LIMIT_MAINNET_21;
use crate::net::api::getmicroblocks_unconfirmed::FunaiUnconfirmedMicroblockStream;
use crate::net::api::*;
use crate::net::connection::ConnectionOptions;
use crate::net::http::HttpChunkGenerator;
use crate::net::httpcore::{
    HttpRequestContentsExtensions, RPCRequestHandler, FunaiHttp, FunaiHttpRequest,
};
use crate::net::{ProtocolFamily, TipRequest};
use crate::util_lib::db::DBConn;

#[test]
fn test_try_parse_request() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let mut http = FunaiHttp::new(addr.clone(), &ConnectionOptions::default());

    let request = FunaiHttpRequest::new_getmicroblocks_unconfirmed(
        addr.into(),
        FunaiBlockId([0x22; 32]),
        123,
    );
    let bytes = request.try_serialize().unwrap();

    debug!("Request:\n{}\n", std::str::from_utf8(&bytes).unwrap());

    let (parsed_preamble, offset) = http.read_preamble(&bytes).unwrap();
    let mut handler = getmicroblocks_unconfirmed::RPCMicroblocksUnconfirmedRequestHandler::new();
    let mut parsed_request = http
        .handle_try_parse_request(
            &mut handler,
            &parsed_preamble.expect_request(),
            &bytes[offset..],
        )
        .unwrap();

    // consumed path args and body
    assert_eq!(handler.parent_block_id, Some(FunaiBlockId([0x22; 32])));
    assert_eq!(handler.start_sequence, Some(123));

    // parsed request consumes headers that would not be in a constructed reqeuest
    parsed_request.clear_headers();
    let (preamble, contents) = parsed_request.destruct();

    assert_eq!(&preamble, request.preamble());

    handler.restart();
    assert!(handler.parent_block_id.is_none());
    assert!(handler.start_sequence.is_none());
}

#[test]
fn test_try_make_response() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);

    let mut rpc_test = TestRPC::setup(function_name!());

    let privk = FunaiPrivateKey::from_hex(
        "eb05c83546fdd2c79f10f5ad5434a90dd28f7e3acb7c092157aa1bc3656b012c01",
    )
    .unwrap();

    let consensus_hash = ConsensusHash([0x02; 20]);
    let anchored_block_hash = BlockHeaderHash([0x03; 32]);
    let index_block_hash =
        FunaiBlockHeader::make_index_block_hash(&consensus_hash, &anchored_block_hash);

    let mut mblocks = make_sample_microblock_stream(&privk, &anchored_block_hash);
    mblocks.truncate(15);

    for mblock in mblocks.iter() {
        store_staging_microblock(
            rpc_test.peer_2.chainstate(),
            &consensus_hash,
            &anchored_block_hash,
            &mblock,
        );
    }

    let mut requests = vec![];

    // get the unconfirmed stream starting at the 5th microblock
    let request =
        FunaiHttpRequest::new_getmicroblocks_unconfirmed(addr.into(), index_block_hash.clone(), 5);
    requests.push(request);

    // get an unconfirmed stream for a non-existant block
    let request = FunaiHttpRequest::new_getmicroblocks_unconfirmed(
        addr.into(),
        FunaiBlockId([0x11; 32]),
        5,
    );
    requests.push(request);

    let mut responses = rpc_test.run(requests);

    // got the microblock stream
    let response = responses.remove(0);
    let resp = response.decode_microblocks_unconfirmed().unwrap();

    debug!("microblocks: {:?}", &resp);
    assert_eq!(resp.len(), 10);
    assert_eq!(resp, mblocks[5..].to_vec());

    // no microblock stream
    let response = responses.remove(0);
    let (preamble, body) = response.destruct();

    assert_eq!(preamble.status_code, 404);
}

#[test]
fn test_stream_unconfirmed_microblocks() {
    let mut chainstate = instantiate_chainstate(false, 0x80000000, function_name!());
    let privk = FunaiPrivateKey::from_hex(
        "eb05c83546fdd2c79f10f5ad5434a90dd28f7e3acb7c092157aa1bc3656b012c01",
    )
    .unwrap();

    let block = make_empty_coinbase_block(&privk);
    let mut mblocks = make_sample_microblock_stream(&privk, &block.block_hash());
    mblocks.truncate(15);

    let consensus_hash = ConsensusHash([2u8; 20]);
    let parent_consensus_hash = ConsensusHash([1u8; 20]);
    let index_block_header =
        FunaiBlockHeader::make_index_block_hash(&consensus_hash, &block.block_hash());

    // can't stream a non-existant microblock
    if let Err(chainstate_error::NoSuchBlockError) =
        FunaiUnconfirmedMicroblockStream::new(&chainstate, &index_block_header, 0)
    {
    } else {
        panic!("Opened nonexistant microblock");
    }

    // store microblocks to staging and stream them back
    for (i, mblock) in mblocks.iter().enumerate() {
        store_staging_microblock(
            &mut chainstate,
            &consensus_hash,
            &block.block_hash(),
            mblock,
        );

        // read back all the data we have so far, block-by-block
        let mut staging_mblocks = vec![];
        for j in 0..(i + 1) {
            let mut next_mblock_bytes = vec![];
            let mut stream =
                FunaiUnconfirmedMicroblockStream::new(&chainstate, &index_block_header, j as u16)
                    .unwrap();
            loop {
                let mut next_bytes = stream.generate_next_chunk().unwrap();
                if next_bytes.is_empty() {
                    break;
                }
                test_debug!(
                    "Got {} more bytes from staging; add to {} total",
                    next_bytes.len(),
                    next_mblock_bytes.len()
                );
                next_mblock_bytes.append(&mut next_bytes);
            }
            test_debug!("Got {} total bytes", next_mblock_bytes.len());

            // should deserialize to a microblock
            let staging_mblock =
                FunaiMicroblock::consensus_deserialize(&mut &next_mblock_bytes[..]).unwrap();
            staging_mblocks.push(staging_mblock);
        }

        assert_eq!(staging_mblocks.len(), mblocks[0..(i + 1)].len());
        for j in 0..(i + 1) {
            test_debug!("check {}", j);
            assert_eq!(staging_mblocks[j], mblocks[j])
        }

        // can also read partial stream in one shot, from any seq
        for k in 0..(i + 1) {
            test_debug!("start at seq {}", k);
            let mut staging_mblock_bytes = vec![];
            let mut stream =
                FunaiUnconfirmedMicroblockStream::new(&chainstate, &index_block_header, k as u16)
                    .unwrap();
            loop {
                let mut next_bytes = stream.generate_next_chunk().unwrap();
                if next_bytes.is_empty() {
                    break;
                }
                test_debug!(
                    "Got {} more bytes from staging; add to {} total",
                    next_bytes.len(),
                    staging_mblock_bytes.len()
                );
                staging_mblock_bytes.append(&mut next_bytes);
            }

            test_debug!("Got {} total bytes", staging_mblock_bytes.len());

            // decode stream
            let staging_mblocks = decode_microblock_stream(&staging_mblock_bytes);

            assert_eq!(staging_mblocks.len(), mblocks[k..(i + 1)].len());
            for j in 0..staging_mblocks.len() {
                test_debug!("check {}", j);
                assert_eq!(staging_mblocks[j], mblocks[k + j])
            }
        }
    }
}
