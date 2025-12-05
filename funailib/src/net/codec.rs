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

use std::collections::HashSet;
use std::io::prelude::*;
use std::io::Read;
use std::{io, mem};

use clarity::vm::types::{QualifiedContractIdentifier, StandardPrincipalData};
use clarity::vm::ContractName;
use rand;
use rand::Rng;
use sha2::{Digest, Sha512_256};
use funai_common::bitvec::BitVec;
use funai_common::codec::{
    read_next, read_next_at_most, read_next_exact, write_next, Error as codec_error,
    FunaiMessageCodec, MAX_MESSAGE_LEN, MAX_RELAYERS_LEN, PREAMBLE_ENCODED_SIZE,
};
use funai_common::types::chainstate::{BlockHeaderHash, BurnchainHeaderHash};
use funai_common::types::net::PeerAddress;
use funai_common::types::FunaiPublicKeyBuffer;
use funai_common::util::hash::{to_hex, DoubleSha256, Hash160, MerkleHashFunc};
use funai_common::util::log;
use funai_common::util::retry::BoundReader;
use funai_common::util::secp256k1::{
    MessageSignature, Secp256k1PrivateKey, Secp256k1PublicKey, MESSAGE_SIGNATURE_ENCODED_SIZE,
};

use crate::burnchains::{BurnchainView, PrivateKey, PublicKey};
use crate::chainstate::burn::ConsensusHash;
use crate::chainstate::funai::{
    FunaiBlock, FunaiMicroblock, FunaiPublicKey, FunaiTransaction, MAX_BLOCK_LEN,
};
use crate::core::PEER_VERSION_TESTNET;
use crate::net::db::LocalPeer;
use crate::net::{Error as net_error, *};

pub fn bitvec_len(bitlen: u16) -> u16 {
    (bitlen / 8) + (if bitlen % 8 != 0 { 1 } else { 0 })
}

impl Preamble {
    /// Make an empty preamble with the given version and fork-set identifier, and payload length.
    pub fn new(
        peer_version: u32,
        network_id: u32,
        block_height: u64,
        burn_block_hash: &BurnchainHeaderHash,
        stable_block_height: u64,
        stable_burn_block_hash: &BurnchainHeaderHash,
        payload_len: u32,
    ) -> Preamble {
        Preamble {
            peer_version: peer_version,
            network_id: network_id,
            seq: 0,
            burn_block_height: block_height,
            burn_block_hash: burn_block_hash.clone(),
            burn_stable_block_height: stable_block_height,
            burn_stable_block_hash: stable_burn_block_hash.clone(),
            additional_data: 0,
            signature: MessageSignature::empty(),
            payload_len: payload_len,
        }
    }

    /// Given the serialized message type and bits, sign the resulting message and store the
    /// signature.  message_bits includes the relayers, payload type, and payload.
    pub fn sign(
        &mut self,
        message_bits: &[u8],
        privkey: &Secp256k1PrivateKey,
    ) -> Result<(), net_error> {
        let mut digest_bits = [0u8; 32];
        let mut sha2 = Sha512_256::new();

        // serialize the premable with a blank signature
        let old_signature = self.signature.clone();
        self.signature = MessageSignature::empty();

        let mut preamble_bits = vec![];
        self.consensus_serialize(&mut preamble_bits)?;
        self.signature = old_signature;

        sha2.update(&preamble_bits[..]);
        sha2.update(message_bits);

        digest_bits.copy_from_slice(sha2.finalize().as_slice());

        let sig = privkey
            .sign(&digest_bits)
            .map_err(|se| net_error::SigningError(se.to_string()))?;

        self.signature = sig;
        Ok(())
    }

    /// Given the serialized message type and bits, verify the signature.
    /// message_bits includes the relayers, payload type, and payload
    pub fn verify(
        &mut self,
        message_bits: &[u8],
        pubkey: &Secp256k1PublicKey,
    ) -> Result<(), net_error> {
        let mut digest_bits = [0u8; 32];
        let mut sha2 = Sha512_256::new();

        // serialize the preamble with a blank signature
        let sig_bits = self.signature.clone();
        self.signature = MessageSignature::empty();

        let mut preamble_bits = vec![];
        self.consensus_serialize(&mut preamble_bits)?;
        self.signature = sig_bits;

        sha2.update(&preamble_bits[..]);
        sha2.update(message_bits);

        digest_bits.copy_from_slice(sha2.finalize().as_slice());

        let res = pubkey
            .verify(&digest_bits, &self.signature)
            .map_err(|_ve| net_error::VerifyingError("Failed to verify signature".to_string()))?;

        if res {
            Ok(())
        } else {
            Err(net_error::VerifyingError(
                "Invalid message signature".to_string(),
            ))
        }
    }
}

impl FunaiMessageCodec for Preamble {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &self.peer_version)?;
        write_next(fd, &self.network_id)?;
        write_next(fd, &self.seq)?;
        write_next(fd, &self.burn_block_height)?;
        write_next(fd, &self.burn_block_hash)?;
        write_next(fd, &self.burn_stable_block_height)?;
        write_next(fd, &self.burn_stable_block_hash)?;
        write_next(fd, &self.additional_data)?;
        write_next(fd, &self.signature)?;
        write_next(fd, &self.payload_len)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<Preamble, codec_error> {
        let peer_version: u32 = read_next(fd)?;
        let network_id: u32 = read_next(fd)?;
        let seq: u32 = read_next(fd)?;
        let burn_block_height: u64 = read_next(fd)?;
        let burn_block_hash: BurnchainHeaderHash = read_next(fd)?;
        let burn_stable_block_height: u64 = read_next(fd)?;
        let burn_stable_block_hash: BurnchainHeaderHash = read_next(fd)?;
        let additional_data: u32 = read_next(fd)?;
        let signature: MessageSignature = read_next(fd)?;
        let payload_len: u32 = read_next(fd)?;

        // minimum is 5 bytes -- a zero-length vector (4 bytes of 0) plus a type identifier (1 byte)
        if payload_len < 5 {
            test_debug!("Payload len is too small: {}", payload_len);
            return Err(codec_error::DeserializeError(format!(
                "Payload len is too small: {}",
                payload_len
            )));
        }

        if payload_len >= MAX_MESSAGE_LEN {
            test_debug!("Payload len is too big: {}", payload_len);
            return Err(codec_error::DeserializeError(format!(
                "Payload len is too big: {}",
                payload_len
            )));
        }

        if burn_block_height <= burn_stable_block_height {
            test_debug!(
                "burn block height {} <= burn stable block height {}",
                burn_block_height,
                burn_stable_block_height
            );
            return Err(codec_error::DeserializeError(format!(
                "Burn block height {} <= burn stable block height {}",
                burn_block_height, burn_stable_block_height
            )));
        }

        Ok(Preamble {
            peer_version,
            network_id,
            seq,
            burn_block_height,
            burn_block_hash,
            burn_stable_block_height,
            burn_stable_block_hash,
            additional_data,
            signature,
            payload_len,
        })
    }
}

impl FunaiMessageCodec for GetBlocksInv {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &self.consensus_hash)?;
        write_next(fd, &self.num_blocks)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<GetBlocksInv, codec_error> {
        let consensus_hash: ConsensusHash = read_next(fd)?;
        let num_blocks: u16 = read_next(fd)?;
        if num_blocks == 0 {
            return Err(codec_error::DeserializeError(
                "GetBlocksInv must request at least one block".to_string(),
            ));
        }

        Ok(GetBlocksInv {
            consensus_hash: consensus_hash,
            num_blocks: num_blocks,
        })
    }
}

impl FunaiMessageCodec for BlocksInvData {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &self.bitlen)?;
        write_next(fd, &self.block_bitvec)?;
        write_next(fd, &self.microblocks_bitvec)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<BlocksInvData, codec_error> {
        let bitlen: u16 = read_next(fd)?;
        if bitlen == 0 {
            return Err(codec_error::DeserializeError(
                "BlocksInv must contain at least one block/microblock bit".to_string(),
            ));
        }

        let block_bitvec: Vec<u8> = read_next_exact::<_, u8>(fd, bitvec_len(bitlen).into())?;
        let microblocks_bitvec: Vec<u8> = read_next_exact::<_, u8>(fd, bitvec_len(bitlen).into())?;

        Ok(BlocksInvData {
            bitlen,
            block_bitvec,
            microblocks_bitvec,
        })
    }
}

impl BlocksInvData {
    pub fn empty() -> BlocksInvData {
        BlocksInvData {
            bitlen: 0,
            block_bitvec: vec![],
            microblocks_bitvec: vec![],
        }
    }

    pub fn compress_bools(bits: &Vec<bool>) -> Vec<u8> {
        let bvl: u16 = bits
            .len()
            .try_into()
            .expect("FATAL: tried to compress more than u16::MAX bools");
        let mut bitvec = vec![0u8; bitvec_len(bvl) as usize];
        for (i, bit) in bits.iter().enumerate() {
            if *bit {
                bitvec[i / 8] |= 1u8 << (i % 8);
            }
        }
        bitvec
    }

    pub fn has_ith_block(&self, block_index: u16) -> bool {
        if block_index >= self.bitlen {
            return false;
        }

        let idx = block_index / 8;
        let bit = block_index % 8;
        (self.block_bitvec[idx as usize] & (1 << bit)) != 0
    }

    pub fn has_ith_microblock_stream(&self, block_index: u16) -> bool {
        if block_index >= self.bitlen {
            return false;
        }

        let idx = block_index / 8;
        let bit = block_index % 8;
        (self.microblocks_bitvec[idx as usize] & (1 << bit)) != 0
    }
}

impl FunaiMessageCodec for GetNakamotoInvData {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &self.consensus_hash)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<Self, codec_error> {
        let consensus_hash: ConsensusHash = read_next(fd)?;
        Ok(Self { consensus_hash })
    }
}

impl FunaiMessageCodec for NakamotoInvData {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &self.tenures)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<Self, codec_error> {
        Ok(Self {
            tenures: read_next(fd)?,
        })
    }
}

impl NakamotoInvData {
    pub fn try_from(bits: &[bool]) -> Result<Self, codec_error> {
        Ok(Self {
            tenures: BitVec::<2100>::try_from(bits).map_err(|e| {
                codec_error::SerializeError(format!(
                    "Could not serialize vec of {} bools: {}",
                    bits.len(),
                    e
                ))
            })?,
        })
    }

    pub fn has_ith_tenure(&self, tenure_index: u16) -> bool {
        self.tenures.get(tenure_index).unwrap_or(false)
    }
}

impl FunaiMessageCodec for GetPoxInv {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &self.consensus_hash)?;
        write_next(fd, &self.num_cycles)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<GetPoxInv, codec_error> {
        let ch: ConsensusHash = read_next(fd)?;
        let num_rcs: u16 = read_next(fd)?;
        if num_rcs == 0 || num_rcs as u64 > GETPOXINV_MAX_BITLEN {
            return Err(codec_error::DeserializeError(
                "Invalid GetPoxInv bitlen".to_string(),
            ));
        }
        Ok(GetPoxInv {
            consensus_hash: ch,
            num_cycles: num_rcs,
        })
    }
}

impl PoxInvData {
    pub fn has_ith_reward_cycle(&self, index: u16) -> bool {
        if index >= self.bitlen {
            return false;
        }

        let idx = index / 8;
        let bit = index % 8;
        (self.pox_bitvec[idx as usize] & (1 << bit)) != 0
    }
}

impl FunaiMessageCodec for PoxInvData {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &self.bitlen)?;
        write_next(fd, &self.pox_bitvec)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<PoxInvData, codec_error> {
        let bitlen: u16 = read_next(fd)?;
        if bitlen == 0 || (bitlen as u64) > GETPOXINV_MAX_BITLEN {
            return Err(codec_error::DeserializeError(
                "Invalid PoxInvData bitlen".to_string(),
            ));
        }

        let pox_bitvec: Vec<u8> = read_next_exact::<_, u8>(fd, bitvec_len(bitlen).into())?;
        Ok(PoxInvData {
            bitlen: bitlen,
            pox_bitvec: pox_bitvec,
        })
    }
}

impl FunaiMessageCodec for BlocksAvailableData {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &self.available)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<BlocksAvailableData, codec_error> {
        let available: Vec<(ConsensusHash, BurnchainHeaderHash)> =
            read_next_at_most::<_, (ConsensusHash, BurnchainHeaderHash)>(
                fd,
                BLOCKS_AVAILABLE_MAX_LEN,
            )?;
        Ok(BlocksAvailableData {
            available: available,
        })
    }
}

impl BlocksAvailableData {
    pub fn new() -> BlocksAvailableData {
        BlocksAvailableData { available: vec![] }
    }

    pub fn try_push(
        &mut self,
        ch: ConsensusHash,
        bhh: BurnchainHeaderHash,
    ) -> Result<(), net_error> {
        if self.available.len() < BLOCKS_AVAILABLE_MAX_LEN as usize {
            self.available.push((ch, bhh));
            return Ok(());
        } else {
            return Err(net_error::InvalidMessage);
        }
    }
}

impl FunaiMessageCodec for BlocksDatum {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &self.0)?;
        write_next(fd, &self.1)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<BlocksDatum, codec_error> {
        let ch: ConsensusHash = read_next(fd)?;
        let block = {
            let mut bound_read = BoundReader::from_reader(fd, MAX_BLOCK_LEN as u64);
            read_next(&mut bound_read)
        }?;

        Ok(BlocksDatum(ch, block))
    }
}

impl BlocksData {
    pub fn new() -> BlocksData {
        BlocksData { blocks: vec![] }
    }

    pub fn push(&mut self, ch: ConsensusHash, block: FunaiBlock) -> () {
        self.blocks.push(BlocksDatum(ch, block))
    }
}

impl FunaiMessageCodec for BlocksData {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &self.blocks)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<BlocksData, codec_error> {
        let blocks: Vec<BlocksDatum> = {
            // loose upper-bound
            let mut bound_read = BoundReader::from_reader(fd, MAX_MESSAGE_LEN as u64);
            read_next_at_most::<_, BlocksDatum>(&mut bound_read, BLOCKS_PUSHED_MAX)
        }?;

        // only valid if there are no dups
        let mut present = HashSet::new();
        for BlocksDatum(consensus_hash, _block) in blocks.iter() {
            if present.contains(consensus_hash) {
                // no dups allowed
                return Err(codec_error::DeserializeError(
                    "Invalid BlocksData: duplicate block".to_string(),
                ));
            }

            present.insert(consensus_hash.clone());
        }

        Ok(BlocksData { blocks })
    }
}

impl FunaiMessageCodec for MicroblocksData {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &self.index_anchor_block)?;
        write_next(fd, &self.microblocks)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<MicroblocksData, codec_error> {
        let index_anchor_block = read_next(fd)?;
        let microblocks: Vec<FunaiMicroblock> = {
            // loose upper-bound
            let mut bound_read = BoundReader::from_reader(fd, MAX_MESSAGE_LEN as u64);
            read_next(&mut bound_read)
        }?;

        Ok(MicroblocksData {
            index_anchor_block,
            microblocks,
        })
    }
}

impl NeighborAddress {
    pub fn from_neighbor(n: &Neighbor) -> NeighborAddress {
        NeighborAddress {
            addrbytes: n.addr.addrbytes.clone(),
            port: n.addr.port,
            public_key_hash: Hash160::from_node_public_key(&n.public_key),
        }
    }
}

impl FunaiMessageCodec for NeighborAddress {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &self.addrbytes)?;
        write_next(fd, &self.port)?;
        write_next(fd, &self.public_key_hash)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<NeighborAddress, codec_error> {
        let addrbytes: PeerAddress = read_next(fd)?;
        let port: u16 = read_next(fd)?;
        let public_key_hash: Hash160 = read_next(fd)?;

        Ok(NeighborAddress {
            addrbytes,
            port,
            public_key_hash,
        })
    }
}

impl FunaiMessageCodec for NeighborsData {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &self.neighbors)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<NeighborsData, codec_error> {
        // don't allow list of more than the pre-set number of neighbors
        let neighbors: Vec<NeighborAddress> =
            read_next_at_most::<_, NeighborAddress>(fd, MAX_NEIGHBORS_DATA_LEN)?;
        Ok(NeighborsData { neighbors })
    }
}

impl HandshakeData {
    pub fn from_local_peer(local_peer: &LocalPeer) -> HandshakeData {
        let (addrbytes, port) = match local_peer.public_ip_address {
            Some((ref public_addrbytes, ref port)) => (public_addrbytes.clone(), *port),
            None => (local_peer.addrbytes.clone(), local_peer.port),
        };

        // transmit the empty string if our data URL compels us to bind to the anynet address
        let data_url = if local_peer.data_url.has_routable_host() {
            local_peer.data_url.clone()
        } else if let Some(data_port) = local_peer.data_url.get_port() {
            // deduce from public IP
            UrlString::try_from(format!("http://{}", addrbytes.to_socketaddr(data_port)).as_str())
                .unwrap()
        } else {
            // unroutable, so don't bother
            UrlString::try_from("").unwrap()
        };

        HandshakeData {
            addrbytes: addrbytes,
            port: port,
            services: local_peer.services,
            node_public_key: FunaiPublicKeyBuffer::from_public_key(
                &Secp256k1PublicKey::from_private(&local_peer.private_key),
            ),
            expire_block_height: local_peer.private_key_expire,
            data_url: data_url,
        }
    }
}

impl FunaiMessageCodec for HandshakeData {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &self.addrbytes)?;
        write_next(fd, &self.port)?;
        write_next(fd, &self.services)?;
        write_next(fd, &self.node_public_key)?;
        write_next(fd, &self.expire_block_height)?;
        write_next(fd, &self.data_url)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<HandshakeData, codec_error> {
        let addrbytes: PeerAddress = read_next(fd)?;
        let port: u16 = read_next(fd)?;
        if port == 0 {
            return Err(codec_error::DeserializeError(
                "Invalid handshake data: port is 0".to_string(),
            ));
        }

        let services: u16 = read_next(fd)?;
        let node_public_key: FunaiPublicKeyBuffer = read_next(fd)?;
        let expire_block_height: u64 = read_next(fd)?;
        let data_url: UrlString = read_next(fd)?;
        Ok(HandshakeData {
            addrbytes,
            port,
            services,
            node_public_key,
            expire_block_height,
            data_url,
        })
    }
}

impl HandshakeAcceptData {
    pub fn new(local_peer: &LocalPeer, heartbeat_interval: u32) -> HandshakeAcceptData {
        HandshakeAcceptData {
            handshake: HandshakeData::from_local_peer(local_peer),
            heartbeat_interval: heartbeat_interval,
        }
    }
}

impl FunaiMessageCodec for HandshakeAcceptData {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &self.handshake)?;
        write_next(fd, &self.heartbeat_interval)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<HandshakeAcceptData, codec_error> {
        let handshake: HandshakeData = read_next(fd)?;
        let heartbeat_interval: u32 = read_next(fd)?;
        Ok(HandshakeAcceptData {
            handshake,
            heartbeat_interval,
        })
    }
}

impl NackData {
    pub fn new(error_code: u32) -> NackData {
        NackData { error_code }
    }
}

impl FunaiMessageCodec for NackData {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &self.error_code)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<NackData, codec_error> {
        let error_code: u32 = read_next(fd)?;
        Ok(NackData { error_code })
    }
}

impl PingData {
    pub fn new() -> PingData {
        let mut rng = rand::thread_rng();
        let n = rng.gen();
        PingData { nonce: n }
    }
}

impl FunaiMessageCodec for PingData {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &self.nonce)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<PingData, codec_error> {
        let nonce: u32 = read_next(fd)?;
        Ok(PingData { nonce })
    }
}

impl PongData {
    pub fn from_ping(p: &PingData) -> PongData {
        PongData { nonce: p.nonce }
    }
}

impl FunaiMessageCodec for PongData {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &self.nonce)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<PongData, codec_error> {
        let nonce: u32 = read_next(fd)?;
        Ok(PongData { nonce })
    }
}

impl FunaiMessageCodec for NatPunchData {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &self.addrbytes)?;
        write_next(fd, &self.port)?;
        write_next(fd, &self.nonce)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<NatPunchData, codec_error> {
        let addrbytes: PeerAddress = read_next(fd)?;
        let port: u16 = read_next(fd)?;
        let nonce: u32 = read_next(fd)?;
        Ok(NatPunchData {
            addrbytes,
            port,
            nonce,
        })
    }
}

fn contract_id_consensus_serialize<W: Write>(
    fd: &mut W,
    cid: &QualifiedContractIdentifier,
) -> Result<(), codec_error> {
    let addr = &cid.issuer;
    let name = &cid.name;
    write_next(fd, &addr.0)?;
    write_next(fd, &addr.1)?;
    write_next(fd, name)?;
    Ok(())
}

fn contract_id_consensus_deserialize<R: Read>(
    fd: &mut R,
) -> Result<QualifiedContractIdentifier, codec_error> {
    let version: u8 = read_next(fd)?;
    let bytes: [u8; 20] = read_next(fd)?;
    let name: ContractName = read_next(fd)?;
    let qn = QualifiedContractIdentifier::new(
        FunaiAddress {
            version,
            bytes: Hash160(bytes),
        }
        .into(),
        name,
    );
    Ok(qn)
}

impl FunaiMessageCodec for FunaiDBHandshakeData {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        if self.smart_contracts.len() > 256 {
            return Err(codec_error::ArrayTooLong);
        }
        // force no more than 256 names in the protocol
        let len_u8: u8 = self.smart_contracts.len().try_into().expect("Unreachable");
        write_next(fd, &self.rc_consensus_hash)?;
        write_next(fd, &len_u8)?;
        for cid in self.smart_contracts.iter() {
            contract_id_consensus_serialize(fd, cid)?;
        }
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<FunaiDBHandshakeData, codec_error> {
        let rc_consensus_hash = read_next(fd)?;
        let len_u8: u8 = read_next(fd)?;
        let mut smart_contracts = Vec::with_capacity(len_u8 as usize);
        for _ in 0..len_u8 {
            let cid: QualifiedContractIdentifier = contract_id_consensus_deserialize(fd)?;
            smart_contracts.push(cid);
        }
        Ok(FunaiDBHandshakeData {
            rc_consensus_hash,
            smart_contracts,
        })
    }
}

impl FunaiMessageCodec for FunaiDBGetChunkInvData {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        contract_id_consensus_serialize(fd, &self.contract_id)?;
        write_next(fd, &self.rc_consensus_hash)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<FunaiDBGetChunkInvData, codec_error> {
        let contract_id: QualifiedContractIdentifier = contract_id_consensus_deserialize(fd)?;
        let rc_consensus_hash: ConsensusHash = read_next(fd)?;
        Ok(FunaiDBGetChunkInvData {
            contract_id,
            rc_consensus_hash,
        })
    }
}

impl FunaiMessageCodec for FunaiDBChunkInvData {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        if self.slot_versions.len() > (funaidb::STACKERDB_INV_MAX as usize) {
            return Err(codec_error::ArrayTooLong);
        }
        write_next(fd, &self.slot_versions)?;
        write_next(fd, &self.num_outbound_replicas)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<FunaiDBChunkInvData, codec_error> {
        let slot_versions: Vec<u32> = read_next_at_most(fd, funaidb::STACKERDB_INV_MAX.into())?;
        let num_outbound_replicas: u32 = read_next(fd)?;
        Ok(FunaiDBChunkInvData {
            slot_versions,
            num_outbound_replicas,
        })
    }
}

impl FunaiMessageCodec for FunaiDBGetChunkData {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        contract_id_consensus_serialize(fd, &self.contract_id)?;
        write_next(fd, &self.rc_consensus_hash)?;
        write_next(fd, &self.slot_id)?;
        write_next(fd, &self.slot_version)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<FunaiDBGetChunkData, codec_error> {
        let contract_id: QualifiedContractIdentifier = contract_id_consensus_deserialize(fd)?;
        let rc_consensus_hash: ConsensusHash = read_next(fd)?;
        let slot_id: u32 = read_next(fd)?;
        let slot_version: u32 = read_next(fd)?;
        Ok(FunaiDBGetChunkData {
            contract_id,
            rc_consensus_hash,
            slot_id,
            slot_version,
        })
    }
}

impl FunaiMessageCodec for FunaiDBPushChunkData {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        contract_id_consensus_serialize(fd, &self.contract_id)?;
        write_next(fd, &self.rc_consensus_hash)?;
        write_next(fd, &self.chunk_data)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<FunaiDBPushChunkData, codec_error> {
        let contract_id: QualifiedContractIdentifier = contract_id_consensus_deserialize(fd)?;
        let rc_consensus_hash: ConsensusHash = read_next(fd)?;
        let chunk_data: FunaiDBChunkData = read_next(fd)?;
        Ok(FunaiDBPushChunkData {
            contract_id,
            rc_consensus_hash,
            chunk_data,
        })
    }
}

impl FunaiMessageCodec for RelayData {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &self.peer)?;
        write_next(fd, &self.seq)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<RelayData, codec_error> {
        let peer: NeighborAddress = read_next(fd)?;
        let seq: u32 = read_next(fd)?;
        Ok(RelayData { peer, seq })
    }
}

impl FunaiMessageType {
    pub fn get_message_id(&self) -> FunaiMessageID {
        match *self {
            FunaiMessageType::Handshake(ref _m) => FunaiMessageID::Handshake,
            FunaiMessageType::HandshakeAccept(ref _m) => FunaiMessageID::HandshakeAccept,
            FunaiMessageType::HandshakeReject => FunaiMessageID::HandshakeReject,
            FunaiMessageType::GetNeighbors => FunaiMessageID::GetNeighbors,
            FunaiMessageType::Neighbors(ref _m) => FunaiMessageID::Neighbors,
            FunaiMessageType::GetPoxInv(ref _m) => FunaiMessageID::GetPoxInv,
            FunaiMessageType::PoxInv(ref _m) => FunaiMessageID::PoxInv,
            FunaiMessageType::GetBlocksInv(ref _m) => FunaiMessageID::GetBlocksInv,
            FunaiMessageType::BlocksInv(ref _m) => FunaiMessageID::BlocksInv,
            FunaiMessageType::BlocksAvailable(ref _m) => FunaiMessageID::BlocksAvailable,
            FunaiMessageType::MicroblocksAvailable(ref _m) => {
                FunaiMessageID::MicroblocksAvailable
            }
            FunaiMessageType::Blocks(ref _m) => FunaiMessageID::Blocks,
            FunaiMessageType::Microblocks(ref _m) => FunaiMessageID::Microblocks,
            FunaiMessageType::Transaction(ref _m) => FunaiMessageID::Transaction,
            FunaiMessageType::Nack(ref _m) => FunaiMessageID::Nack,
            FunaiMessageType::Ping(ref _m) => FunaiMessageID::Ping,
            FunaiMessageType::Pong(ref _m) => FunaiMessageID::Pong,
            FunaiMessageType::NatPunchRequest(ref _m) => FunaiMessageID::NatPunchRequest,
            FunaiMessageType::NatPunchReply(ref _m) => FunaiMessageID::NatPunchReply,
            FunaiMessageType::FunaiDBHandshakeAccept(ref _h, ref _m) => {
                FunaiMessageID::FunaiDBHandshakeAccept
            }
            FunaiMessageType::FunaiDBGetChunkInv(ref _m) => {
                FunaiMessageID::FunaiDBGetChunkInv
            }
            FunaiMessageType::FunaiDBChunkInv(ref _m) => FunaiMessageID::FunaiDBChunkInv,
            FunaiMessageType::FunaiDBGetChunk(ref _m) => FunaiMessageID::FunaiDBGetChunk,
            FunaiMessageType::FunaiDBChunk(ref _m) => FunaiMessageID::FunaiDBChunk,
            FunaiMessageType::FunaiDBPushChunk(ref _m) => FunaiMessageID::FunaiDBPushChunk,
            FunaiMessageType::GetNakamotoInv(ref _m) => FunaiMessageID::GetNakamotoInv,
            FunaiMessageType::NakamotoInv(ref _m) => FunaiMessageID::NakamotoInv,
        }
    }

    pub fn get_message_name(&self) -> &'static str {
        match *self {
            FunaiMessageType::Handshake(ref _m) => "Handshake",
            FunaiMessageType::HandshakeAccept(ref _m) => "HandshakeAccept",
            FunaiMessageType::HandshakeReject => "HandshakeReject",
            FunaiMessageType::GetNeighbors => "GetNeighbors",
            FunaiMessageType::Neighbors(ref _m) => "Neighbors",
            FunaiMessageType::GetPoxInv(ref _m) => "GetPoxInv",
            FunaiMessageType::PoxInv(ref _m) => "PoxInv",
            FunaiMessageType::GetBlocksInv(ref _m) => "GetBlocksInv",
            FunaiMessageType::BlocksInv(ref _m) => "BlocksInv",
            FunaiMessageType::BlocksAvailable(ref _m) => "BlocksAvailable",
            FunaiMessageType::MicroblocksAvailable(ref _m) => "MicroblocksAvailable",
            FunaiMessageType::Blocks(ref _m) => "Blocks",
            FunaiMessageType::Microblocks(ref _m) => "Microblocks",
            FunaiMessageType::Transaction(ref _m) => "Transaction",
            FunaiMessageType::Nack(ref _m) => "Nack",
            FunaiMessageType::Ping(ref _m) => "Ping",
            FunaiMessageType::Pong(ref _m) => "Pong",
            FunaiMessageType::NatPunchRequest(ref _m) => "NatPunchRequest",
            FunaiMessageType::NatPunchReply(ref _m) => "NatPunchReply",
            FunaiMessageType::FunaiDBHandshakeAccept(ref _h, ref _m) => {
                "FunaiDBHandshakeAccept"
            }
            FunaiMessageType::FunaiDBGetChunkInv(ref _m) => "FunaiDBGetChunkInv",
            FunaiMessageType::FunaiDBChunkInv(ref _m) => "FunaiDBChunkInv",
            FunaiMessageType::FunaiDBGetChunk(ref _m) => "FunaiDBGetChunk",
            FunaiMessageType::FunaiDBChunk(ref _m) => "FunaiDBChunk",
            FunaiMessageType::FunaiDBPushChunk(ref _m) => "FunaiDBPushChunk",
            FunaiMessageType::GetNakamotoInv(ref _m) => "GetNakamotoInv",
            FunaiMessageType::NakamotoInv(ref _m) => "NakamotoInv",
        }
    }

    pub fn get_message_description(&self) -> String {
        match *self {
            FunaiMessageType::Handshake(ref m) => {
                format!("Handshake({})", &to_hex(&m.node_public_key.to_bytes()))
            }
            FunaiMessageType::HandshakeAccept(ref m) => format!(
                "HandshakeAccept({},{})",
                &to_hex(&m.handshake.node_public_key.to_bytes()),
                m.heartbeat_interval
            ),
            FunaiMessageType::HandshakeReject => "HandshakeReject".to_string(),
            FunaiMessageType::GetNeighbors => "GetNeighbors".to_string(),
            FunaiMessageType::Neighbors(ref m) => format!("Neighbors({:?})", m.neighbors),
            FunaiMessageType::GetPoxInv(ref m) => {
                format!("GetPoxInv({},{}))", &m.consensus_hash, m.num_cycles)
            }
            FunaiMessageType::PoxInv(ref m) => {
                format!("PoxInv({},{:?})", &m.bitlen, &m.pox_bitvec)
            }
            FunaiMessageType::GetBlocksInv(ref m) => {
                format!("GetBlocksInv({},{})", &m.consensus_hash, m.num_blocks)
            }
            FunaiMessageType::BlocksInv(ref m) => format!(
                "BlocksInv({},{:?},{:?})",
                m.bitlen, &m.block_bitvec, &m.microblocks_bitvec
            ),
            FunaiMessageType::BlocksAvailable(ref m) => {
                format!("BlocksAvailable({:?})", &m.available)
            }
            FunaiMessageType::MicroblocksAvailable(ref m) => {
                format!("MicroblocksAvailable({:?})", &m.available)
            }
            FunaiMessageType::Blocks(ref m) => format!(
                "Blocks({:?})",
                m.blocks
                    .iter()
                    .map(|BlocksDatum(ch, blk)| (ch.clone(), blk.block_hash()))
                    .collect::<Vec<(ConsensusHash, BlockHeaderHash)>>()
            ),
            FunaiMessageType::Microblocks(ref m) => format!(
                "Microblocks({},{:?})",
                &m.index_anchor_block,
                m.microblocks
                    .iter()
                    .map(|mblk| mblk.block_hash())
                    .collect::<Vec<BlockHeaderHash>>()
            ),
            FunaiMessageType::Transaction(ref m) => format!("Transaction({})", m.txid()),
            FunaiMessageType::Nack(ref m) => format!("Nack({})", m.error_code),
            FunaiMessageType::Ping(ref m) => format!("Ping({})", m.nonce),
            FunaiMessageType::Pong(ref m) => format!("Pong({})", m.nonce),
            FunaiMessageType::NatPunchRequest(ref m) => format!("NatPunchRequest({})", m),
            FunaiMessageType::NatPunchReply(ref m) => {
                format!("NatPunchReply({},{}:{})", m.nonce, &m.addrbytes, m.port)
            }
            FunaiMessageType::FunaiDBHandshakeAccept(ref h, ref m) => {
                format!(
                    "FunaiDBHandshakeAccept({},{},{:?})",
                    &to_hex(&h.handshake.node_public_key.to_bytes()),
                    &m.rc_consensus_hash,
                    &m.smart_contracts
                )
            }
            FunaiMessageType::FunaiDBGetChunkInv(ref m) => {
                format!(
                    "FunaiDBGetChunkInv({}.{})",
                    &m.contract_id, &m.rc_consensus_hash
                )
            }
            FunaiMessageType::FunaiDBChunkInv(ref m) => {
                format!("FunaiDBChunkInv({:?})", &m.slot_versions)
            }
            FunaiMessageType::FunaiDBGetChunk(ref m) => {
                format!(
                    "FunaiDBGetChunk({},{},{},{})",
                    &m.contract_id, &m.rc_consensus_hash, m.slot_id, m.slot_version
                )
            }
            FunaiMessageType::FunaiDBChunk(ref m) => {
                format!(
                    "FunaiDBChunk({},{},{},sz={})",
                    m.slot_id,
                    m.slot_version,
                    &m.sig,
                    m.data.len()
                )
            }
            FunaiMessageType::FunaiDBPushChunk(ref m) => {
                format!(
                    "FunaiDBPushChunk({},{},{},{},{},sz={})",
                    &m.contract_id,
                    &m.rc_consensus_hash,
                    m.chunk_data.slot_id,
                    m.chunk_data.slot_version,
                    &m.chunk_data.sig,
                    m.chunk_data.data.len()
                )
            }
            FunaiMessageType::GetNakamotoInv(ref m) => {
                format!("GetNakamotoInv({})", &m.consensus_hash,)
            }
            FunaiMessageType::NakamotoInv(ref m) => {
                format!("NakamotoInv({:?})", &m.tenures)
            }
        }
    }
}

impl FunaiMessageCodec for FunaiMessageID {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &(*self as u8))
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<FunaiMessageID, codec_error> {
        let as_u8: u8 = read_next(fd)?;
        let id = match as_u8 {
            x if x == FunaiMessageID::Handshake as u8 => FunaiMessageID::Handshake,
            x if x == FunaiMessageID::HandshakeAccept as u8 => FunaiMessageID::HandshakeAccept,
            x if x == FunaiMessageID::HandshakeReject as u8 => FunaiMessageID::HandshakeReject,
            x if x == FunaiMessageID::GetNeighbors as u8 => FunaiMessageID::GetNeighbors,
            x if x == FunaiMessageID::Neighbors as u8 => FunaiMessageID::Neighbors,
            x if x == FunaiMessageID::GetPoxInv as u8 => FunaiMessageID::GetPoxInv,
            x if x == FunaiMessageID::PoxInv as u8 => FunaiMessageID::PoxInv,
            x if x == FunaiMessageID::GetBlocksInv as u8 => FunaiMessageID::GetBlocksInv,
            x if x == FunaiMessageID::BlocksInv as u8 => FunaiMessageID::BlocksInv,
            x if x == FunaiMessageID::BlocksAvailable as u8 => FunaiMessageID::BlocksAvailable,
            x if x == FunaiMessageID::MicroblocksAvailable as u8 => {
                FunaiMessageID::MicroblocksAvailable
            }
            x if x == FunaiMessageID::Blocks as u8 => FunaiMessageID::Blocks,
            x if x == FunaiMessageID::Microblocks as u8 => FunaiMessageID::Microblocks,
            x if x == FunaiMessageID::Transaction as u8 => FunaiMessageID::Transaction,
            x if x == FunaiMessageID::Nack as u8 => FunaiMessageID::Nack,
            x if x == FunaiMessageID::Ping as u8 => FunaiMessageID::Ping,
            x if x == FunaiMessageID::Pong as u8 => FunaiMessageID::Pong,
            x if x == FunaiMessageID::NatPunchRequest as u8 => FunaiMessageID::NatPunchRequest,
            x if x == FunaiMessageID::NatPunchReply as u8 => FunaiMessageID::NatPunchReply,
            x if x == FunaiMessageID::FunaiDBHandshakeAccept as u8 => {
                FunaiMessageID::FunaiDBHandshakeAccept
            }
            x if x == FunaiMessageID::FunaiDBGetChunkInv as u8 => {
                FunaiMessageID::FunaiDBGetChunkInv
            }
            x if x == FunaiMessageID::FunaiDBChunkInv as u8 => {
                FunaiMessageID::FunaiDBChunkInv
            }
            x if x == FunaiMessageID::FunaiDBGetChunk as u8 => {
                FunaiMessageID::FunaiDBGetChunk
            }
            x if x == FunaiMessageID::FunaiDBChunk as u8 => FunaiMessageID::FunaiDBChunk,
            x if x == FunaiMessageID::FunaiDBPushChunk as u8 => {
                FunaiMessageID::FunaiDBPushChunk
            }
            x if x == FunaiMessageID::GetNakamotoInv as u8 => FunaiMessageID::GetNakamotoInv,
            x if x == FunaiMessageID::NakamotoInv as u8 => FunaiMessageID::NakamotoInv,
            _ => {
                return Err(codec_error::DeserializeError(
                    "Unknown message ID".to_string(),
                ));
            }
        };
        Ok(id)
    }
}

impl FunaiMessageCodec for FunaiMessageType {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &(self.get_message_id() as u8))?;
        match *self {
            FunaiMessageType::Handshake(ref m) => write_next(fd, m)?,
            FunaiMessageType::HandshakeAccept(ref m) => write_next(fd, m)?,
            FunaiMessageType::HandshakeReject => {}
            FunaiMessageType::GetNeighbors => {}
            FunaiMessageType::Neighbors(ref m) => write_next(fd, m)?,
            FunaiMessageType::GetPoxInv(ref m) => write_next(fd, m)?,
            FunaiMessageType::PoxInv(ref m) => write_next(fd, m)?,
            FunaiMessageType::GetBlocksInv(ref m) => write_next(fd, m)?,
            FunaiMessageType::BlocksInv(ref m) => write_next(fd, m)?,
            FunaiMessageType::BlocksAvailable(ref m) => write_next(fd, m)?,
            FunaiMessageType::MicroblocksAvailable(ref m) => write_next(fd, m)?,
            FunaiMessageType::Blocks(ref m) => write_next(fd, m)?,
            FunaiMessageType::Microblocks(ref m) => write_next(fd, m)?,
            FunaiMessageType::Transaction(ref m) => write_next(fd, m)?,
            FunaiMessageType::Nack(ref m) => write_next(fd, m)?,
            FunaiMessageType::Ping(ref m) => write_next(fd, m)?,
            FunaiMessageType::Pong(ref m) => write_next(fd, m)?,
            FunaiMessageType::NatPunchRequest(ref nonce) => write_next(fd, nonce)?,
            FunaiMessageType::NatPunchReply(ref m) => write_next(fd, m)?,
            FunaiMessageType::FunaiDBHandshakeAccept(ref h, ref m) => {
                write_next(fd, h)?;
                write_next(fd, m)?
            }
            FunaiMessageType::FunaiDBGetChunkInv(ref m) => write_next(fd, m)?,
            FunaiMessageType::FunaiDBChunkInv(ref m) => write_next(fd, m)?,
            FunaiMessageType::FunaiDBGetChunk(ref m) => write_next(fd, m)?,
            FunaiMessageType::FunaiDBChunk(ref m) => write_next(fd, m)?,
            FunaiMessageType::FunaiDBPushChunk(ref m) => write_next(fd, m)?,
            FunaiMessageType::GetNakamotoInv(ref m) => write_next(fd, m)?,
            FunaiMessageType::NakamotoInv(ref m) => write_next(fd, m)?,
        }
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<FunaiMessageType, codec_error> {
        let message_id: FunaiMessageID = read_next(fd)?;
        let message = match message_id {
            FunaiMessageID::Handshake => {
                let m: HandshakeData = read_next(fd)?;
                FunaiMessageType::Handshake(m)
            }
            FunaiMessageID::HandshakeAccept => {
                let m: HandshakeAcceptData = read_next(fd)?;
                FunaiMessageType::HandshakeAccept(m)
            }
            FunaiMessageID::HandshakeReject => FunaiMessageType::HandshakeReject,
            FunaiMessageID::GetNeighbors => FunaiMessageType::GetNeighbors,
            FunaiMessageID::Neighbors => {
                let m: NeighborsData = read_next(fd)?;
                FunaiMessageType::Neighbors(m)
            }
            FunaiMessageID::GetPoxInv => {
                let m: GetPoxInv = read_next(fd)?;
                FunaiMessageType::GetPoxInv(m)
            }
            FunaiMessageID::PoxInv => {
                let m: PoxInvData = read_next(fd)?;
                FunaiMessageType::PoxInv(m)
            }
            FunaiMessageID::GetBlocksInv => {
                let m: GetBlocksInv = read_next(fd)?;
                FunaiMessageType::GetBlocksInv(m)
            }
            FunaiMessageID::BlocksInv => {
                let m: BlocksInvData = read_next(fd)?;
                FunaiMessageType::BlocksInv(m)
            }
            FunaiMessageID::BlocksAvailable => {
                let m: BlocksAvailableData = read_next(fd)?;
                FunaiMessageType::BlocksAvailable(m)
            }
            FunaiMessageID::MicroblocksAvailable => {
                let m: BlocksAvailableData = read_next(fd)?;
                FunaiMessageType::MicroblocksAvailable(m)
            }
            FunaiMessageID::Blocks => {
                let m: BlocksData = read_next(fd)?;
                FunaiMessageType::Blocks(m)
            }
            FunaiMessageID::Microblocks => {
                let m: MicroblocksData = read_next(fd)?;
                FunaiMessageType::Microblocks(m)
            }
            FunaiMessageID::Transaction => {
                let m: FunaiTransaction = read_next(fd)?;
                FunaiMessageType::Transaction(m)
            }
            FunaiMessageID::Nack => {
                let m: NackData = read_next(fd)?;
                FunaiMessageType::Nack(m)
            }
            FunaiMessageID::Ping => {
                let m: PingData = read_next(fd)?;
                FunaiMessageType::Ping(m)
            }
            FunaiMessageID::Pong => {
                let m: PongData = read_next(fd)?;
                FunaiMessageType::Pong(m)
            }
            FunaiMessageID::NatPunchRequest => {
                let nonce: u32 = read_next(fd)?;
                FunaiMessageType::NatPunchRequest(nonce)
            }
            FunaiMessageID::NatPunchReply => {
                let m: NatPunchData = read_next(fd)?;
                FunaiMessageType::NatPunchReply(m)
            }
            FunaiMessageID::FunaiDBHandshakeAccept => {
                let h: HandshakeAcceptData = read_next(fd)?;
                let m: FunaiDBHandshakeData = read_next(fd)?;
                FunaiMessageType::FunaiDBHandshakeAccept(h, m)
            }
            FunaiMessageID::FunaiDBGetChunkInv => {
                let m: FunaiDBGetChunkInvData = read_next(fd)?;
                FunaiMessageType::FunaiDBGetChunkInv(m)
            }
            FunaiMessageID::FunaiDBChunkInv => {
                let m: FunaiDBChunkInvData = read_next(fd)?;
                FunaiMessageType::FunaiDBChunkInv(m)
            }
            FunaiMessageID::FunaiDBGetChunk => {
                let m: FunaiDBGetChunkData = read_next(fd)?;
                FunaiMessageType::FunaiDBGetChunk(m)
            }
            FunaiMessageID::FunaiDBChunk => {
                let m: FunaiDBChunkData = read_next(fd)?;
                FunaiMessageType::FunaiDBChunk(m)
            }
            FunaiMessageID::FunaiDBPushChunk => {
                let m: FunaiDBPushChunkData = read_next(fd)?;
                FunaiMessageType::FunaiDBPushChunk(m)
            }
            FunaiMessageID::GetNakamotoInv => {
                let m: GetNakamotoInvData = read_next(fd)?;
                FunaiMessageType::GetNakamotoInv(m)
            }
            FunaiMessageID::NakamotoInv => {
                let m: NakamotoInvData = read_next(fd)?;
                FunaiMessageType::NakamotoInv(m)
            }
            FunaiMessageID::Reserved => {
                return Err(codec_error::DeserializeError(
                    "Unsupported message ID 'reserved'".to_string(),
                ));
            }
        };
        Ok(message)
    }
}

impl FunaiMessageCodec for FunaiMessage {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &self.preamble)?;
        write_next(fd, &self.relayers)?;
        write_next(fd, &self.payload)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<FunaiMessage, codec_error> {
        let preamble: Preamble = read_next(fd)?;
        if preamble.payload_len > MAX_MESSAGE_LEN - PREAMBLE_ENCODED_SIZE {
            return Err(codec_error::DeserializeError(
                "Message would be too big".to_string(),
            ));
        }

        let relayers: Vec<RelayData> = read_next_at_most::<_, RelayData>(fd, MAX_RELAYERS_LEN)?;
        let payload: FunaiMessageType = read_next(fd)?;

        let message = FunaiMessage {
            preamble,
            relayers,
            payload,
        };
        Ok(message)
    }
}

impl FunaiMessage {
    /// Create an unsigned Funai p2p message
    pub fn new(
        peer_version: u32,
        network_id: u32,
        block_height: u64,
        burn_header_hash: &BurnchainHeaderHash,
        stable_block_height: u64,
        stable_burn_header_hash: &BurnchainHeaderHash,
        message: FunaiMessageType,
    ) -> FunaiMessage {
        let preamble = Preamble::new(
            peer_version,
            network_id,
            block_height,
            burn_header_hash,
            stable_block_height,
            stable_burn_header_hash,
            0,
        );
        FunaiMessage {
            preamble: preamble,
            relayers: vec![],
            payload: message,
        }
    }

    /// Create an unsigned Funai message
    pub fn from_chain_view(
        peer_version: u32,
        network_id: u32,
        chain_view: &BurnchainView,
        message: FunaiMessageType,
    ) -> FunaiMessage {
        FunaiMessage::new(
            peer_version,
            network_id,
            chain_view.burn_block_height,
            &chain_view.burn_block_hash,
            chain_view.burn_stable_block_height,
            &chain_view.burn_stable_block_hash,
            message,
        )
    }

    /// represent as neighbor key
    pub fn to_neighbor_key(&self, addrbytes: &PeerAddress, port: u16) -> NeighborKey {
        NeighborKey {
            peer_version: self.preamble.peer_version,
            network_id: self.preamble.network_id,
            addrbytes: addrbytes.clone(),
            port: port,
        }
    }

    /// Sign the funai message
    fn do_sign(&mut self, private_key: &Secp256k1PrivateKey) -> Result<(), net_error> {
        let mut message_bits = vec![];
        self.relayers.consensus_serialize(&mut message_bits)?;
        self.payload.consensus_serialize(&mut message_bits)?;

        self.preamble.payload_len = message_bits.len() as u32;
        self.preamble.sign(&message_bits[..], private_key)
    }

    /// Sign the FunaiMessage.  The FunaiMessage must _not_ have any relayers (i.e. we're
    /// originating this messsage).
    pub fn sign(&mut self, seq: u32, private_key: &Secp256k1PrivateKey) -> Result<(), net_error> {
        if self.relayers.len() > 0 {
            return Err(net_error::InvalidMessage);
        }
        self.preamble.seq = seq;
        self.do_sign(private_key)
    }

    /// Sign the FunaiMessage and add ourselves as a relayer.
    pub fn sign_relay(
        &mut self,
        private_key: &Secp256k1PrivateKey,
        our_seq: u32,
        our_addr: &NeighborAddress,
    ) -> Result<(), net_error> {
        if self.relayers.len() >= MAX_RELAYERS_LEN as usize {
            warn!(
                "Message {:?} has too many relayers; will not sign",
                self.payload.get_message_description()
            );
            return Err(net_error::InvalidMessage);
        }

        // don't sign if signed more than once
        for relayer in &self.relayers {
            if relayer.peer.public_key_hash == our_addr.public_key_hash {
                warn!(
                    "Message {:?} already signed by {}",
                    self.payload.get_message_description(),
                    &our_addr.public_key_hash
                );
                return Err(net_error::InvalidMessage);
            }
        }

        // save relayer state
        let our_relay = RelayData {
            peer: our_addr.clone(),
            seq: self.preamble.seq,
        };

        self.relayers.push(our_relay);
        self.preamble.seq = our_seq;
        self.do_sign(private_key)
    }

    pub fn deserialize_body<R: Read>(
        fd: &mut R,
    ) -> Result<(Vec<RelayData>, FunaiMessageType), net_error> {
        let relayers: Vec<RelayData> = read_next_at_most::<_, RelayData>(fd, MAX_RELAYERS_LEN)?;
        let payload: FunaiMessageType = read_next(fd)?;
        Ok((relayers, payload))
    }

    /// Verify this message by treating the public key buffer as a secp256k1 public key.
    /// Fails if:
    /// * the signature doesn't match
    /// * the buffer doesn't encode a secp256k1 public key
    pub fn verify_secp256k1(&self, public_key: &FunaiPublicKeyBuffer) -> Result<(), net_error> {
        let secp256k1_pubkey = public_key
            .to_public_key()
            .map_err(|e| net_error::DeserializeError(e.into()))?;

        let mut message_bits = vec![];
        self.relayers.consensus_serialize(&mut message_bits)?;
        self.payload.consensus_serialize(&mut message_bits)?;

        let mut p = self.preamble.clone();
        p.verify(&message_bits, &secp256k1_pubkey)
            .and_then(|_m| Ok(()))
    }
}

impl MessageSequence for FunaiMessage {
    fn request_id(&self) -> u32 {
        self.preamble.seq
    }

    fn get_message_name(&self) -> &'static str {
        self.payload.get_message_name()
    }
}

impl FunaiP2P {
    pub fn new() -> FunaiP2P {
        FunaiP2P {}
    }
}

impl ProtocolFamily for FunaiP2P {
    type Preamble = Preamble;
    type Message = FunaiMessage;

    /// How big can a P2P preamble get?
    fn preamble_size_hint(&mut self) -> usize {
        PREAMBLE_ENCODED_SIZE as usize
    }

    /// How long is an encoded message payload going to be, if we can tell at all?
    fn payload_len(&mut self, preamble: &Preamble) -> Option<usize> {
        Some(preamble.payload_len as usize)
    }

    /// FunaiP2P deals with Preambles
    fn read_preamble(&mut self, buf: &[u8]) -> Result<(Preamble, usize), net_error> {
        if buf.len() < PREAMBLE_ENCODED_SIZE as usize {
            return Err(net_error::UnderflowError(
                "Not enough bytes to form a P2P preamble".to_string(),
            ));
        }

        let preamble: Preamble = read_next(&mut &buf[0..(PREAMBLE_ENCODED_SIZE as usize)])?;
        Ok((preamble, PREAMBLE_ENCODED_SIZE as usize))
    }

    /// FunaiP2P messages are never streamed, since we always know how long they are.
    /// This should be unreachable, since payload_len() always returns Some(...)
    fn stream_payload<R: Read>(
        &mut self,
        _preamble: &Preamble,
        _fd: &mut R,
    ) -> Result<(Option<(FunaiMessage, usize)>, usize), net_error> {
        panic!(
            "BUG: tried to stream a FunaiP2P message, even though their lengths are always known"
        )
    }

    /// FunaiP2P deals with FunaiMessages
    fn read_payload(
        &mut self,
        preamble: &Preamble,
        bytes: &[u8],
    ) -> Result<(FunaiMessage, usize), net_error> {
        if bytes.len() < preamble.payload_len as usize {
            return Err(net_error::UnderflowError(
                "Not enough bytes to form a FunaiMessage".to_string(),
            ));
        }

        let mut cursor = io::Cursor::new(&bytes[0..(preamble.payload_len as usize)]);
        let (relayers, payload) = FunaiMessage::deserialize_body(&mut cursor)?;
        let message = FunaiMessage {
            preamble: preamble.clone(),
            relayers: relayers,
            payload: payload,
        };
        Ok((message, cursor.position() as usize))
    }

    fn verify_payload_bytes(
        &mut self,
        key: &FunaiPublicKey,
        preamble: &Preamble,
        bytes: &[u8],
    ) -> Result<(), Error> {
        preamble
            .clone()
            .verify(&bytes[0..(preamble.payload_len as usize)], key)
            .and_then(|_m| Ok(()))
    }

    fn write_message<W: Write>(
        &mut self,
        fd: &mut W,
        message: &FunaiMessage,
    ) -> Result<(), net_error> {
        message.consensus_serialize(fd).map_err(|e| e.into())
    }
}

#[cfg(test)]
pub mod test {
    use funai_common::bitvec::BitVec;
    use funai_common::codec::NEIGHBOR_ADDRESS_ENCODED_SIZE;
    use funai_common::util::hash::hex_bytes;
    use funai_common::util::secp256k1::*;

    use super::*;
    use crate::net::{GetNakamotoInvData, NakamotoInvData};

    fn check_overflow<T>(r: Result<T, net_error>) -> bool {
        match r {
            Ok(_) => {
                test_debug!("did not get an overflow error, or any error");
                false
            }
            Err(e) => match e {
                net_error::OverflowError(_) => true,
                _ => {
                    test_debug!("did not get an overflow error, but got {:?}", &e);
                    false
                }
            },
        }
    }

    fn check_underflow<T>(r: Result<T, net_error>) -> bool {
        match r {
            Ok(_) => {
                test_debug!("did not get an underflow error, or any error");
                false
            }
            Err(e) => match e {
                net_error::UnderflowError(_) => true,
                _ => {
                    test_debug!("did not get an underflow error, but got {:?}", &e);
                    false
                }
            },
        }
    }

    fn check_deserialize<T: std::fmt::Debug>(r: Result<T, codec_error>) -> bool {
        match r {
            Ok(m) => {
                test_debug!("deserialized {:?}", &m);
                false
            }
            Err(e) => match e {
                codec_error::DeserializeError(_) => true,
                _ => false,
            },
        }
    }

    fn check_deserialize_failure<T: FunaiMessageCodec + fmt::Debug + Clone + PartialEq>(
        obj: &T,
    ) -> bool {
        let mut bytes: Vec<u8> = vec![];
        obj.consensus_serialize(&mut bytes).unwrap();
        check_deserialize(T::consensus_deserialize(&mut &bytes[..]))
    }

    pub fn check_codec_and_corruption<T: FunaiMessageCodec + fmt::Debug + Clone + PartialEq>(
        obj: &T,
        bytes: &Vec<u8>,
    ) -> () {
        // obj should serialize to bytes
        let mut write_buf: Vec<u8> = Vec::with_capacity(bytes.len());
        obj.consensus_serialize(&mut write_buf).unwrap();
        assert_eq!(write_buf, *bytes);

        // bytes should deserialize to obj
        let read_buf: Vec<u8> = write_buf.clone();
        let res = T::consensus_deserialize(&mut &read_buf[..]);
        match res {
            Ok(out) => {
                assert_eq!(out, *obj);
            }
            Err(e) => {
                test_debug!("\nFailed to parse to {:?}: {:?}", obj, bytes);
                test_debug!("error: {:?}", &e);
                assert!(false);
            }
        }

        // short message shouldn't parse, but should EOF
        if write_buf.len() > 0 {
            let mut short_buf = write_buf.clone();
            let short_len = short_buf.len() - 1;
            short_buf.truncate(short_len);

            let underflow_res = T::consensus_deserialize(&mut &short_buf[..]);
            match underflow_res {
                Ok(oops) => {
                    test_debug!(
                        "\nMissing Underflow: Parsed {:?}\nFrom {:?}\n",
                        &oops,
                        &write_buf[0..short_len].to_vec()
                    );
                }
                Err(codec_error::ReadError(io_error)) => match io_error.kind() {
                    io::ErrorKind::UnexpectedEof => {}
                    _ => {
                        test_debug!("Got unexpected I/O error: {:?}", &io_error);
                        assert!(false);
                    }
                },
                Err(e) => {
                    test_debug!("Got unexpected Net error: {:?}", &e);
                    assert!(false);
                }
            };
        }
    }

    #[test]
    fn codec_primitive_types() {
        check_codec_and_corruption::<u8>(&0x01, &vec![0x01]);
        check_codec_and_corruption::<u16>(&0x0203, &vec![0x02, 0x03]);
        check_codec_and_corruption::<u32>(&0x04050607, &vec![0x04, 0x05, 0x06, 0x07]);
        check_codec_and_corruption::<u64>(
            &0x08090a0b0c0d0e0f,
            &vec![0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f],
        );
    }

    #[test]
    fn codec_primitive_vector() {
        check_codec_and_corruption::<Vec<u8>>(&vec![], &vec![0x00, 0x00, 0x00, 0x00]);
        check_codec_and_corruption::<Vec<u8>>(
            &vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09],
            &vec![
                0x00, 0x00, 0x00, 0x0a, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
            ],
        );

        check_codec_and_corruption::<Vec<u16>>(&vec![], &vec![0x00, 0x00, 0x00, 0x00]);
        check_codec_and_corruption::<Vec<u16>>(
            &vec![
                0xf000, 0xf101, 0xf202, 0xf303, 0xf404, 0xf505, 0xf606, 0xf707, 0xf808, 0xf909,
            ],
            &vec![
                0x00, 0x00, 0x00, 0x0a, 0xf0, 0x00, 0xf1, 0x01, 0xf2, 0x02, 0xf3, 0x03, 0xf4, 0x04,
                0xf5, 0x05, 0xf6, 0x06, 0xf7, 0x07, 0xf8, 0x08, 0xf9, 0x09,
            ],
        );

        check_codec_and_corruption::<Vec<u32>>(&vec![], &vec![0x00, 0x00, 0x00, 0x00]);
        check_codec_and_corruption::<Vec<u32>>(
            &vec![
                0xa0b0f000, 0xa1b1f101, 0xa2b2f202, 0xa3b3f303, 0xa4b4f404, 0xa5b5f505, 0xa6b6f606,
                0xa7b7f707, 0xa8b8f808, 0xa9b9f909,
            ],
            &vec![
                0x00, 0x00, 0x00, 0x0a, 0xa0, 0xb0, 0xf0, 0x00, 0xa1, 0xb1, 0xf1, 0x01, 0xa2, 0xb2,
                0xf2, 0x02, 0xa3, 0xb3, 0xf3, 0x03, 0xa4, 0xb4, 0xf4, 0x04, 0xa5, 0xb5, 0xf5, 0x05,
                0xa6, 0xb6, 0xf6, 0x06, 0xa7, 0xb7, 0xf7, 0x07, 0xa8, 0xb8, 0xf8, 0x08, 0xa9, 0xb9,
                0xf9, 0x09,
            ],
        );

        check_codec_and_corruption::<Vec<u64>>(&vec![], &vec![0x00, 0x00, 0x00, 0x00]);
        check_codec_and_corruption::<Vec<u64>>(
            &vec![
                0x1020304050607080,
                0x1121314151617181,
                0x1222324252627282,
                0x1323334353637383,
                0x1424344454647484,
                0x1525354555657585,
                0x1626364656667686,
                0x1727374757677787,
                0x1828384858687888,
            ],
            &vec![
                0x00, 0x00, 0x00, 0x09, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x11, 0x21,
                0x31, 0x41, 0x51, 0x61, 0x71, 0x81, 0x12, 0x22, 0x32, 0x42, 0x52, 0x62, 0x72, 0x82,
                0x13, 0x23, 0x33, 0x43, 0x53, 0x63, 0x73, 0x83, 0x14, 0x24, 0x34, 0x44, 0x54, 0x64,
                0x74, 0x84, 0x15, 0x25, 0x35, 0x45, 0x55, 0x65, 0x75, 0x85, 0x16, 0x26, 0x36, 0x46,
                0x56, 0x66, 0x76, 0x86, 0x17, 0x27, 0x37, 0x47, 0x57, 0x67, 0x77, 0x87, 0x18, 0x28,
                0x38, 0x48, 0x58, 0x68, 0x78, 0x88,
            ],
        );
    }

    #[test]
    fn codec_Preamble() {
        let preamble = Preamble {
            peer_version: 0x01020304,
            network_id: 0x05060708,
            seq: 0x090a0b0c,
            burn_block_height: 0x00001122,
            burn_block_hash: BurnchainHeaderHash([0x11; 32]),
            burn_stable_block_height: 0x00001111,
            burn_stable_block_hash: BurnchainHeaderHash([0x22; 32]),
            additional_data: 0x33333333,
            signature: MessageSignature::from_raw(&vec![0x44; 65]),
            payload_len: 0x000007ff,
        };
        let preamble_bytes: Vec<u8> = vec![
            // peer_version
            0x01, 0x02, 0x03, 0x04, // network_id
            0x05, 0x06, 0x07, 0x08, // seq
            0x09, 0x0a, 0x0b, 0x0c, // burn_block_height
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x22, // burn_block_hash
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, // stable_burn_block_height
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x11, // stable_burn_block_hash
            0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
            0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
            0x22, 0x22, 0x22, 0x22, // additional_data
            0x33, 0x33, 0x33, 0x33, // signature
            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, // payload_len
            0x00, 0x00, 0x07, 0xff,
        ];

        assert_eq!(preamble_bytes.len() as u32, PREAMBLE_ENCODED_SIZE);
        check_codec_and_corruption::<Preamble>(&preamble, &preamble_bytes);
    }

    #[test]
    fn codec_GetPoxInv() {
        let getpoxinv = GetPoxInv {
            consensus_hash: ConsensusHash([0x55; 20]),
            num_cycles: GETPOXINV_MAX_BITLEN as u16,
        };

        let getpoxinv_bytes: Vec<u8> = vec![
            // consensus hash
            0x55,
            0x55,
            0x55,
            0x55,
            0x55,
            0x55,
            0x55,
            0x55,
            0x55,
            0x55,
            0x55,
            0x55,
            0x55,
            0x55,
            0x55,
            0x55,
            0x55,
            0x55,
            0x55,
            0x55,
            // num reward cycles
            0x00,
            GETPOXINV_MAX_BITLEN as u8,
        ];

        check_codec_and_corruption::<GetPoxInv>(&getpoxinv, &getpoxinv_bytes);

        // should fail to decode if the block range is too big
        let getpoxinv_range_too_big = GetPoxInv {
            consensus_hash: ConsensusHash([0x55; 20]),
            num_cycles: (GETPOXINV_MAX_BITLEN + 1) as u16,
        };

        assert!(check_deserialize_failure::<GetPoxInv>(
            &getpoxinv_range_too_big
        ));
    }

    #[test]
    fn codec_PoxInvData() {
        // maximially big PoxInvData
        let maximal_bitvec = vec![0xffu8; (GETPOXINV_MAX_BITLEN / 8) as usize];
        let mut too_big_bitvec: Vec<u8> = vec![];
        for i in 0..GETPOXINV_MAX_BITLEN + 1 {
            too_big_bitvec.push(0xff);
        }

        let maximal_poxinvdata = PoxInvData {
            bitlen: GETPOXINV_MAX_BITLEN as u16,
            pox_bitvec: maximal_bitvec.clone(),
        };

        let mut maximal_poxinvdata_bytes: Vec<u8> = vec![];
        // bitlen
        maximal_poxinvdata_bytes.append(&mut (GETPOXINV_MAX_BITLEN as u16).to_be_bytes().to_vec());
        // pox bitvec
        maximal_poxinvdata_bytes
            .append(&mut ((GETPOXINV_MAX_BITLEN / 8) as u32).to_be_bytes().to_vec());
        maximal_poxinvdata_bytes.append(&mut maximal_bitvec.clone());

        assert!((maximal_poxinvdata_bytes.len() as u32) < MAX_MESSAGE_LEN);

        check_codec_and_corruption::<PoxInvData>(&maximal_poxinvdata, &maximal_poxinvdata_bytes);

        // should fail to decode if the bitlen is too big
        let too_big_poxinvdata = PoxInvData {
            bitlen: (GETPOXINV_MAX_BITLEN + 1) as u16,
            pox_bitvec: too_big_bitvec.clone(),
        };
        assert!(check_deserialize_failure::<PoxInvData>(&too_big_poxinvdata));

        // should fail to decode if the bitlen doesn't match the bitvec
        let long_bitlen = PoxInvData {
            bitlen: 1,
            pox_bitvec: vec![0xff, 0x01],
        };
        assert!(check_deserialize_failure::<PoxInvData>(&long_bitlen));

        let short_bitlen = PoxInvData {
            bitlen: 9,
            pox_bitvec: vec![0xff],
        };
        assert!(check_deserialize_failure::<PoxInvData>(&short_bitlen));

        // empty
        let empty_inv = PoxInvData {
            bitlen: 0,
            pox_bitvec: vec![],
        };
        let empty_inv_bytes = vec![
            // bitlen
            0x00, 0x00, 0x00, 0x00, // bitvec
            0x00, 0x00, 0x00, 0x00,
        ];

        check_codec_and_corruption::<PoxInvData>(&maximal_poxinvdata, &maximal_poxinvdata_bytes);
    }

    #[test]
    fn codec_GetBlocksInv() {
        let getblocksdata = GetBlocksInv {
            consensus_hash: ConsensusHash([0x55; 20]),
            num_blocks: 32,
        };

        let getblocksdata_bytes: Vec<u8> = vec![
            // consensus hash
            0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
            0x55, 0x55, 0x55, 0x55, 0x55, 0x55, // num blocks
            0x00, 0x20,
        ];

        check_codec_and_corruption::<GetBlocksInv>(&getblocksdata, &getblocksdata_bytes);
    }

    #[test]
    fn codec_BlocksInvData() {
        let blocks_bitlen: u32 = 32;

        let maximal_bitvec = vec![0xffu8; (blocks_bitlen / 8) as usize];
        let maximal_blocksinvdata = BlocksInvData {
            bitlen: blocks_bitlen as u16,
            block_bitvec: maximal_bitvec.clone(),
            microblocks_bitvec: maximal_bitvec.clone(),
        };

        let mut maximal_blocksinvdata_bytes: Vec<u8> = vec![];
        // bitlen
        maximal_blocksinvdata_bytes.append(&mut (blocks_bitlen as u16).to_be_bytes().to_vec());
        // block bitvec
        maximal_blocksinvdata_bytes.append(&mut (blocks_bitlen / 8).to_be_bytes().to_vec());
        maximal_blocksinvdata_bytes.append(&mut maximal_bitvec.clone());
        // microblock bitvec
        maximal_blocksinvdata_bytes.append(&mut (blocks_bitlen / 8).to_be_bytes().to_vec());
        maximal_blocksinvdata_bytes.append(&mut maximal_bitvec.clone());

        assert!((maximal_blocksinvdata_bytes.len() as u32) < MAX_MESSAGE_LEN);

        check_codec_and_corruption::<BlocksInvData>(
            &maximal_blocksinvdata,
            &maximal_blocksinvdata_bytes,
        );

        // should fail to decode if the bitlen doesn't match the bitvec
        let long_bitlen = BlocksInvData {
            bitlen: 1,
            block_bitvec: vec![0xff, 0x01],
            microblocks_bitvec: vec![0xff, 0x01],
        };
        assert!(check_deserialize_failure::<BlocksInvData>(&long_bitlen));

        let short_bitlen = BlocksInvData {
            bitlen: 9,
            block_bitvec: vec![0xff],
            microblocks_bitvec: vec![0xff],
        };
        assert!(check_deserialize_failure::<BlocksInvData>(&short_bitlen));

        // empty
        let empty_inv = BlocksInvData {
            bitlen: 0,
            block_bitvec: vec![],
            microblocks_bitvec: vec![],
        };
        let empty_inv_bytes = vec![
            // bitlen
            0x00, 0x00, 0x00, 0x00, // bitvec
            0x00, 0x00, 0x00, 0x00, // microblock bitvec
            0x00, 0x00, 0x00, 0x00,
        ];

        assert!(check_deserialize_failure::<BlocksInvData>(&empty_inv));
    }

    #[test]
    fn codec_NeighborAddress() {
        let data = NeighborAddress {
            addrbytes: PeerAddress([
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f,
            ]),
            port: 12345,
            public_key_hash: Hash160::from_bytes(
                &hex_bytes("1111111111111111111111111111111111111111").unwrap(),
            )
            .unwrap(),
        };
        let bytes = vec![
            // addrbytes
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, // port
            0x30, 0x39, // public key hash
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        ];

        assert_eq!(bytes.len() as u32, NEIGHBOR_ADDRESS_ENCODED_SIZE);
        check_codec_and_corruption::<NeighborAddress>(&data, &bytes);
    }

    #[test]
    fn codec_NeighborsData() {
        let data = NeighborsData {
            neighbors: vec![
                NeighborAddress {
                    addrbytes: PeerAddress([
                        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                        0x0c, 0x0d, 0x0e, 0x0f,
                    ]),
                    port: 12345,
                    public_key_hash: Hash160::from_bytes(
                        &hex_bytes("1111111111111111111111111111111111111111").unwrap(),
                    )
                    .unwrap(),
                },
                NeighborAddress {
                    addrbytes: PeerAddress([
                        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                        0x1c, 0x1d, 0x1e, 0x1f,
                    ]),
                    port: 23456,
                    public_key_hash: Hash160::from_bytes(
                        &hex_bytes("2222222222222222222222222222222222222222").unwrap(),
                    )
                    .unwrap(),
                },
            ],
        };
        let bytes = vec![
            // length
            0x00, 0x00, 0x00, 0x02, // addrbytes
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, // port
            0x30, 0x39, // public key hash
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, // addrbytes
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f, // port
            0x5b, 0xa0, // public key hash
            0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
            0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
        ];

        check_codec_and_corruption::<NeighborsData>(&data, &bytes);
    }

    #[test]
    fn codec_HandshakeData() {
        let data = HandshakeData {
            addrbytes: PeerAddress([
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f,
            ]),
            port: 12345,
            services: 0x0001,
            node_public_key: FunaiPublicKeyBuffer::from_bytes(
                &hex_bytes("034e316be04870cef1795fba64d581cf64bad0c894b01a068fb9edf85321dcd9bb")
                    .unwrap(),
            )
            .unwrap(),
            expire_block_height: 0x0102030405060708,
            data_url: UrlString::try_from("https://the-new-interwebs.com/data").unwrap(),
        };
        let mut bytes = vec![
            // addrbytes
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, // port
            0x30, 0x39, // services
            0x00, 0x01, // public key
            0x03, 0x4e, 0x31, 0x6b, 0xe0, 0x48, 0x70, 0xce, 0xf1, 0x79, 0x5f, 0xba, 0x64, 0xd5,
            0x81, 0xcf, 0x64, 0xba, 0xd0, 0xc8, 0x94, 0xb0, 0x1a, 0x06, 0x8f, 0xb9, 0xed, 0xf8,
            0x53, 0x21, 0xdc, 0xd9, 0xbb, // expire block height
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        ];
        // data URL
        bytes.push(data.data_url.len() as u8);
        bytes.extend_from_slice(data.data_url.as_bytes());

        check_codec_and_corruption::<HandshakeData>(&data, &bytes);
    }

    #[test]
    fn codec_HandshakeAcceptData() {
        let data = HandshakeAcceptData {
            handshake: HandshakeData {
                addrbytes: PeerAddress([
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f,
                ]),
                port: 12345,
                services: 0x0001,
                node_public_key: FunaiPublicKeyBuffer::from_bytes(
                    &hex_bytes(
                        "034e316be04870cef1795fba64d581cf64bad0c894b01a068fb9edf85321dcd9bb",
                    )
                    .unwrap(),
                )
                .unwrap(),
                expire_block_height: 0x0102030405060708,
                data_url: UrlString::try_from("https://the-new-interwebs.com/data").unwrap(),
            },
            heartbeat_interval: 0x01020304,
        };
        let mut bytes = vec![
            // addrbytes
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, // port
            0x30, 0x39, // services
            0x00, 0x01, // public key
            0x03, 0x4e, 0x31, 0x6b, 0xe0, 0x48, 0x70, 0xce, 0xf1, 0x79, 0x5f, 0xba, 0x64, 0xd5,
            0x81, 0xcf, 0x64, 0xba, 0xd0, 0xc8, 0x94, 0xb0, 0x1a, 0x06, 0x8f, 0xb9, 0xed, 0xf8,
            0x53, 0x21, 0xdc, 0xd9, 0xbb, // expire block height
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        ];
        // data URL
        bytes.push(data.handshake.data_url.len() as u8);
        bytes.extend_from_slice(data.handshake.data_url.as_bytes());

        bytes.extend_from_slice(&[
            // heartbeat
            0x01, 0x02, 0x03, 0x04,
        ]);

        check_codec_and_corruption::<HandshakeAcceptData>(&data, &bytes);
    }

    #[test]
    fn codec_NackData() {
        let data = NackData {
            error_code: 0x01020304,
        };
        let bytes = vec![
            // error code
            0x01, 0x02, 0x03, 0x04,
        ];

        check_codec_and_corruption::<NackData>(&data, &bytes);
    }

    #[test]
    fn codec_RelayData() {
        let data = RelayData {
            peer: NeighborAddress {
                addrbytes: PeerAddress([
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f,
                ]),
                port: 12345,
                public_key_hash: Hash160::from_bytes(
                    &hex_bytes("1111111111111111111111111111111111111111").unwrap(),
                )
                .unwrap(),
            },
            seq: 0x01020304,
        };
        let bytes = vec![
            // peer.addrbytes
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, // peer.port
            0x30, 0x39, // peer.public_key_hash
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, // seq
            0x01, 0x02, 0x03, 0x04,
        ];

        check_codec_and_corruption::<RelayData>(&data, &bytes);
    }

    #[test]
    fn codec_BlocksAvailable() {
        let data = BlocksAvailableData {
            available: vec![
                (ConsensusHash([0x11; 20]), BurnchainHeaderHash([0x22; 32])),
                (ConsensusHash([0x33; 20]), BurnchainHeaderHash([0x44; 32])),
            ],
        };
        let bytes = vec![
            // length
            0x00, 0x00, 0x00, 0x02, // first tuple
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
            0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
            0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, // second tuple
            0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
            0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
        ];

        check_codec_and_corruption::<BlocksAvailableData>(&data, &bytes);
    }

    #[test]
    fn codec_NatPunch() {
        let data = NatPunchData {
            addrbytes: PeerAddress([0x1; 16]),
            port: 0x1234,
            nonce: 0x56789abc,
        };
        let bytes = vec![
            // peer address
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, // port
            0x12, 0x34, // nonce
            0x56, 0x78, 0x9a, 0xbc,
        ];

        check_codec_and_corruption::<NatPunchData>(&data, &bytes);
    }

    #[test]
    fn codec_FunaiDBHandshakeAccept() {
        let data = FunaiDBHandshakeData {
            rc_consensus_hash: ConsensusHash([0x01; 20]),
            smart_contracts: vec![
                QualifiedContractIdentifier::parse("SP8QPP8TVXYAXS1VFSERG978A6WKBF59NSYJQEMN.foo")
                    .unwrap(),
                QualifiedContractIdentifier::parse("SP28D54YKFCMRKXBR6BR0E4BPN57S62RSM4XEVPRP.bar")
                    .unwrap(),
            ],
        };
        let bytes = vec![
            // rc consensus hash
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, // len(smart_contracts)
            0x02, // SP8QPP8TVXYAXS1VFSERG978A6WKBF59NSYJQEMN
            0x16, 0x11, 0x7b, 0x59, 0x1a, 0xdf, 0x7c, 0xae, 0xe4, 0x3b, 0x7e, 0x5d, 0x88, 0x24,
            0xe8, 0x51, 0xb9, 0x35, 0xbc, 0xa9, 0xae, // len(foo)
            0x03, // foo
            0x66, 0x6f, 0x6f, // SP28D54YKFCMRKXBR6BR0E4BPN57S62RSM4XEVPRP
            0x16, 0x90, 0xd2, 0x93, 0xd3, 0x7b, 0x29, 0x89, 0xf5, 0x78, 0x32, 0xf0, 0x07, 0x11,
            0x76, 0xa9, 0x4f, 0x93, 0x0b, 0x19, 0xa1, // len(bar)
            0x03, // bar
            0x62, 0x61, 0x72,
        ];

        check_codec_and_corruption::<FunaiDBHandshakeData>(&data, &bytes);
    }

    #[test]
    fn codec_FunaiDBGetChunkInvData() {
        let data = FunaiDBGetChunkInvData {
            contract_id: QualifiedContractIdentifier::parse(
                "SP8QPP8TVXYAXS1VFSERG978A6WKBF59NSYJQEMN.foo",
            )
            .unwrap(),
            rc_consensus_hash: ConsensusHash([0x01; 20]),
        };

        let bytes = vec![
            // SP8QPP8TVXYAXS1VFSERG978A6WKBF59NSYJQEMN
            0x16, 0x11, 0x7b, 0x59, 0x1a, 0xdf, 0x7c, 0xae, 0xe4, 0x3b, 0x7e, 0x5d, 0x88, 0x24,
            0xe8, 0x51, 0xb9, 0x35, 0xbc, 0xa9, 0xae, // len(foo)
            0x03, // foo
            0x66, 0x6f, 0x6f, // rc consensus hash
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        ];

        check_codec_and_corruption::<FunaiDBGetChunkInvData>(&data, &bytes);
    }

    #[test]
    fn codec_FunaiDBChunkInvData() {
        let data = FunaiDBChunkInvData {
            slot_versions: vec![0, 1, 2, 3],
            num_outbound_replicas: 4,
        };

        let bytes = vec![
            // len(slot_versions)
            0x00, 0x00, 0x00, 0x04, // 0u32
            0x00, 0x00, 0x00, 0x00, // 1u32
            0x00, 0x00, 0x00, 0x01, // 2u32
            0x00, 0x00, 0x00, 0x02, // 3u32
            0x00, 0x00, 0x00, 0x03, // num_outbound_replicas
            0x00, 0x00, 0x00, 0x04,
        ];

        check_codec_and_corruption::<FunaiDBChunkInvData>(&data, &bytes);
    }

    #[test]
    fn codec_FunaiDBGetChunkData() {
        let data = FunaiDBGetChunkData {
            contract_id: QualifiedContractIdentifier::parse(
                "SP8QPP8TVXYAXS1VFSERG978A6WKBF59NSYJQEMN.foo",
            )
            .unwrap(),
            rc_consensus_hash: ConsensusHash([0x01; 20]),
            slot_id: 2,
            slot_version: 3,
        };

        let bytes = vec![
            // SP8QPP8TVXYAXS1VFSERG978A6WKBF59NSYJQEMN
            0x16, 0x11, 0x7b, 0x59, 0x1a, 0xdf, 0x7c, 0xae, 0xe4, 0x3b, 0x7e, 0x5d, 0x88, 0x24,
            0xe8, 0x51, 0xb9, 0x35, 0xbc, 0xa9, 0xae, // len(foo)
            0x03, // foo
            0x66, 0x6f, 0x6f, // rc consensus hash
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, // slot id
            0x00, 0x00, 0x00, 0x02, // slot version
            0x00, 0x00, 0x00, 0x03,
        ];

        check_codec_and_corruption::<FunaiDBGetChunkData>(&data, &bytes);
    }

    #[test]
    fn codec_FunaiDBChunkData() {
        let data = FunaiDBChunkData {
            slot_id: 2,
            slot_version: 3,
            sig: MessageSignature::from_raw(&vec![0x44; 65]),
            data: vec![
                0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            ],
        };

        let bytes = vec![
            // slot id
            0x00, 0x00, 0x00, 0x02, // slot version
            0x00, 0x00, 0x00, 0x03, // signature
            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, // length
            0x00, 0x00, 0x00, 0x0b, // data
            0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ];

        check_codec_and_corruption::<FunaiDBChunkData>(&data, &bytes);
    }

    #[test]
    fn codec_FunaiDBPushChunkData() {
        let data = FunaiDBChunkData {
            slot_id: 2,
            slot_version: 3,
            sig: MessageSignature::from_raw(&vec![0x44; 65]),
            data: vec![
                0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            ],
        };

        let push_data = FunaiDBPushChunkData {
            contract_id: QualifiedContractIdentifier::parse(
                "SP8QPP8TVXYAXS1VFSERG978A6WKBF59NSYJQEMN.foo",
            )
            .unwrap(),
            rc_consensus_hash: ConsensusHash([0x01; 20]),
            chunk_data: data,
        };

        let bytes = vec![
            // SP8QPP8TVXYAXS1VFSERG978A6WKBF59NSYJQEMN
            0x16, 0x11, 0x7b, 0x59, 0x1a, 0xdf, 0x7c, 0xae, 0xe4, 0x3b, 0x7e, 0x5d, 0x88, 0x24,
            0xe8, 0x51, 0xb9, 0x35, 0xbc, 0xa9, 0xae, // len(foo)
            0x03, // foo
            0x66, 0x6f, 0x6f, // rc consensus hash
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, // slot id
            0x00, 0x00, 0x00, 0x02, // slot version
            0x00, 0x00, 0x00, 0x03, // signature
            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, // length
            0x00, 0x00, 0x00, 0x0b, // data
            0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ];

        check_codec_and_corruption::<FunaiDBPushChunkData>(&push_data, &bytes);
    }

    #[test]
    fn codec_GetNakamotoInv() {
        let get_nakamoto_inv = GetNakamotoInvData {
            consensus_hash: ConsensusHash([0x55; 20]),
        };

        let get_nakamoto_inv_bytes: Vec<u8> = vec![
            // consensus hash
            0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
            0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
        ];

        check_codec_and_corruption::<GetNakamotoInvData>(
            &get_nakamoto_inv,
            &get_nakamoto_inv_bytes,
        );
    }

    #[test]
    fn codec_NakamotoInv() {
        let nakamoto_inv = NakamotoInvData {
            tenures: BitVec::<2100>::try_from(
                // 0xdd
                vec![
                    true, false, true, true, true, false, true, true, // 0xee
                    false, true, true, true, false, true, true, true, // 0xaa
                    false, true, false, true, false, true, false, true, // 0xdd
                    true, false, true, true, true, false, true, true, // 0xbb
                    true, true, false, true, true, true, false, true, // 0xee
                    false, true, true, true, false, true, true, true, // 0xee
                    false, true, true, true, false, true, true, true, // 0xff
                    true, true, true, true, true, true, true, true,
                ]
                .as_slice(),
            )
            .unwrap(),
        };

        let nakamoto_inv_bytes = vec![
            // bitlen
            0x00, 0x40, // vec len
            0x00, 0x00, 0x00, 0x08, // bits
            0xdd, 0xee, 0xaa, 0xdd, 0xbb, 0xee, 0xee, 0xff,
        ];

        check_codec_and_corruption::<NakamotoInvData>(&nakamoto_inv, &nakamoto_inv_bytes);

        // should fail
        let nakamoto_inv_bytes = vec![
            // bitlen
            0x00, 0x20, // vec len
            0x00, 0x00, 0x00, 0x05, // bits
            0x00, 0x00, 0x00, 0x00,
        ];

        let _ = NakamotoInvData::consensus_deserialize(&mut &nakamoto_inv_bytes[..]).unwrap_err();

        // should fail
        let nakamoto_inv_bytes = vec![
            // bitlen
            0x00, 0x21, // vec len
            0x00, 0x00, 0x00, 0x04, // bits
            0x00, 0x00, 0x00, 0x00,
        ];

        let _ = NakamotoInvData::consensus_deserialize(&mut &nakamoto_inv_bytes[..]).unwrap_err();
    }

    #[test]
    fn codec_FunaiMessage() {
        let payloads: Vec<FunaiMessageType> = vec![
            FunaiMessageType::Handshake(HandshakeData {
                addrbytes: PeerAddress([
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f,
                ]),
                port: 12345,
                services: 0x0001,
                node_public_key: FunaiPublicKeyBuffer::from_bytes(
                    &hex_bytes(
                        "034e316be04870cef1795fba64d581cf64bad0c894b01a068fb9edf85321dcd9bb",
                    )
                    .unwrap(),
                )
                .unwrap(),
                expire_block_height: 0x0102030405060708,
                data_url: UrlString::try_from("https://the-new-interwebs.com:4008/the-data")
                    .unwrap(),
            }),
            FunaiMessageType::HandshakeAccept(HandshakeAcceptData {
                heartbeat_interval: 0x01020304,
                handshake: HandshakeData {
                    addrbytes: PeerAddress([
                        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                        0x0c, 0x0d, 0x0e, 0x0f,
                    ]),
                    port: 12345,
                    services: 0x0001,
                    node_public_key: FunaiPublicKeyBuffer::from_bytes(
                        &hex_bytes(
                            "034e316be04870cef1795fba64d581cf64bad0c894b01a068fb9edf85321dcd9bb",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    expire_block_height: 0x0102030405060708,
                    data_url: UrlString::try_from("https://the-new-interwebs.com:4008/the-data")
                        .unwrap(),
                },
            }),
            FunaiMessageType::HandshakeReject,
            FunaiMessageType::GetNeighbors,
            FunaiMessageType::Neighbors(NeighborsData {
                neighbors: vec![
                    NeighborAddress {
                        addrbytes: PeerAddress([
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                            0x0c, 0x0d, 0x0e, 0x0f,
                        ]),
                        port: 12345,
                        public_key_hash: Hash160::from_bytes(
                            &hex_bytes("1111111111111111111111111111111111111111").unwrap(),
                        )
                        .unwrap(),
                    },
                    NeighborAddress {
                        addrbytes: PeerAddress([
                            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                            0x1c, 0x1d, 0x1e, 0x1f,
                        ]),
                        port: 23456,
                        public_key_hash: Hash160::from_bytes(
                            &hex_bytes("2222222222222222222222222222222222222222").unwrap(),
                        )
                        .unwrap(),
                    },
                ],
            }),
            FunaiMessageType::GetPoxInv(GetPoxInv {
                consensus_hash: ConsensusHash([0x55; 20]),
                num_cycles: GETPOXINV_MAX_BITLEN as u16,
            }),
            FunaiMessageType::PoxInv(PoxInvData {
                bitlen: 2,
                pox_bitvec: vec![0x03],
            }),
            FunaiMessageType::GetBlocksInv(GetBlocksInv {
                consensus_hash: ConsensusHash([0x55; 20]),
                num_blocks: 32,
            }),
            FunaiMessageType::BlocksInv(BlocksInvData {
                bitlen: 2,
                block_bitvec: vec![0x03],
                microblocks_bitvec: vec![0x03],
            }),
            FunaiMessageType::BlocksAvailable(BlocksAvailableData {
                available: vec![
                    (ConsensusHash([0x11; 20]), BurnchainHeaderHash([0x22; 32])),
                    (ConsensusHash([0x33; 20]), BurnchainHeaderHash([0x44; 32])),
                ],
            }),
            FunaiMessageType::MicroblocksAvailable(BlocksAvailableData {
                available: vec![
                    (ConsensusHash([0x11; 20]), BurnchainHeaderHash([0x22; 32])),
                    (ConsensusHash([0x33; 20]), BurnchainHeaderHash([0x44; 32])),
                ],
            }),
            // TODO: Blocks
            // TODO: Microblocks
            // TODO: Transaction
            FunaiMessageType::Nack(NackData {
                error_code: 0x01020304,
            }),
            FunaiMessageType::Ping(PingData { nonce: 0x01020304 }),
            FunaiMessageType::Pong(PongData { nonce: 0x01020304 }),
            FunaiMessageType::NatPunchRequest(0x12345678),
            FunaiMessageType::NatPunchReply(NatPunchData {
                addrbytes: PeerAddress([
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f,
                ]),
                port: 12345,
                nonce: 0x12345678,
            }),
            FunaiMessageType::FunaiDBHandshakeAccept(
                HandshakeAcceptData {
                    heartbeat_interval: 0x01020304,
                    handshake: HandshakeData {
                        addrbytes: PeerAddress([
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                            0x0c, 0x0d, 0x0e, 0x0f,
                        ]),
                        port: 12345,
                        services: 0x0001,
                        node_public_key: FunaiPublicKeyBuffer::from_bytes(
                            &hex_bytes(
                                "034e316be04870cef1795fba64d581cf64bad0c894b01a068fb9edf85321dcd9bb",
                            )
                            .unwrap(),
                        )
                        .unwrap(),
                        expire_block_height: 0x0102030405060708,
                        data_url: UrlString::try_from("https://the-new-interwebs.com:4008/the-data")
                            .unwrap(),
                    },
                },
                FunaiDBHandshakeData {
                    rc_consensus_hash: ConsensusHash([0x01; 20]),
                    smart_contracts: vec![QualifiedContractIdentifier::parse("SP8QPP8TVXYAXS1VFSERG978A6WKBF59NSYJQEMN.foo").unwrap(), QualifiedContractIdentifier::parse("SP28D54YKFCMRKXBR6BR0E4BPN57S62RSM4XEVPRP.bar").unwrap()]
                }
            ),
            FunaiMessageType::FunaiDBGetChunkInv(FunaiDBGetChunkInvData {
                contract_id: QualifiedContractIdentifier::parse("SP8QPP8TVXYAXS1VFSERG978A6WKBF59NSYJQEMN.foo").unwrap(),
                rc_consensus_hash: ConsensusHash([0x01; 20]),
            }),
            FunaiMessageType::FunaiDBChunkInv(FunaiDBChunkInvData {
                slot_versions: vec![0, 1, 2, 3],
                num_outbound_replicas: 4,
            }),
            FunaiMessageType::FunaiDBGetChunk(FunaiDBGetChunkData {
                contract_id: QualifiedContractIdentifier::parse("SP8QPP8TVXYAXS1VFSERG978A6WKBF59NSYJQEMN.foo").unwrap(),
                rc_consensus_hash: ConsensusHash([0x01; 20]),
                slot_id: 2,
                slot_version: 3
            }),
            FunaiMessageType::FunaiDBChunk(FunaiDBChunkData {
                slot_id: 2,
                slot_version: 3,
                sig: MessageSignature::from_raw(&vec![0x44; 65]),
                data: vec![0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
            }),
            FunaiMessageType::FunaiDBPushChunk(FunaiDBPushChunkData {
                contract_id: QualifiedContractIdentifier::parse("SP8QPP8TVXYAXS1VFSERG978A6WKBF59NSYJQEMN.foo").unwrap(),
                rc_consensus_hash: ConsensusHash([0x01; 20]),
                chunk_data: FunaiDBChunkData {
                    slot_id: 2,
                    slot_version: 3,
                    sig: MessageSignature::from_raw(&vec![0x44; 65]),
                    data: vec![0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
                }
            }),
            FunaiMessageType::GetNakamotoInv(GetNakamotoInvData {
                consensus_hash: ConsensusHash([0x01; 20]),
            }),
            FunaiMessageType::NakamotoInv(NakamotoInvData {
                tenures: BitVec::<2100>::try_from(
                    // 0xdd
                    vec![true, true, false, true, true, true, false, true,
                    // 0xee
                    true, true, true, false, true, true, true, false,
                    // 0xaa
                    true, false, true, false, true, false, true, false,
                    // 0xdd
                    true, true, false, true, true, true, false, true,
                    // 0xbb
                    true, false, true, true, true, false, true, true,
                    // 0xee
                    true, true, true, false, true, true, true, false,
                    // 0xee
                    true, true, true, false, true, true, true, false,
                    // 0xff
                    true, true, true, true, true, true, true, true].as_slice()
                ).unwrap()
            }),
        ];

        let mut maximal_relayers: Vec<RelayData> = vec![];
        let mut too_many_relayers: Vec<RelayData> = vec![];
        for i in 0..MAX_RELAYERS_LEN {
            let next_relayer = RelayData {
                peer: NeighborAddress {
                    addrbytes: PeerAddress([
                        i as u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                        0x0c, 0x0d, 0x0e, 0x0f,
                    ]),
                    port: 12345 + (i as u16),
                    public_key_hash: Hash160::from_bytes(
                        &hex_bytes("1111111111111111111111111111111111111111").unwrap(),
                    )
                    .unwrap(),
                },
                seq: 0x01020304 + i,
            };
            too_many_relayers.push(next_relayer.clone());
            maximal_relayers.push(next_relayer);
        }
        too_many_relayers.push(RelayData {
            peer: NeighborAddress {
                addrbytes: PeerAddress([
                    0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f,
                ]),
                port: 65535,
                public_key_hash: Hash160::from_bytes(
                    &hex_bytes("1111111111111111111111111111111111111111").unwrap(),
                )
                .unwrap(),
            },
            seq: 0x010203ff,
        });

        let mut relayers_bytes: Vec<u8> = vec![];
        maximal_relayers
            .consensus_serialize(&mut relayers_bytes)
            .unwrap();

        let mut too_many_relayer_bytes: Vec<u8> = vec![];
        too_many_relayers
            .consensus_serialize(&mut too_many_relayer_bytes)
            .unwrap();

        for payload in &payloads {
            // just testing codec; don't worry about signatures
            // (only payload_len must be valid)
            let mut payload_bytes: Vec<u8> = vec![];
            payload.consensus_serialize(&mut payload_bytes).unwrap();

            let preamble = Preamble {
                peer_version: 0x01020304,
                network_id: 0x05060708,
                seq: 0x090a0b0c,
                burn_block_height: 0x00001122,
                burn_block_hash: BurnchainHeaderHash([0x11; 32]),
                burn_stable_block_height: 0x00001111,
                burn_stable_block_hash: BurnchainHeaderHash([0x22; 32]),
                additional_data: 0x33333333,
                signature: MessageSignature::from_raw(&vec![0x44; 65]),
                payload_len: (relayers_bytes.len() + payload_bytes.len()) as u32,
            };

            let funai_message = FunaiMessage {
                preamble: preamble.clone(),
                relayers: maximal_relayers.clone(),
                payload: payload.clone(),
            };

            let mut funai_message_bytes: Vec<u8> = vec![];
            preamble
                .consensus_serialize(&mut funai_message_bytes)
                .unwrap();
            funai_message_bytes.append(&mut relayers_bytes.clone());
            funai_message_bytes.append(&mut payload_bytes.clone());

            test_debug!(
                "Test {}-byte relayer, {}-byte payload {:?}",
                relayers_bytes.len(),
                payload_bytes.len(),
                &payload
            );
            check_codec_and_corruption::<FunaiMessage>(&funai_message, &funai_message_bytes);

            // can't have too many relayers
            let mut preamble_too_many_relayers = preamble.clone();
            preamble_too_many_relayers.payload_len =
                (too_many_relayer_bytes.len() + payload_bytes.len() + 1) as u32;

            let funai_message_too_many_relayers = FunaiMessage {
                preamble: preamble_too_many_relayers.clone(),
                relayers: too_many_relayers.clone(),
                payload: payload.clone(),
            };
            assert!(check_deserialize_failure(&funai_message_too_many_relayers));
        }
    }

    #[test]
    fn codec_sign_and_verify() {
        let privkey = Secp256k1PrivateKey::new();
        let pubkey_buf =
            FunaiPublicKeyBuffer::from_public_key(&Secp256k1PublicKey::from_private(&privkey));

        let mut ping = FunaiMessage::new(
            PEER_VERSION_TESTNET,
            0x9abcdef0,
            12345,
            &BurnchainHeaderHash([0x11; 32]),
            12339,
            &BurnchainHeaderHash([0x22; 32]),
            FunaiMessageType::Ping(PingData { nonce: 0x01020304 }),
        );

        ping.sign(444, &privkey).unwrap();
        ping.verify_secp256k1(&pubkey_buf).unwrap();
    }

    #[test]
    fn codec_funai_public_key_roundtrip() {
        for i in 0..100 {
            let privkey = Secp256k1PrivateKey::new();
            let pubkey = Secp256k1PublicKey::from_private(&privkey);

            let pubkey_buf = FunaiPublicKeyBuffer::from_public_key(&pubkey);
            let pubkey_2 = pubkey_buf.to_public_key().unwrap();

            assert_eq!(pubkey, pubkey_2);
        }
    }

    #[test]
    fn blocks_inv_compress_bools() {
        let block_flags = vec![
            true, true, true, false, false, false, false, true, true, false, true,
        ];
        let block_bitvec = BlocksInvData::compress_bools(&block_flags);
        assert_eq!(block_bitvec, vec![0x87, 0x05]);

        let short_block_flags = vec![true, false, true];
        let short_block_bitvec = BlocksInvData::compress_bools(&short_block_flags);
        assert_eq!(short_block_bitvec, vec![0x05]);
    }
}
