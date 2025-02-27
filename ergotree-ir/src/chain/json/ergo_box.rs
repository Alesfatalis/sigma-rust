use crate::chain::ergo_box::box_value::BoxValue;
use crate::chain::ergo_box::BoxId;
use crate::chain::ergo_box::BoxTokens;
use crate::chain::ergo_box::ErgoBox;
use crate::chain::ergo_box::ErgoBoxCandidate;
use crate::chain::ergo_box::NonMandatoryRegisters;
use crate::chain::ergo_box::RegisterValue;
use crate::chain::token::Token;
use crate::chain::tx_id::TxId;
use crate::ergo_tree::ErgoTree;
use crate::serialization::SigmaParsingError;
use crate::serialization::SigmaSerializationError;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::convert::TryFrom;
use core::convert::TryInto;
use core::str::FromStr;
use ergo_chain_types::Base16DecodedBytes;

extern crate derive_more;
use derive_more::From;

use serde::{Deserialize, Serialize};
use thiserror::Error;

mod box_value;

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct ErgoBoxJson {
    #[serde(rename = "boxId", alias = "id")]
    pub box_id: Option<BoxId>,
    /// amount of money associated with the box
    #[serde(rename = "value")]
    pub value: BoxValue,
    /// guarding script, which should be evaluated to true in order to open this box
    #[serde(rename = "ergoTree", with = "super::ergo_tree")]
    pub ergo_tree: ErgoTree,
    /// secondary tokens the box contains
    #[serde(rename = "assets")]
    pub tokens: Vec<Token>,
    ///  additional registers the box can carry over
    #[serde(rename = "additionalRegisters")]
    pub additional_registers: NonMandatoryRegisters,
    /// height when a transaction containing the box was created.
    /// This height is declared by user and should not exceed height of the block,
    /// containing the transaction with this box.
    #[serde(rename = "creationHeight")]
    pub creation_height: u32,
    /// id of transaction which created the box
    #[serde(rename = "transactionId", alias = "txId")]
    pub transaction_id: TxId,
    /// number of box (from 0 to total number of boxes the transaction with transactionId created - 1)
    #[serde(rename = "index")]
    pub index: u16,
}

impl TryFrom<ErgoBoxJson> for ErgoBox {
    type Error = ErgoBoxFromJsonError;
    fn try_from(box_json: ErgoBoxJson) -> Result<Self, Self::Error> {
        let tokens = if box_json.tokens.is_empty() {
            None
        } else {
            Some(box_json.tokens.try_into().map_err(|_| {
                SigmaSerializationError::NotSupported(
                    "More than ErgoBox::MAX_TOKENS_COUNT tokens are not allowed in a box"
                        .to_string(),
                )
            })?)
        };
        let box_with_zero_id = ErgoBox {
            box_id: BoxId::zero(),
            value: box_json.value,
            ergo_tree: box_json.ergo_tree,
            tokens,
            additional_registers: box_json.additional_registers,
            creation_height: box_json.creation_height,
            transaction_id: box_json.transaction_id,
            index: box_json.index,
        };
        let box_id = box_with_zero_id.calc_box_id()?;
        let ergo_box = ErgoBox {
            box_id,
            ..box_with_zero_id
        };
        match box_json.box_id {
            Some(box_id) => {
                if ergo_box.box_id() == box_id {
                    Ok(ergo_box)
                } else {
                    //dbg!(&ergo_box);
                    Err(ErgoBoxFromJsonError::InvalidBoxId {
                        json: box_id,
                        actual: ergo_box.box_id(),
                    })
                }
            }
            None => Ok(ergo_box),
        }
    }
}

impl From<ErgoBox> for ErgoBoxJson {
    fn from(ergo_box: ErgoBox) -> ErgoBoxJson {
        let tokens = ergo_box
            .tokens
            .as_ref()
            .map(BoxTokens::as_vec)
            .cloned()
            .unwrap_or_default(); // JSON serialization for assets requires that tokens be [] instead of null
        ErgoBoxJson {
            box_id: Some(ergo_box.box_id),
            value: ergo_box.value,
            ergo_tree: ergo_box.ergo_tree,
            tokens,
            additional_registers: ergo_box.additional_registers,
            creation_height: ergo_box.creation_height,
            transaction_id: ergo_box.transaction_id,
            index: ergo_box.index,
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct ErgoBoxCandidateJson {
    /// amount of money associated with the box
    #[serde(rename = "value")]
    pub value: BoxValue,
    /// guarding script, which should be evaluated to true in order to open this box
    #[serde(rename = "ergoTree", with = "super::ergo_tree")]
    pub ergo_tree: ErgoTree,
    /// secondary tokens the box contains
    #[serde(rename = "assets")]
    pub tokens: Vec<Token>,
    ///  additional registers the box can carry over
    #[serde(rename = "additionalRegisters")]
    pub additional_registers: NonMandatoryRegisters,
    /// height when a transaction containing the box was created.
    /// This height is declared by user and should not exceed height of the block,
    /// containing the transaction with this box.
    #[serde(rename = "creationHeight")]
    pub creation_height: u32,
}

impl From<ErgoBoxCandidate> for ErgoBoxCandidateJson {
    fn from(ergo_box_candidate: ErgoBoxCandidate) -> Self {
        let tokens = ergo_box_candidate
            .tokens
            .as_ref()
            .map(BoxTokens::as_vec)
            .cloned()
            .unwrap_or_default(); // JSON serialization for assets requires that tokens be [] instead of null
        ErgoBoxCandidateJson {
            value: ergo_box_candidate.value,
            ergo_tree: ergo_box_candidate.ergo_tree,
            tokens,
            additional_registers: ergo_box_candidate.additional_registers,
            creation_height: ergo_box_candidate.creation_height,
        }
    }
}

impl TryFrom<ErgoBoxCandidateJson> for ErgoBoxCandidate {
    type Error = ErgoBoxFromJsonError;
    fn try_from(box_json: ErgoBoxCandidateJson) -> Result<Self, Self::Error> {
        let tokens = if box_json.tokens.is_empty() {
            None
        } else {
            Some(box_json.tokens.try_into().map_err(|_| {
                SigmaSerializationError::NotSupported(
                    "More than ErgoBox::MAX_TOKENS_COUNT tokens are not allowed in a box"
                        .to_string(),
                )
            })?)
        };
        Ok(ErgoBoxCandidate {
            value: box_json.value,
            ergo_tree: box_json.ergo_tree,
            tokens,
            additional_registers: box_json.additional_registers,
            creation_height: box_json.creation_height,
        })
    }
}

/// Errors on parsing ErgoBox from JSON
#[derive(Error, PartialEq, Eq, Debug, Clone)]
pub enum ErgoBoxFromJsonError {
    /// Box id parsed from JSON differs from calculated from box serialized bytes
    #[error(
        "Box id parsed from JSON {json} differs from calculated from box serialized bytes {actual}"
    )]
    InvalidBoxId { json: BoxId, actual: BoxId },
    /// Box serialization failed (id calculation)
    #[error("Box serialization failed (id calculation): {0}")]
    SerializationError(#[from] SigmaSerializationError),
}

#[derive(Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct ConstantHolder(#[serde(deserialize_with = "super::t_as_string_or_struct")] RichConstant);

impl From<ConstantHolder> for RegisterValue {
    fn from(ch: ConstantHolder) -> Self {
        RegisterValue::sigma_parse_bytes(ch.0.raw_value.0.as_slice())
    }
}

#[derive(Deserialize, PartialEq, Eq, Debug, Clone)]
struct RichConstant {
    #[serde(rename = "rawValue", alias = "serializedValue")]
    raw_value: ConstantWrapper,
}

#[derive(Deserialize, PartialEq, Eq, Debug, Clone)]
#[serde(try_from = "Base16DecodedBytes")]
struct ConstantWrapper(Vec<u8>);

#[derive(Error, PartialEq, Eq, Debug, Clone, From)]
pub enum ConstantParsingError {
    #[error("Base16 decoding error: {0}")]
    DecodeError(base16::DecodeError),
    #[error("Deserialization error: {0}")]
    DeserializationError(SigmaParsingError),
}

impl TryFrom<Base16DecodedBytes> for ConstantWrapper {
    type Error = ConstantParsingError;

    fn try_from(Base16DecodedBytes(bytes): Base16DecodedBytes) -> Result<Self, Self::Error> {
        Ok(ConstantWrapper(bytes))
    }
}

impl FromStr for RichConstant {
    type Err = ConstantParsingError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let Base16DecodedBytes(bytes) = Base16DecodedBytes::try_from(s)?;
        Ok(RichConstant {
            raw_value: ConstantWrapper(bytes),
        })
    }
}

#[allow(clippy::panic)]
#[allow(clippy::unwrap_used)]
#[cfg(test)]
#[cfg(feature = "arbitrary")]
mod tests {
    use core::convert::TryInto;

    use crate::chain::ergo_box::ErgoBox;
    use crate::chain::ergo_box::NonMandatoryRegisterId;
    use crate::chain::ergo_box::NonMandatoryRegisters;
    use crate::chain::token::Token;
    use pretty_assertions::assert_eq;
    use proptest::prelude::*;

    proptest! {

        #[test]
        fn ergo_box_roundtrip(b in any::<ErgoBox>()) {
            let j = serde_json::to_string(&b)?;
            // eprintln!("{}", j);
            let b_parsed: ErgoBox = serde_json::from_str(&j)?;
            prop_assert_eq![b, b_parsed];
        }

    }

    #[test]
    fn parse_registers() {
        let json = r#"
        {"R4":"05b0b5cad8e6dbaef44a","R5":"048ce5d4e505"}
        "#;
        let regs: NonMandatoryRegisters = serde_json::from_str(json).unwrap();
        assert_eq!(regs.len(), 2)
    }

    #[test]
    fn parse_registers_explorer_api_v1() {
        let json = r#"
            {"R4":{"serializedValue":"0500","sigmaType":"SLong","renderedValue":"0"}}
                                                                                                                                           "#;
        let regs: NonMandatoryRegisters = serde_json::from_str(json).unwrap();
        assert!(regs.get_constant(NonMandatoryRegisterId::R4).is_ok());
    }

    #[test]
    fn parse_registers_explorer_api_v2() {
        let json = r#"
            {
                "R4": {
                    "decodedValue": "Coll(-89,30,-127,32,-20,-100,-42,0,-25,-9,-25,107,-100,27,10,-97,127,127,-93,109,-48,70,51,-111,27,85,107,-116,97,102,87,45)",
                    "valueType": "Coll[Byte]",
                    "rawValue": "0e20a71e8120ec9cd600e7f7e76b9c1b0a9f7f7fa36dd04633911b556b8c6166572d"
                }
            }
        "#;
        let regs: NonMandatoryRegisters = serde_json::from_str(json).unwrap();
        assert!(regs.get_constant(NonMandatoryRegisterId::R4).is_ok());
    }

    #[test]
    fn parse_registers_error() {
        // base16 decoding error
        let json = r#"
        {"R4":"0"}
        "#;
        let regs: Result<NonMandatoryRegisters, _> = serde_json::from_str(json);
        assert!(regs.is_err());
    }

    #[test]
    fn parse_registers_unit() {
        let json = r#" {"R4":"62"} "#;
        let regs: NonMandatoryRegisters = serde_json::from_str(json).unwrap();
        assert_eq!(regs.len(), 1)
    }

    #[test]
    fn parse_ergo_box() {
        let box_json = r#"{
          "boxId": "e56847ed19b3dc6b72828fcfb992fdf7310828cf291221269b7ffc72fd66706e",
          "value": 67500000000,
          "ergoTree": "100204a00b08cd021dde34603426402615658f1d970cfa7c7bd92ac81a8b16eeebff264d59ce4604ea02d192a39a8cc7a70173007301",
          "assets": [],
          "creationHeight": 284761,
          "additionalRegisters": {},
          "transactionId": "9148408c04c2e38a6402a7950d6157730fa7d49e9ab3b9cadec481d7769918e9",
          "index": 1
        }"#;
        let b: ErgoBox = serde_json::from_str(box_json).unwrap();
        assert_eq!(b.value, 67500000000u64.try_into().unwrap());
    }

    #[test]
    fn parse_ergo_box_without_id() {
        let box_json = r#"{
          "value": 67500000000,
          "ergoTree": "100204a00b08cd021dde34603426402615658f1d970cfa7c7bd92ac81a8b16eeebff264d59ce4604ea02d192a39a8cc7a70173007301",
          "assets": [],
          "creationHeight": 284761,
          "additionalRegisters": {},
          "transactionId": "9148408c04c2e38a6402a7950d6157730fa7d49e9ab3b9cadec481d7769918e9",
          "index": 1
        }"#;
        let b: ErgoBox = serde_json::from_str(box_json).unwrap();
        let id: String = b.box_id().into();
        assert_eq!(
            id,
            "e56847ed19b3dc6b72828fcfb992fdf7310828cf291221269b7ffc72fd66706e"
        );
    }

    #[test]
    fn parse_ergo_box_alternative_box_id_field_name() {
        // check that using "id" field name instead of "boxId" also works
        // used in explorer API
        let box_json = r#"{
          "id": "e56847ed19b3dc6b72828fcfb992fdf7310828cf291221269b7ffc72fd66706e",
          "value": 67500000000,
          "ergoTree": "100204a00b08cd021dde34603426402615658f1d970cfa7c7bd92ac81a8b16eeebff264d59ce4604ea02d192a39a8cc7a70173007301",
          "assets": [],
          "creationHeight": 284761,
          "additionalRegisters": {},
          "transactionId": "9148408c04c2e38a6402a7950d6157730fa7d49e9ab3b9cadec481d7769918e9",
          "index": 1
        }"#;
        let b: ErgoBox = serde_json::from_str(box_json).unwrap();
        assert_eq!(b.value, 67500000000u64.try_into().unwrap());
    }

    #[test]
    fn parse_ergo_box_alternative_transaction_id_field_name() {
        // check that using "txId" field name instead of "transactionId" also works
        // used in explorer API
        let box_json = r#"{
          "id": "e56847ed19b3dc6b72828fcfb992fdf7310828cf291221269b7ffc72fd66706e",
          "value": 67500000000,
          "ergoTree": "100204a00b08cd021dde34603426402615658f1d970cfa7c7bd92ac81a8b16eeebff264d59ce4604ea02d192a39a8cc7a70173007301",
          "assets": [],
          "creationHeight": 284761,
          "additionalRegisters": {},
          "txId": "9148408c04c2e38a6402a7950d6157730fa7d49e9ab3b9cadec481d7769918e9",
          "index": 1
        }"#;
        let b: ErgoBox = serde_json::from_str(box_json).unwrap();
        assert_eq!(b.value, 67500000000u64.try_into().unwrap());
    }

    #[test]
    fn parse_ergo_box_from_explorer() {
        let box_json = r#"
        {
            "id": "3e762407d99b006d53b6583adcca08ef690b42fb0b2ed7abf63179eb6b9033b2",
            "txId": "93d344aa527e18e5a221db060ea1a868f46b61e4537e6e5f69ecc40334c15e38",
            "value": 2875858910,
            "index": 0,
            "creationHeight": 352126,
            "ergoTree": "101f0400040004020402040004000402050005000580dac4090580dac409050005c00c05c80104000e20b662db51cf2dc39f110a021c2a31c74f0a1a18ffffbf73e8a051a7b8c0f09ebc0580dac40904040404050005feffffffffffffffff01050005e807050005e807050005a0060101050005c00c05a006d81ed601b2db6501fe730000d602b2a5730100d603c17202d604db6308a7d605b27204730200d6068c720502d607db63087202d608b27207730300d6098c720802d60a9472067209d60bb27204730400d60c8c720b02d60db27207730500d60e8c720d02d60f94720c720ed610e4c6a70505d611e4c672020505d612e4c6a70405d613e4c672020405d614b2a5730600d615e4c672140405d61695720a73077215d61795720a72157308d61899c1a77309d619e4c672140505d61a997203730ad61be4c672010405d61ca172189c7212721bd61d9c7213721bd61e9593721d730b730c9d9c721a730d721dd1ededed938cb2db63087201730e0001730fedededed9272037310edec720a720fefed720a720fed939a720672109a72097211939a720c72129a720e7213eded939a721272167213939a721072177211939a72187219721aeded938c720d018c720b01938c7208018c720501938cb27207731100018cb272047312000193721995720f9ca1721b95937212731373149d721c72127216d801d61f997218721c9c9593721f7315731695937210731773189d721f7210721795720f95917216731992721e731a731b95917217731c90721e731d92721e731e",
            "address": "9aFbqNsmDwSxCdcLDKmSxVTL58ms2A39Rpn2zodVzkBN5MzB8zvW5PFX551W1A5vUdFJ3yxwvwgYTTS4JrPQcb5qxBbRDJkGNikuqHRXhnbniK4ajumEj7ot2o7DbcNFaM674fWufQzSGS1KtgMw95ZojyqhswUNbKpYDV1PhKw62bEMdJL9vAvzea4KwKXGUTdYYkcPdQKFWXfrdo2nTS3ucFNxqyTRB3VtZk7AWE3eeNHFcXZ1kLkfrX1ZBjpQ7qrBemHk4KZgS8fzmm6hPSZThiVVtBfQ2CZhJQdAZjRwGrw5TDcZ4BBDAZxg9h13vZ7tQSPsdAtjMFQT1DxbqAruKxX38ZwaQ3UfWmbBpbJEThAQaS4gsCBBSjswrv8BvupxaHZ4oQmA2LZiz4nYaPr8MJtR4fbM9LErwV4yDVMb873bRE5TBF59NipUyHAir7ysajPjbGc8aRLqsMVjntFSCFYx7822RBrj7RRX11CpiGK6vdfKHe3k14EH6YaNXvGSq8DrfNHEK4SgreknTqCgjL6i3EMZKPCW8Lao3Q5tbJFnFjEyntpUDf5zfGgFURxzobeEY4USqFaxyppHkgLjQuFQtDWbYVu3ztQL6hdWHjZXMK4VVvEDeLd1woebD1CyqS5kJHpGa78wQZ4iKygw4ijYrodZpqqEwTXdqwEB6xaLfkxZCBPrYPST3xz67GGTBUFy6zkXP5vwVVM5gWQJFdWCZniAAzBpzHeVq1yzaBp5GTJgr9bfrrAmuX8ra1m125yfeT9sTWroVu",
            "assets": [
                {
                    "tokenId": "2d554219a80c011cc51509e34fa4950965bb8e01de4d012536e766c9ca08bc2c",
                    "index": 0,
                    "amount": 99999999998
                },
                {
                    "tokenId": "bcd5db3a2872f279ef89edaa51a9344a6095ea1f03396874b695b5ba95ff602e",
                    "index": 1,
                    "amount": 99995619990
                },
                {
                    "tokenId": "9f90c012e03bf99397e363fb1571b7999941e0862a217307e3467ee80cf53af7",
                    "index": 2,
                    "amount": 1
                }
            ],
            "additionalRegisters": {
                "R4": "0504",
                "R5": "05d4d59604"
            },
            "spentTransactionId": null,
            "mainChain": true
        }
        "#;
        let b: ErgoBox = serde_json::from_str(box_json).unwrap();
        assert_eq!(b.value, 2875858910u64.try_into().unwrap());
    }

    #[test]
    fn parse_token_amount_as_num() {
        let token_json = r#"
        {
            "tokenId": "2d554219a80c011cc51509e34fa4950965bb8e01de4d012536e766c9ca08bc2c",
            "amount": 99999999998
        }"#;
        let t: Token = serde_json::from_str(token_json).unwrap();
        assert_eq!(t.amount, 99999999998u64.try_into().unwrap());
    }

    #[test]
    fn parse_token_amount_as_str() {
        let token_json = r#"
        {
            "tokenId": "2d554219a80c011cc51509e34fa4950965bb8e01de4d012536e766c9ca08bc2c",
            "amount": "99999999998"
        }"#;
        let t: Token = serde_json::from_str(token_json).unwrap();
        assert_eq!(t.amount, 99999999998u64.try_into().unwrap());
    }

    #[test]
    fn encode_token_amount_as_num() {
        let token_json = "{\n  \"tokenId\": \"2d554219a80c011cc51509e34fa4950965bb8e01de4d012536e766c9ca08bc2c\",\n  \"amount\": 99999999998\n}";
        let t: Token = serde_json::from_str(token_json).unwrap();
        assert_eq!(t.amount, 99999999998u64.try_into().unwrap());
        let to_json = serde_json::to_string_pretty(&t).unwrap();
        assert_eq!(to_json, token_json);
    }
}
