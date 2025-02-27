# Change Log
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

<!-- next-header -->
## [Unreleased] - ReleaseDate
## [0.28.0] - 2024-08-09
## [0.27.1] - 2023-12-02
## [0.27.0] - 2023-12-02
## [0.26.0] - 2023-10-13

### Added
* Add pretty_print method to ErgoTree and Expr https://github.com/ergoplatform/sigma-rust/pull/729

### Fixed
* Reset interpreter env after lambda call https://github.com/ergoplatform/sigma-rust/pull/728

## [0.25.0] - 2023-10-09

### Added
* Revamped errro messages for ErgoTree evaluation errors https://github.com/ergoplatform/sigma-rust/pull/720

### Fixed
* fix `Coll.slice` to gracefully handle indices out of bounds https://github.com/ergoplatform/sigma-rust/pull/725

## [0.24.1] - 2023-09-20

### Added
* add `Coll[Long]` parsing from an array of strings in Wasm API `Constant.from_js`;
* impl `From` for `EcPoint`;

### Fixed
* updated `wasm-bindgen`with a fix for wrong memory address when exceeding 2GB;

## [0.24.0] - 2023-05-12

### Added
* Introduce Wallet::sign_tx_input; by @greenhat in https://github.com/ergoplatform/sigma-rust/pull/689
* Introduce transaction::verify_tx_input_proof by @greenhat in https://github.com/ergoplatform/sigma-rust/pull/691
* Tuple expression support in register values by @greenhat in https://github.com/ergoplatform/sigma-rust/pull/702
* Include backtrace on error in Expr::check_post_eval_tpe by @greenhat in https://github.com/ergoplatform/sigma-rust/pull/713
* enable TC39 weak ref support in wasm-bindgen by @greenhat in https://github.com/ergoplatform/sigma-rust/pull/682

### Changed
* update wasm-pack build command to use --dev profile for *-alpha builds; by @greenhat in https://github.com/ergoplatform/sigma-rust/pull/697

### Fixed
* fix wrong AvlTree method ids and missing PropertyCall type specialization by @greenhat in https://github.com/ergoplatform/sigma-rust/pull/696
* Store error message in `RegisterValue::Unparseable` and show it on writer-based serialization error by @greenhat in https://github.com/ergoplatform/sigma-rust/pull/699


## [0.23.0] - 2023-02-08

### Added
- serde serialization for NetworkAddress [#667](https://github.com/ergoplatform/sigma-rust/pull/667);
- expose constant value and type in C bindings [#669](https://github.com/ergoplatform/sigma-rust/pull/669)
- Parse tx input's spending proof as either string or struct (explorer API) [#671](https://github.com/ergoplatform/sigma-rust/pull/671);
- Add FullBlock type [#678](https://github.com/ergoplatform/sigma-rust/pull/678);
- Validate parsed ErgoTree header, check no bytes left unconsumed after ErgoTree is parsed [#684](https://github.com/ergoplatform/sigma-rust/pull/684);
- Preserve ContextExtension items order in JSON encoding [#687](https://github.com/ergoplatform/sigma-rust/pull/687);

### Fixed
- Fix scientific notion deserialization with powSolutions d parameter [#668](https://github.com/ergoplatform/sigma-rust/pull/668);

## [0.22.0] - 2022-12-28

### Added
- Diffie-Hellman tuple secret support in wallet API [#665](https://github.com/ergoplatform/sigma-rust/pull/665)

### Fixed
- make various types easier to use in multithread environment (remove `Rc`, switch to `Arc`, implement `Copy`, etc.);

## [0.21.1] - 2022-11-21

### Added
- `ErgoBox::from_box_candidate` in Wasm API [#651](https://github.com/ergoplatform/sigma-rust/pull/651);

### Changed
- uparseable register value should not prevent parsing `ErgoBox` from JSON [#647](https://github.com/ergoplatform/sigma-rust/pull/647);
- rename `NonMandatoryRegisters:get` to `NonMandatoryRegisters::get_constant` and return `None` if the register value is unparseable [#647](https://github.com/ergoplatform/sigma-rust/pull/647);
- add `NonMandatoryRegisters:get` returning new `RegisterValue` holding either a `Constant` or unparseable bytes [#647](https://github.com/ergoplatform/sigma-rust/pull/647);


## [0.21.0] - 2022-10-27

### Changed
- add `type` and `exports` fields in package.json [#637](https://github.com/ergoplatform/sigma-rust/pull/637);
- Fix bottom-up and top-down traverals in the prover (affects nested sigma conjectures) [#644](https://github.com/ergoplatform/sigma-rust/pull/644);
- enable wasm-opt pass, make compiler optional to minimize wasm binary [#646](https://github.com/ergoplatform/sigma-rust/pull/646);

### Fixed (ergo-lib-wasm v0.20.1)
- Fix field names for `Transaction`, `UnsignedTransaction` in EIP-12 format (`.to_js_eip12()`) [#627](https://github.com/ergoplatform/sigma-rust/pull/627);

## [0.20.0] - 2022-09-07

### Changed
- increase max tokens allowed in a box to 122 [#616](https://github.com/ergoplatform/sigma-rust/pull/616);

### Added
- `Transaction::verify_p2pk_input` for P2PK inputs verification [#613](https://github.com/ergoplatform/sigma-rust/pull/613);
- `Constant::to_js` and `from_js` arbitrary JS type to `Constant` conversion [614](https://github.com/ergoplatform/sigma-rust/pull/614);
- add IP v6 support in `PeerAddr::as_http_url` [#617](https://github.com/ergoplatform/sigma-rust/pull/617);

## [0.19.0] - 2022-08-08

### Changed (BREAKING)
- only allow explicit token burning in `TxBuilder` and add token preservation check [#603](https://github.com/ergoplatform/sigma-rust/pull/603);
- remove `min_value_change` parameter in `TxBuilder::new` and add coin preservation check [#605](https://github.com/ergoplatform/sigma-rust/pull/605);

### Changed
- fix distributed signing in case a script reduces to `true` [#609](https://github.com/ergoplatform/sigma-rust/pull/609);
- fix `AtLeast` handling in the prover [#598](https://github.com/ergoplatform/sigma-rust/pull/598);
- improve error messages for constant value parsing from JSON (box registers) [#600](https://github.com/ergoplatform/sigma-rust/pull/600).

## [0.18.0] - 2022-07-14

### Added 
- add Address::content_bytes() in Wasm API [#582](https://github.com/ergoplatform/sigma-rust/pull/582);

### Changed
- fix `peer_discovery()` in Chrome [#584](https://github.com/ergoplatform/sigma-rust/pull/584);
- fix accidental token burn in change box in box selection process [#591](https://github.com/ergoplatform/sigma-rust/pull/591) 

## [0.17.0] - 2022-06-04

### Added 
- Swift bindings for MnemonicGenerator [#573](https://github.com/ergoplatform/sigma-rust/pull/573);
- JSON encoding for TransactionHintsBag type hierarchy [#577](https://github.com/ergoplatform/sigma-rust/pull/577);

### Changed
- eliminate `TransactionContext::get_boxes_to_spend()` and introduce `TransactionContext::get_input_box(box_id: BoxId) -> Option<ErgoBox>` [#574](https://github.com/ergoplatform/sigma-rust/pull/574);
- move `Header` type from `ergotree-ir` to `ergo-chain-types` [#572](https://github.com/ergoplatform/sigma-rust/pull/572);
- fix JSON encoding for no tokens (empty array); [#578](https://github.com/ergoplatform/sigma-rust/pull/578);

## [0.16.1] - 2022-05-04

### Changed
- Convert vendored dependencies of ergo-rest into sub-modules [#571](https://github.com/ergoplatform/sigma-rust/pull/571);

## [0.16.0] - 2022-04-29

### Changed
- REST API implementation is hidden behind the `rest` feature flag [#554](https://github.com/ergoplatform/sigma-rust/pull/554);

### Added 
- arbitrary message signing and verification [#553](https://github.com/ergoplatform/sigma-rust/pull/553);
- `PoPowHeader` type [#551](https://github.com/ergoplatform/sigma-rust/pull/551);
- `TokenId::from_base64` [#555](https://github.com/ergoplatform/sigma-rust/pull/555);
- `Constant` to/from `TokenId`(`Digest32`) conversion [#557](https://github.com/ergoplatform/sigma-rust/pull/557);
- `TxBuilder::set_context_extension` to set a `ContextExtension` for a given input [#560](https://github.com/ergoplatform/sigma-rust/pull/560);
- Serialization for NipopowProof [#562](https://github.com/ergoplatform/sigma-rust/pull/562);
- WASM/swift bindings for message signing/verifying [#564](https://github.com/ergoplatform/sigma-rust/pull/564);
- Add SUnit variant of SType [#566](https://github.com/ergoplatform/sigma-rust/pull/566);
- Node discovery via node's REST API [#558](https://github.com/ergoplatform/sigma-rust/pull/558);
- Add BatchMerkleProof + PoPow Interlink vector verification [#538](https://github.com/ergoplatform/sigma-rust/pull/538);
- add ErgoBox::tx_id() and index() in Wasm API [#561](https://github.com/ergoplatform/sigma-rust/pull/561);

## [0.15.0] - 2022-03-08

### Changed
- Construct ErgoStateContext using last block headers [#450](https://github.com/ergoplatform/sigma-rust/pull/450);

### Added 
- `AvlTree.remove` [#436](https://github.com/ergoplatform/sigma-rust/pull/436);
- `AvlTree.update` [#443](https://github.com/ergoplatform/sigma-rust/pull/443);
- `ReducedTransaction` implementation according to EIP-19 [#442](https://github.com/ergoplatform/sigma-rust/pull/442)
- `AvlTree.get` and `AvlTree.getMany` [#445](https://github.com/ergoplatform/sigma-rust/pull/445);
- `AvlTree.contains` [#437] (https://github.com/ergoplatform/sigma-rust/pull/437);
- `LastBlockUtxoRootHash` [#452](https://github.com/ergoplatform/sigma-rust/pull/452);
- `ExtPubKey` and `DerivationPath` with BIP-32,44 and soft derivation support for Ledger [#448](https://github.com/ergoplatform/sigma-rust/pull/448);
- Modulo binary op [#460](https://github.com/ergoplatform/sigma-rust/pull/460);
- `treeLookup` predefined function [#459](https://github.com/ergoplatform/sigma-rust/pull/459);
- `createAvlTree` predefined function [#466](https://github.com/ergoplatform/sigma-rust/pull/466);
- `ScorexSerializable`, serialization framework of the ergo node [#485](https://github.com/ergoplatform/sigma-rust/pull/485);
- `Wallet::from_mnemonic` [#492](https://github.com/ergoplatform/sigma-rust/pull/492);
- Peer management for p2p networking [#493](https://github.com/ergoplatform/sigma-rust/pull/493);
- C/Swift(iOS, macOS) bindings for ergo-lib [#468](https://github.com/ergoplatform/sigma-rust/pull/468);
- wallet extended secret key derivation [#498](https://github.com/ergoplatform/sigma-rust/pull/498);
- transaction serialization in Wasm API [506](https://github.com/ergoplatform/sigma-rust/pull/506);
- support for `(Int, Int)`, `Coll[Coll[Byte]]`, `Coll[Int]` and `BigInt` types in constant conversion in Wasm API;
- mnemonic generation [#505](https://github.com/ergoplatform/sigma-rust/pull/505);
- arithmetic operations and polynomial interpolation over Galois fields GF(2^192) [#496](https://github.com/ergoplatform/sigma-rust/pull/496);
- Merkle tree support [#521](https://github.com/ergoplatform/sigma-rust/pull/521);
- NiPoPoW proof verification [#517](https://github.com/ergoplatform/sigma-rust/pull/517);
- distributed signatures support [#470](https://github.com/ergoplatform/sigma-rust/pull/470);

### Fixed
- fix `elem_tpe` in `Append` and `Slice` evaluation [#455](https://github.com/ergoplatform/sigma-rust/pull/455)
- fix `CollKind::elem_tpe` [#457](https://github.com/ergoplatform/sigma-rust/pull/457);
- fix a bug with self box lookup in TransactionContext and added checks for box resolution in tx inputs and data_inputs [#462](https://github.com/ergoplatform/sigma-rust/pull/462);
- audit and remove unwraps and panics in ergo-lib [#467](https://github.com/ergoplatform/sigma-rust/pull/467);
- fix missing ContextExtenion support [#458](https://github.com/ergoplatform/sigma-rust/pull/458);
- make `BoxSelection::boxes` of non-empty type [#471](https://github.com/ergoplatform/sigma-rust/pull/471);
- check for allowed ops in `Coll.flatMap` lambda [#472](https://github.com/ergoplatform/sigma-rust/pull/472);
- missing `SGlobal.xor`, `groupGenerator` method eval [#523](https://github.com/ergoplatform/sigma-rust/pull/523);

## [0.14.0] - 2021-10-07

### Added 
- `Header` properties [#433](https://github.com/ergoplatform/sigma-rust/pull/433); 
- `PreHeader` properties [#435](https://github.com/ergoplatform/sigma-rust/pull/435);
- `AvlTree` properties [#432](https://github.com/ergoplatform/sigma-rust/pull/432);
- `AvlTree.insert` [#413](https://github.com/ergoplatform/sigma-rust/pull/413);
- `SubstConstants` [#410](https://github.com/ergoplatform/sigma-rust/pull/410);
- `Box.bytesWithoutRef` [#409](https://github.com/ergoplatform/sigma-rust/pull/409);
- `Downcast` [#408](https://github.com/ergoplatform/sigma-rust/pull/408);
- `Address::P2SH` support [#407](https://github.com/ergoplatform/sigma-rust/pull/407);
- `Context.selfBoxIndex` [#405](https://github.com/ergoplatform/sigma-rust/pull/405);
- Ensure JSON parsing for explorer API [#398](https://github.com/ergoplatform/sigma-rust/pull/398);
- `Box.bytes` [#390](https://github.com/ergoplatform/sigma-rust/pull/390);
- add (Coll[Byte], Coll[Byte]) and (Long, Long) support for Constant conversion in JS [#386](https://github.com/ergoplatform/sigma-rust/pull/386);
- add `ErgoBox::serialized_additional_registers()` in Wasm [#387](https://github.com/ergoplatform/sigma-rust/pull/387);
- add `Transaction::from_unsigned_tx()` to construct from unsigned tx + proofs [#387](https://github.com/ergoplatform/sigma-rust/pull/387);
- extract distinct token ids on tx serialization and expose as `UnsignedTransaction::distinct_token_ids()` in Wasm [#387](https://github.com/ergoplatform/sigma-rust/pull/387);
- add `to_bytes()` for `BoxValue` and `TokenAmount` in Wasm [#387](https://github.com/ergoplatform/sigma-rust/pull/387);
- `Constant::sigma_serialize_bytes()`, `ContextExtension::sigma_serialize_bytes()` in Wasm [#387](https://github.com/ergoplatform/sigma-rust/pull/387);
- `TokenId::as_bytes()` and `BoxId::as_bytes()` in Wasm [#387](https://github.com/ergoplatform/sigma-rust/pull/387);
- add (Coll[Byte], Coll[Byte]) and (Long, Long) support for Constant conversion in JS [#386](https://github.com/ergoplatform/sigma-rust/pull/386);
- Serialization for `SigmaBoolean` types [#341](https://github.com/ergoplatform/sigma-rust/pull/351);
- Diffie-Hellman tuples support in sigma protocol [#315](https://github.com/ergoplatform/sigma-rust/pull/315);
- `Coll.zip` [#350](https://github.com/ergoplatform/sigma-rust/pull/350);
- `BigInt256` 256-bit BigInt [#325](https://github.com/ergoplatform/sigma-rust/pull/325);
- Logical XOR [#349](https://github.com/ergoplatform/sigma-rust/pull/349);
- `groupGenerator` global variable [#340](https://github.com/ergoplatform/sigma-rust/pull/340);
- `GroupElement.getEncoded` method for GroupElement [#335](https://github.com/ergoplatform/sigma-rust/pull/335);
- `Negate` IR node for GroupElement [#334](https://github.com/ergoplatform/sigma-rust/pull/334);
- `Exponentiate` IR node for GroupElement [#321](https://github.com/ergoplatform/sigma-rust/pull/321);
- WASM `to_js_eip12()` (along `to_json()`) that encodes JSON according to [EIP-12](https://github.com/ergoplatform/eips/pull/23) (similar to JSON by `to_json()`, but box value and token amount encodes as strings to avoid accuracy loss in JS) [#346](https://github.com/ergoplatform/sigma-rust/pull/346);
- `Coll.slice` [#309](https://github.com/ergoplatform/sigma-rust/pull/309);
- Byte-wise XOR for byte arrays [#310](https://github.com/ergoplatform/sigma-rust/pull/310);
- `Constant::from_i64_str_array` and `to_i64_str_array` for `Coll[Long]` encoding [#311](https://github.com/ergoplatform/sigma-rust/pull/311);
- `Coll.append` [#308](https://github.com/ergoplatform/sigma-rust/pull/308);
- `MultiplyGroup` IR node for GroupElement [#316](https://github.com/ergoplatform/sigma-rust/pull/316);
- `SubstConst` IR node and serialization [#318] (https://github.com/ergoplatform/sigma-rust/pull/318);
- Better Debug print for EC point [#319](https://github.com/ergoplatform/sigma-rust/pull/319);
- `Constant::from_ecpoint_bytes` to Wasm API [#324](https://github.com/ergoplatform/sigma-rust/pull/324);
- `Constant::to/from_ergo_box`to Wasm API [#397](https://github.com/ergoplatform/sigma-rust/pull/397);

### Changed(BREAKING!):
- **WASM `to_json()` returns string (instead of `JsValue`) to avoid silent accuracy loss on JS object -> text conversion on JS side [#346](https://github.com/ergoplatform/sigma-rust/pull/346);**
- `SigmaSerializable:sigma_serialize_bytes` made failible (returns `Result`) [#328](https://github.com/ergoplatform/sigma-rust/pull/328);
- `ErgoBox::new`, `from_box_candidate` made failible (returns `Result`) [#328](https://github.com/ergoplatform/sigma-rust/pull/328);
- `ErgoTree::new`, `template_bytes`, `to_base16_bytes` made failible (returns `Result`) [#328](https://github.com/ergoplatform/sigma-rust/pull/328);
- `Transaction::new`  made failible (returns `Result`) [#328](https://github.com/ergoplatform/sigma-rust/pull/328);
- WASM `ErgoBox::new`, `byte_to_sign` made failible (returns `Result`) [#328](https://github.com/ergoplatform/sigma-rust/pull/328);
- WASM `ErgoTree::to_bytes`, `to_base16_bytes` made failible (returns `Result`) [#328](https://github.com/ergoplatform/sigma-rust/pull/328);
- `ErgoTree::to_bytes()` renamed to  `ErgoTree::sigma_serialize_bytes()` in Wasm [#387](https://github.com/ergoplatform/sigma-rust/pull/387);
- `ErgoBox` and other types that it uses moved to `ergotree_ir` crate and re-exported in `ergo_lib::ergotree_ir` [#397](https://github.com/ergoplatform/sigma-rust/pull/397);

### Changed
- Switched to `ThreadRng` CSPRNG for source of randomness in sigma protocol [#315](https://github.com/ergoplatform/sigma-rust/pull/315);
- `SigmaSerializable:sigma_serialize` errors are extended beyond `io::Error` [#328](https://github.com/ergoplatform/sigma-rust/pull/328);
- `ergotree-ir::mir::constant::constant_placeholder` module is public;
- `ErgoTree::set_constant` is removed in favor of `ErgoTree::with_constant` with an added check for matching constant type[#323](https://github.com/ergoplatform/sigma-rust/pull/323);
- Eliminate and ban panics (unwrap, panic!, todo!, etc) in `sigma-ser`, `ergotree-ir` and `ergotree-interpreter` crates [#328](https://github.com/ergoplatform/sigma-rust/pull/328), [#344](https://github.com/ergoplatform/sigma-rust/pull/344);

## [0.13.3] - 2021-06-11

### Added 
- Implement CalcSha256 op for byte arrays [#303](https://github.com/ergoplatform/sigma-rust/pull/303);

### Fixes
- Parsing of `UnsignedTransaction` from JSON [#304](https://github.com/ergoplatform/sigma-rust/pull/304);

## [0.13.2] - 2021-06-09

### Added 
- AND, OR conjecture support in sigma protocol [#226](https://github.com/ergoplatform/sigma-rust/pull/226);
- Support for ErgoTree header v1 with tree size [#281](https://github.com/ergoplatform/sigma-rust/pull/281);
- Add support for explorer v1 JSON format parsing for `BlockHeader::votes` [#285](https://github.com/ergoplatform/sigma-rust/pull/285);
- Add bitwise binary operators (&|^) [#290](https://github.com/ergoplatform/sigma-rust/pull/290);

### Changed
- make `ergotree_ir::serialization::constant_store` module public;
- `Peekable` trait is removed in `sigma_ser` crate [#284](https://github.com/ergoplatform/sigma-rust/pull/284);

### Fixed 
- change `MINER_PUBKEY` type to `Coll[Byte]` [#291](https://github.com/ergoplatform/sigma-rust/pull/291);
- Make BigInt arithmetic ops check for 256-bit overflow [#294](https://github.com/ergoplatform/sigma-rust/pull/294);
- Fix numeric negation to give an error on overflow [#294](https://github.com/ergoplatform/sigma-rust/pull/294); 

## [0.13.1] - 2021-05-28

### Fixed 
- Fix VQL encoding/decoding for signed ints in ranges i32::MIN..-1073741825 and 1073741824..i32::MAX [#263](https://github.com/ergoplatform/sigma-rust/pull/263);

## [0.13.0] - 2021-05-26

### Added 
- add `ErgoTree::template_bytes` [#274](https://github.com/ergoplatform/sigma-rust/pull/274);

### Changed 
- encode/decode `UnsignedTransaction` without `id` and using `ErgoBoxCandidate` for `outputs` instead of `ErgoBox` [#275](https://github.com/ergoplatform/sigma-rust/pull/275); 

## [0.12.0] - 2021-05-20

### Added 
- add `Transaction::outputs()` returning `ErgoBoxes` [#267](https://github.com/ergoplatform/sigma-rust/pull/267);

### Changed 
- rename  `Transaction::outputs()` and `UnsignedTransaction::outputs()` to `output_candidates()` in WASM (both return `ErgoBoxCandidates`) [#267](https://github.com/ergoplatform/sigma-rust/pull/267);

### Fixed 
- fix input box lookup on tx signing[#268](https://github.com/ergoplatform/sigma-rust/pull/268);

## [0.11.0] - 2021-05-19

### Added 
- `ByteArrayToLong` `ByteArrayToBigInt` `LongToByteArray` IR nodes [#244](https://github.com/ergoplatform/sigma-rust/pull/244);
- `ErgoTree::constants_len`, `get_constant`, `set_constant` API for accessing the constants list in `ErgoTree` [#261](https://github.com/ergoplatform/sigma-rust/issues/261);

## [0.10.0] - 2021-04-22

### Added 
- Add MinerPubKey and Global as global variables [#232](https://github.com/ergoplatform/sigma-rust/pull/232);
- Implement parser and evaluator for DH tuple [#233](https://github.com/ergoplatform/sigma-rust/pull/233);
- Add method descriptions for SContext (serialization) [#235](https://github.com/ergoplatform/sigma-rust/pull/235)
- Implement GetVar [#236](https://github.com/ergoplatform/sigma-rust/pull/236)
- Implement Atleast IR node (serialization) [#237](https://github.com/ergoplatform/sigma-rust/pull/237)
- Implementation of Deserialize{Context,Register} (serialization) [#239](https://github.com/ergoplatform/sigma-rust/pull/239)
- WASM: fix DataInput construction, ErgoStateContext construction from parsed JSON block headers [#238](https://github.com/ergoplatform/sigma-rust/pull/238) 

### Changed 
- Explicitly handle errors in SMethod::from_ids & and PropertyCall deserialization [#231](https://github.com/ergoplatform/sigma-rust/pull/231);
- Fix flatmap method & GET_VAR opcode [#234](https://github.com/ergoplatform/sigma-rust/pull/234);

## [0.9.0] - 2021-04-09

### Added 
- `Coll.indexOf`, `flatMap`, `forall` IR nodes (evaluation, serialization) [#220](https://github.com/ergoplatform/sigma-rust/pull/220);
- Complete types serialization implementation [#223](https://github.com/ergoplatform/sigma-rust/pull/223);
- `Tuple` constructor evaluation and serialization [#223](https://github.com/ergoplatform/sigma-rust/pull/223);
- Type unification (`SMethod` specialization) [#225](https://github.com/ergoplatform/sigma-rust/pull/226);
- `SigmaAnd`, `SigmaOr` serialization [#225](https://github.com/ergoplatform/sigma-rust/pull/226);
- `Contract::ergo_tree()` in WASM API;
- `decodePoint` IR node (evaluation and serialization) [#227](https://github.com/ergoplatform/sigma-rust/pull/227);

## [0.8.0] - 2021-03-22

### Added 
- `proveDlog`, `box.creationInfo`, `Box.id`, `Coll.exists`, `SigmaProp.propBytes`, `Option.isDefined`, `Option.getOrElse` IR nodes (evaluation, serialization) [#209](https://github.com/ergoplatform/sigma-rust/pull/209);
- `Box.R0..R3` register access [#213](https://github.com/ergoplatform/sigma-rust/pull/213);
- `-` negation for numeric types evaluation and serialization [#214](https://github.com/ergoplatform/sigma-rust/pull/214);
- BigInt values support, arithmetic operations (`+, -, *, /`), `-` negation, `Upcast` [#216](https://github.com/ergoplatform/sigma-rust/pull/216);

## [0.7.0] - 2021-03-03

### Added 
- ErgoScript compiler pipeline draft (`ergoscript-compiler` crate) and added a feature(default) "compiler" in `ergo-lib` with compiler exposed via `Contract::compile(source)`;
- `ErgoTree:to_base16_bytes()` returns Base16-encoded serialized bytes;


### Changed
- Extract Ergotree IR with serialization from `ergo-lib` crate into `ergotree-ir` crate;
- Extract ErgoTree IR interpreter from `ergo-lib` crate into `ergotree-interpreter` crate;


## [0.5.1] - 2021-02-17

### Added 
- Explorer v1 API support for box register parsing [#197](https://github.com/ergoplatform/sigma-rust/pull/197);

## [0.5.0] - 2021-02-04

### Added 
- `CalcBlake2b256` IR node evaluation and serialization [#179](https://github.com/ergoplatform/sigma-rust/pull/179);
- Arith ops (`+, -, *, /`) IR node evaluation and serialization [#181](https://github.com/ergoplatform/sigma-rust/pull/181);
- Comparison ops (`>, >=, <, <=`) IR node evaluation and serialization [#182](https://github.com/ergoplatform/sigma-rust/pull/182);
- `AND`, `Collection` (collection declaration), `BinAnd` IR nodes evaluation and serialization [#183](https://github.com/ergoplatform/sigma-rust/pull/183);
- `Or`, `BinOr` IR nodes evaluation and serialization [#184](https://github.com/ergoplatform/sigma-rust/pull/184);
- `LogicalNot` IR nodes evaluation and serialization [#185](https://github.com/ergoplatform/sigma-rust/pull/185);
- `Map`, `Filter` IR nodes evaluation and serialization [#186](https://github.com/ergoplatform/sigma-rust/pull/186);
- `BoolToSigmaProp`, `If`, `Min`, `Max` IR nodes evaluation and serialization [#187](https://github.com/ergoplatform/sigma-rust/pull/187);
- `ByIndex`, `Box.tokens` IR nodes evaluation and serialization [#188](https://github.com/ergoplatform/sigma-rust/pull/188);

## [0.4.4] - 2021-01-20

### Added 
- `BlockValue`, `ValDef`, `ValUse`, `FuncValue`, `Apply` IR nodes evaluation and serialization [#171](https://github.com/ergoplatform/sigma-rust/pull/171);
- `SimpleBoxSelector`: sort inputs by target tokens and skip inputs that does not have target tokens [#175](https://github.com/ergoplatform/sigma-rust/pull/175);
- `Fold`(collection), `ExtractAmount`(`Box.value`), `SelectField`(tuple field access) IR nodes evaluation and serialization [#173](https://github.com/ergoplatform/sigma-rust/pull/173)

## [0.4.3] - 2021-01-15

### Added 
- `SType::STuple()` and `Value::Tup()` types to store tuples. Implemented serialization, conversion between Rust types and `Constant`(`Value`, `SType`) [#166](https://github.com/ergoplatform/sigma-rust/pull/166);
- `EQ(==)`, `NEQ(!=)` implementation [#166](https://github.com/ergoplatform/sigma-rust/pull/166);

## [0.4.2] - 2020-12-21

### Added 

- Interpreter: Box.Rx properties (get register value), OptionGet [#163](https://github.com/ergoplatform/sigma-rust/pull/163);
- Interpreter: added global vars (`INPUTS`, `OUTPUTS`, `SELF`, `HEIGHT`), `Context` properties (`dataInputs`) [#155](https://github.com/ergoplatform/sigma-rust/pull/155);
- Explorer API v1 format parsing for box.additionalRegisters [#161](https://github.com/ergoplatform/sigma-rust/pull/161);

## [0.4.1] - 2020-11-19

### Added 

- Support for parsing ErgoBox transaction id from `txId` JSON field name;

## [0.4.0] - 2020-11-19

### Added

- Support for parsing ErgoBox id also from "id" JSON field name [#134](https://github.com/ergoplatform/sigma-rust/pull/134)
- Address::p2pk_from_pk_bytes to make an Address from serialized PK [#136](https://github.com/ergoplatform/sigma-rust/pull/136)
- Address::from_str to parse an Address without checking the network prefix [#136](https://github.com/ergoplatform/sigma-rust/pull/136)
- Address::recreate_from_ergo_tree to re-create the address from ErgoTree (built from the address) [#146](https://github.com/ergoplatform/sigma-rust/pull/146)
- NetworkAddress to store Address + NetworkPrefix [#146](https://github.com/ergoplatform/sigma-rust/pull/144)


### Changed

- Move and changed visibility of various modules(input, data_input, prover_result, etc.) [#135](https://github.com/ergoplatform/sigma-rust/pull/135)
- Add Context parameter to Prover::prove, Verifier::verify [#139](https://github.com/ergoplatform/sigma-rust/pull/139)
- Move all transaction-related parameters into TransactionContext parameter in Wallet::sign_transaction [#139](https://github.com/ergoplatform/sigma-rust/pull/139)
- Move Constant export from crate root to constant module (ast::constant) and made eval module private [#142](https://github.com/ergoplatform/sigma-rust/pull/142)
- Make SType public [#142](https://github.com/ergoplatform/sigma-rust/pull/142)

## [0.3.0] - 2020-11-04

### Added

- Add value extraction API for Constant (e.g i64::try_extract_from(constant))  [#111](https://github.com/ergoplatform/sigma-rust/pull/111).
- Implement From<BoxId> for DataInput [#113](https://github.com/ergoplatform/sigma-rust/pull/113).
- Add data inputs to TxBuilder [#115](https://github.com/ergoplatform/sigma-rust/pull/115).
- Read/Write register values in ErgoBox, ErgoBoxCandidate [#116](https://github.com/ergoplatform/sigma-rust/pull/116).
- Add tokens support in TxBuilder and ErgoBoxCandidateBuilder [#118](https://github.com/ergoplatform/sigma-rust/pull/118).
- Implement JSON encoding/decoding for UnsignedTransaction [#123](https://github.com/ergoplatform/sigma-rust/pull/123).
- Add TxBuilder::estimate_tx_size_bytes() to get estimated serialized transaction size in bytes after signing (assuming P2PK box spending); tx_builder::SUGGESTED_TX_FEE constant with "default" current tx fee used lately (1100000 nanoERGs); [#128](https://github.com/ergoplatform/sigma-rust/pull/128).
- Add checks when minting token for minting token exclusivity and registers overwrite [#129](https://github.com/ergoplatform/sigma-rust/pull/129).
- Add transaction validity checks in TxBuilder [#130](https://github.com/ergoplatform/sigma-rust/pull/130).
- Use TokenAmount instead of u64 in sum_tokens*() [#130](https://github.com/ergoplatform/sigma-rust/pull/130).
- Add TokenAmount::checked*() ops [#130](https://github.com/ergoplatform/sigma-rust/pull/130).
- Add I64::as_num() in WASM bindings [#130](https://github.com/ergoplatform/sigma-rust/pull/130)
 

### Changed

- box_id, box_value and register modules made private in ergo_box module and all types are re-exported from ergo_box module itself [#131](https://github.com/ergoplatform/sigma-rust/pull/131).


## [0.2.0] - 2020-10-06

### Added

- Binary serialization;
- JSON serialization;
- Box, Transaction building;
- Transaction signing (P2PK only);
- ErgoTree constant values conversion.

<!-- next-url -->
[Unreleased]: https://github.com/ergoplatform/sigma-rust/compare/ergo-lib-v0.28.0...HEAD
[0.28.0]: https://github.com/ergoplatform/sigma-rust/compare/ergo-lib-v0.27.1...ergo-lib-v0.28.0
[0.27.1]: https://github.com/ergoplatform/sigma-rust/compare/ergo-lib-v0.27.0...ergo-lib-v0.27.1
[0.27.0]: https://github.com/ergoplatform/sigma-rust/compare/ergo-lib-v0.26.0...ergo-lib-v0.27.0
[0.26.0]: https://github.com/ergoplatform/sigma-rust/compare/ergo-lib-v0.25.0...ergo-lib-v0.26.0
[0.25.0]: https://github.com/ergoplatform/sigma-rust/compare/ergo-lib-v0.24.1...ergo-lib-v0.25.0
[0.24.1]: https://github.com/ergoplatform/sigma-rust/compare/ergo-lib-v0.24.0...ergo-lib-v0.24.1
[0.24.0]: https://github.com/ergoplatform/sigma-rust/compare/ergo-lib-v0.23.0...ergo-lib-v0.24.0
[0.23.0]: https://github.com/ergoplatform/sigma-rust/compare/ergo-lib-v0.22.0...ergo-lib-v0.23.0
[0.22.0]: https://github.com/ergoplatform/sigma-rust/compare/ergo-lib-v0.21.1...ergo-lib-v0.22.0
[0.21.1]: https://github.com/ergoplatform/sigma-rust/compare/ergo-lib-v0.21.0...ergo-lib-v0.21.1
[0.21.0]: https://github.com/ergoplatform/sigma-rust/compare/ergo-lib-v0.20.0...ergo-lib-v0.21.0
[0.20.0]: https://github.com/ergoplatform/sigma-rust/compare/ergo-lib-v0.19.0...ergo-lib-v0.20.0
[0.19.0]: https://github.com/ergoplatform/sigma-rust/compare/ergo-lib-v0.18.0...ergo-lib-v0.19.0
[0.18.0]: https://github.com/ergoplatform/sigma-rust/compare/ergo-lib-v0.17.0...ergo-lib-v0.18.0
[0.17.0]: https://github.com/ergoplatform/sigma-rust/compare/ergo-lib-v0.16.1...ergo-lib-v0.17.0
[0.16.1]: https://github.com/ergoplatform/sigma-rust/compare/ergo-lib-v0.16.0...ergo-lib-v0.16.1
[0.16.0]: https://github.com/ergoplatform/sigma-rust/compare/ergo-lib-v0.15.0...ergo-lib-v0.16.0
[0.15.0]: https://github.com/ergoplatform/sigma-rust/compare/ergo-lib-v0.14.0...ergo-lib-v0.15.0
[0.14.0]: https://github.com/ergoplatform/sigma-rust/compare/ergo-lib-v0.13.3...ergo-lib-v0.14.0
[0.13.3]: https://github.com/ergoplatform/sigma-rust/compare/ergo-lib-v0.13.2...ergo-lib-v0.13.3
[0.13.2]: https://github.com/ergoplatform/sigma-rust/compare/ergo-lib-v0.13.1...ergo-lib-v0.13.2
[0.13.1]: https://github.com/ergoplatform/sigma-rust/compare/ergo-lib-v0.13.0...ergo-lib-v0.13.1
[0.13.0]: https://github.com/ergoplatform/sigma-rust/compare/ergo-lib-v0.12.0...ergo-lib-v0.13.0
[0.12.0]: https://github.com/ergoplatform/sigma-rust/compare/ergo-lib-v0.11.0...ergo-lib-v0.12.0
[0.11.0]: https://github.com/ergoplatform/sigma-rust/compare/ergo-lib-v0.10.0...ergo-lib-v0.11.0
[0.10.0]: https://github.com/ergoplatform/sigma-rust/compare/ergo-lib-v0.9.0...ergo-lib-v0.10.0
[0.9.0]: https://github.com/ergoplatform/sigma-rust/compare/ergo-lib-v0.8.0...ergo-lib-v0.9.0
[0.8.0]: https://github.com/ergoplatform/sigma-rust/compare/ergo-lib-v0.7.0...ergo-lib-v0.8.0
[0.7.0]: https://github.com/ergoplatform/sigma-rust/compare/ergo-lib-v0.5.1...ergo-lib-v0.7.0
[0.5.1]: https://github.com/ergoplatform/sigma-rust/compare/ergo-lib-v0.5.0...ergo-lib-v0.5.1
[0.5.0]: https://github.com/ergoplatform/sigma-rust/compare/ergo-lib-v0.4.4...ergo-lib-v0.5.0
[0.4.4]: https://github.com/ergoplatform/sigma-rust/compare/ergo-lib-v0.4.3...ergo-lib-v0.4.4
[0.4.3]: https://github.com/ergoplatform/sigma-rust/compare/ergo-lib-v0.4.2...ergo-lib-v0.4.3
[0.4.2]: https://github.com/ergoplatform/sigma-rust/compare/ergo-lib-v0.4.1...ergo-lib-v0.4.2
[0.4.1]: https://github.com/ergoplatform/sigma-rust/compare/ergo-lib-v0.4.0...ergo-lib-v0.4.1
[0.4.0]: https://github.com/ergoplatform/sigma-rust/compare/ergo-lib-v0.3.0...ergo-lib-v0.4.0
[0.3.0]: https://github.com/ergoplatform/sigma-rust/compare/v0.2.0...ergo-lib-v0.3.0
[0.2.0]: https://github.com/ergoplatform/sigma-rust/compare/v0.1.0...v0.2.0        
