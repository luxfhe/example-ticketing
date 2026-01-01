// SPDX-License-Identifier: BSD-3-Clause-Clear

pragma solidity >=0.8.13 <0.9.0;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";

import {FHE, euint32, Euint32} from "@luxfi/contracts/fhe/FHE.sol";

contract Ticket is ERC721 {
    string private _baseTokenURI;
    bytes32 private _adminKey;
    euint32 private _privateKey;
    mapping(uint => euint32) internal keys;

    constructor(
        string memory name,
        string memory symbol,
        string memory baseTokenURI,
        bytes32 adminPublicKey
    ) ERC721(name, symbol) {
        _baseTokenURI = baseTokenURI;
        _adminKey = adminPublicKey;
    }

    function _baseURI() internal view virtual override(ERC721) returns (string memory) {
        return _baseTokenURI;
    }

    function supportsInterface(bytes4 interfaceId) public view override(ERC721) returns (bool) {
        return super.supportsInterface(interfaceId);
    }

    function setPrivateKey(Euint32 calldata k1) external {
        _privateKey = FHE.asEuint32(k1);
    }

    function mintNft(address to, uint tokenId) external returns (uint256) {
        _mint(to, tokenId);
        return tokenId;
    }

    function getKeyDebug(bytes32 publicKey) public view returns (bytes memory) {
        return FHE.sealoutput(_privateKey, publicKey);
    }

    function getKey() public view returns (bytes memory) {
        return FHE.sealoutput(_privateKey, _adminKey);
    }

    // todo: add eip-712 signatures for user validation
    function getKeyWithChallenge(Euint32 calldata challenge) public returns (bytes memory) {
        euint32 challengeValue = FHE.asEuint32(challenge);
        euint32 result = FHE.xor(_privateKey, challengeValue);
        return FHE.sealoutput(result, _adminKey);
    }
}
