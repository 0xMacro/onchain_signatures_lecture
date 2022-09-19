// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

// taken from https://solidity-by-example.org/signature/

/* Signature Verification

How to Sign and Verify
# Signing
1. Create message to sign
2. Hash the message
3. Sign the hash (off chain, keep your private key secret!)

# Verify
1. Recreate hash from the original message
2. Recover signer from signature and hash
3. Compare recovered signer to claimed signer
*/

contract VerifySignature {
    mapping(address => uint256) public nonces;

    address public owner;

    constructor(address _owner) {
        owner = _owner;
    }

    /*

    1. startup Hardhat console

    npx hardhat console

    const [deployer] = await ethers.getSigners()
    deployer.address // '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266'

    let VerifySignature = await ethers.getContractFactory("VerifySignature")
    let verifySignature = await VerifySignature.deploy(deployer.address)
    await verifySignature.deployed()

    // need to fund the contract. So I need to send it some ETH

    */

    /*

    2. Get message hash to sign
    let hash = await verifySignature.getMessageHash(
        "0x14723A09ACff6D2A60DcdF7aA4AFf308FDDC160C",
        123,
        "coffee and donuts",
        1
    ) // "0xcf36ac4f97dc10d91fc2cbb20d718e94a8cbfe0f82eaedc6a4aa38946fb797cd"

    */
    function getMessageHash(
        address _to,
        uint _amount,
        string memory _message,
        uint _nonce // replay protection
    ) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(_to, _amount, _message, _nonce));
    }

    /*

    3. Get the correctly formatted 32-byte message we will sign

    let messageToSign = await verifySignature.getMessageToSign(hash)

    */


    function getMessageToSign(bytes32 _messageHash)
        public
        pure
        returns (bytes32)
    {
        /*
        Signature is produced by signing a keccak256 hash with the following format:
        "\x19Ethereum Signed Message\n" + len(msg) + msg
        */
        return
            keccak256(
                abi.encodePacked("\x19Ethereum Signed Message:\n32", _messageHash)
            );
    }

    /*

    4. Sign message hash

    let sig = await deployer.signMessage(
        ethers.utils.arrayify(messageToSign)
    )


    Signature will be different for different accounts
    0xb4da7d2dc0f4086db89cd273b61073118b2baa222b39de0dafeed27f6b4eb4b677728c3828f90554ca90cc6c5e9ae0c33d1cb5c544aedd8cfb8de151bfb89b7c1c

    5. Verify signature
    _to = "0x14723A09ACff6D2A60DcdF7aA4AFf308FDDC160C"
    _amount = 123
    _message = "coffee and donuts"
    _nonce = 1

    let isValidSignature = await verifySignature.verify(
        _signer,
        _to,
        _amount,
        _message,
        _nonce,
        sig
    )

    */
    function verify(
        address _to,
        uint _amount,
        string memory _message,
        uint _nonce,
        bytes memory signature
    ) public returns (bool) {
        bytes32 messageHash = getMessageHash(_to, _amount, _message, _nonce);
        bytes32 ethSignedMessageHash = getMessageToSign(messageHash);

        address actualSigner = recoverSigner(ethSignedMessageHash, signature);

        require(nonces[actualSigner] == _nonce - 1, "VerifySignature: INVALID_NONCE");
        nonces[actualSigner] = _nonce;



        return actualSigner == owner;
    }

    /*

    6. Perform an action after correctly validating the signature
    In this case, it's a toy example of sending some ETH to the _to address
    */
    function sendETHWithValidSig(
        address _to,
        uint _amount,
        string memory _message,
        uint _nonce,
        bytes memory signature
    ) public {
        require(verify(_to, _amount, _message, _nonce, signature), "VerifySignature: INVALID_SIG");

        (bool success,) = _to.call{value: _amount}(bytes(_message));
        require(success, "VerifySignature: FAILED_SEND");
    }

    function recoverSigner(bytes32 _ethSignedMessageHash, bytes memory _signature)
        public
        pure
        returns (address)
    {
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(_signature);

        return ecrecover(_ethSignedMessageHash, v, r, s);
    }

    function splitSignature(bytes memory sig)
        public
        pure
        returns (
            bytes32 r,
            bytes32 s,
            uint8 v
        )
    {
        require(sig.length == 65, "invalid signature length");

        assembly {
            /*
            First 32 bytes stores the length of the signature

            add(sig, 32) = pointer of sig + 32
            effectively, skips first 32 bytes of signature

            mload(p) loads next 32 bytes starting at the memory address p into memory
            */

            // first 32 bytes, after the length prefix
            r := mload(add(sig, 32))
            // second 32 bytes
            s := mload(add(sig, 64))
            // final byte (first byte of the next 32 bytes)
            v := byte(0, mload(add(sig, 96)))
        }

        // implicitly return (r, s, v)
    }
}
