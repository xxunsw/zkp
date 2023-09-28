pragma solidity ^0.8.0;
// SPDX-License-Identifier: UNLICENSED


import "verifier.sol"; // Import the verifier contract

contract StudentDisabilitySystem {
    Verifier public verifier; // Instance of the Verifier contract
    mapping(address => bool) public registeredStudents; // A mapping to keep track of registered students

    constructor(address _verifierAddress) {
        verifier = Verifier(_verifierAddress); // Initialize the verifier instance with its address
    }

    function registerStudent(
        Verifier.Proof memory proof,
        uint[1] memory input
    ) public {
        // Verify the zk-SNARK proof
        require(verifier.verifyTx(proof, input), "Invalid zk-SNARK proof");

        // If the proof is valid, register the student
        registeredStudents[msg.sender] = true;
    }

    function isStudentRegistered(address student) public view returns (bool) {
        return registeredStudents[student];
    }
}
