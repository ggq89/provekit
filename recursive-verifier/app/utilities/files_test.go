package utilities

import "testing"

func Test_WriteProofInSolidity(t *testing.T) {
	proof, err := ReadProof("./proof")
	if err != nil {
		t.Fatal(err)
	}

	err = WriteProofInSolidity(proof, "./proof_solidity")
	if err != nil {
		t.Fatal(err)
	}

}
