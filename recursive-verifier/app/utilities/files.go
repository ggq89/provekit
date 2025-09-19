package utilities

import (
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
)

// FileExists checks if a file exists at the given path.
func FileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, fmt.Errorf("stat error: %v", err)
}

// CheckOrCreateDir checks if the directory of file exists, and creates it if it does not exist.
func CheckOrCreateDir(file string) error {
	dir := filepath.Dir(file)

	_, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return err
		}

		err = os.MkdirAll(dir, os.ModePerm)
		if err != nil {
			return err
		}
	}

	return nil
}

// OpenFileOnCreaterOverwrite opens a file, creating any missing directories, and overwriting the file if it already exists.
// It returns an os.File pointer that should be closed by the caller.
func OpenFileOnCreateOrOverwrite(file string) (*os.File, error) {
	exists, err := FileExists(file)
	if err != nil {
		return nil, err
	}

	if exists {
		err := os.Remove(file)
		if err != nil {
			return nil, err
		}
	} else {
		err := CheckOrCreateDir(file)
		if err != nil {
			return nil, err
		}
	}

	fFile, err := os.Create(file)
	if err != nil {
		return nil, err
	}
	return fFile, nil
}

func WriteCcs(ccs constraint.ConstraintSystem, fn string) error {
	openFile, err := OpenFileOnCreateOrOverwrite(fn)
	if err != nil {
		return err
	}
	defer func() {
		_ = openFile.Close()
	}()

	_, err = ccs.WriteTo(openFile)
	if err != nil {
		return err
	}

	return nil
}

func WriteVkInSolidity(vk groth16.VerifyingKey, fn string) error {
	openFile, err := OpenFileOnCreateOrOverwrite(fn)
	if err != nil {
		return err
	}
	defer func() {
		_ = openFile.Close()
	}()

	err = vk.ExportSolidity(openFile)
	if err != nil {
		return err
	}
	return nil
}

func WriteProof(proof groth16.Proof, fn string) error {
	openFile, err := OpenFileOnCreateOrOverwrite(fn)
	if err != nil {
		return err
	}
	defer func() {
		_ = openFile.Close()
	}()

	_, err = proof.WriteTo(openFile)
	if err != nil {
		return err
	}

	return nil
}

func ReadProof(fn string) (groth16.Proof, error) {
	f, err := os.Open(fn)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = f.Close()
	}()

	var bn254Proof groth16_bn254.Proof
	_, err = bn254Proof.ReadFrom(f)
	if err != nil {
		return nil, err
	}

	return &bn254Proof, nil
}

const (
	proofLen          = 8
	eachCommitmentLen = 2
	commitmentPokLen  = 2
)

func WriteProofInSolidity(proof groth16.Proof, fn string) error {
	openFile, err := OpenFileOnCreateOrOverwrite(fn)
	if err != nil {
		return err
	}
	defer func() {
		_ = openFile.Close()
	}()

	_proof := proof.(*groth16_bn254.Proof)
	commitmentsLen := len(_proof.Commitments)

	var proofInSol [proofLen]*big.Int
	proofInSol[0] = new(big.Int).SetBytes(_proof.Ar.X.Marshal())
	proofInSol[1] = new(big.Int).SetBytes(_proof.Ar.Y.Marshal())
	proofInSol[2] = new(big.Int).SetBytes(_proof.Bs.X.A1.Marshal())
	proofInSol[3] = new(big.Int).SetBytes(_proof.Bs.X.A0.Marshal())
	proofInSol[4] = new(big.Int).SetBytes(_proof.Bs.Y.A1.Marshal())
	proofInSol[5] = new(big.Int).SetBytes(_proof.Bs.Y.A0.Marshal())
	proofInSol[6] = new(big.Int).SetBytes(_proof.Krs.X.Marshal())
	proofInSol[7] = new(big.Int).SetBytes(_proof.Krs.Y.Marshal())

	_, err = openFile.WriteString(bigIntSliceToString(proofInSol[:]))
	if err != nil {
		return err
	}

	commitmentsInSol := make([]*big.Int, commitmentsLen*eachCommitmentLen)
	for i := 0; i < commitmentsLen; i++ {
		commitmentsInSol[i*eachCommitmentLen] = new(big.Int).SetBytes(_proof.Commitments[i].X.Marshal())
		commitmentsInSol[i*eachCommitmentLen+1] = new(big.Int).SetBytes(_proof.Commitments[i].Y.Marshal())
	}

	_, err = openFile.WriteString("\n" + bigIntSliceToString(commitmentsInSol[:]))
	if err != nil {
		return err
	}

	var commitmentPokInSol [commitmentPokLen]*big.Int
	commitmentPokInSol[0] = new(big.Int).SetBytes(_proof.CommitmentPok.X.Marshal())
	commitmentPokInSol[1] = new(big.Int).SetBytes(_proof.CommitmentPok.Y.Marshal())

	_, err = openFile.WriteString("\n" + bigIntSliceToString(commitmentPokInSol[:]))
	if err != nil {
		return err
	}

	return nil
}

func bigIntSliceToString(nums []*big.Int) string {
	var sb strings.Builder
	sb.WriteString("[")
	for i, n := range nums {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(n.String())
	}
	sb.WriteString("]")
	return sb.String()
}

func WritePublicWitnessInJson(pw witness.Witness, fn string) error {
	openFile, err := OpenFileOnCreateOrOverwrite(fn)
	if err != nil {
		return err
	}
	defer func() {
		_ = openFile.Close()
	}()

	pwStr := fmt.Sprint(pw.Vector())
	_, err = openFile.WriteString(pwStr)
	if err != nil {
		return err
	}

	return nil
}
