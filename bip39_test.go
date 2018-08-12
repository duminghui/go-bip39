package big39

import (
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
	"math/big"
	"testing"
)

func TestNewEntropy(t *testing.T) {
	// fmt.Println(NewEntropy(256))
}

func TestNewMnemonic(t *testing.T) {
	// bytes, _ := NewEntropy(128)
	// NewMnemonic(bytes)
	// fmt.Println("mnemonic:", mnemonic)
}

// +ignore
func TestNewSeed(t *testing.T) {
	t.SkipNow()
	entropy, _ := NewEntropy(256)
	fmt.Printf("entropy:%x\n", entropy)
	mnemonic, _ := NewMnemonic(entropy)
	fmt.Println("mnemonic:", mnemonic)
	seed := NewSeed(mnemonic, "11111")
	fmt.Printf("seed:%x\n", seed)
}

func TestIsMnemonic(t *testing.T) {
	t.SkipNow()
	isMnemonic := IsMnemonic("orient neutral catch matrix reopen fine victory faculty jar clever fold agent stage beyond ride sudden answer maze exercise confirm dentist people shift")
	fmt.Println(isMnemonic)
}

func TestMnemonic2Entropy(t *testing.T) {
	t.SkipNow()
	entropy, _ := NewEntropy(256)
	// entropy = make([]byte, 32)
	fmt.Printf("%x\n", entropy)
	mnemonic, _ := NewMnemonic(entropy)
	// mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
	// mnemonic = "genius actress virtual glimpse foot oak expect chalk poem slim now aware math clump awake ostrich short witness pill turn round barely diary rocket"
	mnemonic = "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold"
	fmt.Println(mnemonic)
	entropy2, err := Mnemonic2Entropy(mnemonic)
	fmt.Printf("%x\n", entropy2)
	fmt.Println(err)
}

func TestNewSeedWithValidMnemonic(t *testing.T) {
	// t.SkipNow()
	entropy, _ := NewEntropy(256)
	fmt.Printf("entropy: %x\n", entropy)
	mnemonic, _ := NewMnemonic(entropy)
	// mnemonic = "much local guess refuse cannon project march dwarf color sleep fringe safe"
	// mnemonic = "army van defense carry jealous true garbage claim echo media make crunch"
	fmt.Println("mnemonic:", mnemonic)
	seed, _ := NewSeedWithValidMnemonic(mnemonic, "")
	fmt.Printf("seed: %x\n", seed)
	hmac512 := hmac.New(sha512.New, []byte("Bitcoin seed"))
	hmac512.Write(seed)
	masterKey := hmac512.Sum(nil)
	fmt.Printf("masterKey: %x\n", masterKey)
	masterPriKey := masterKey[:32]
	fmt.Printf("masterPriKey: %x\n", masterPriKey)
	fmt.Println(len(masterPriKey))
	masterChainCode := masterKey[32:]
	fmt.Printf("masterChainCode: %x\n", masterChainCode)
}
func TestFunction(t *testing.T) {
	var tmp big.Int
	len, err := fmt.Sscan("0xF", &tmp)
	fmt.Println(tmp, len, err)
	fmt.Println(fmt.Sprintf("%d", tmp.Bytes()))
	fmt.Println(fmt.Sprintf("%x", tmp.String()))
}
