package bip39

import (
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
	"math/big"
	"testing"
)

func TestNewEntropy(t *testing.T) {
	bitSizeSlice := []int{
		128, 160, 192, 224, 256,
	}
	for _, bitSize := range bitSizeSlice {
		entropy, err := NewEntropy(bitSize)
		fmt.Println(bitSize, bitSize/32)
		if err != nil {
			fmt.Println(bitSize, err)
		} else {
			fmt.Println(bitSize, entropy)
		}
	}
}

func TestNewMnemonic(t *testing.T) {
	bytes, err := NewEntropy(128)
	if err != nil {
		fmt.Println(err)
		return
	}
	mnemonic, err := NewMnemonic(bytes)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("mnemonic:", mnemonic)
}

func TestNewSeed(t *testing.T) {
	entropy, _ := NewEntropy(256)
	fmt.Printf("entropy:%x\n", entropy)
	mnemonic, _ := NewMnemonic(entropy)
	fmt.Println("mnemonic:", mnemonic)
	seed := NewSeed(mnemonic, "11111")
	fmt.Printf("seed:%x\n", seed)
}

func TestIsMnemonic(t *testing.T) {
	t.SkipNow()
	isMnemonic := IsMnemonicValid("orient neutral catch matrix reopen fine victory faculty jar clever fold agent stage beyond ride sudden answer maze exercise confirm dentist people shift")
	fmt.Println(isMnemonic)
}

func TestNewSeedWithErrorChecking(t *testing.T) {
	// t.SkipNow()
	entropy, _ := NewEntropy(128)
	fmt.Printf("entropy: %x\n", entropy)
	mnemonic, _ := NewMnemonic(entropy)
	// mnemonic = "much local guess refuse cannon project march dwarf color sleep fringe safe"
	// mnemonic = "army van defense carry jealous true garbage claim echo media make crunch"
	fmt.Println("mnemonic:", mnemonic)
	seed, _ := NewSeedWithErrorChecking(mnemonic, "")
	fmt.Printf("seed: %x , %d\n", seed, len(seed))
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
