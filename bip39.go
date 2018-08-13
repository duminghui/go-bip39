package bip39

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"math/big"
	"strings"

	"golang.org/x/crypto/pbkdf2"

	"github.com/duminghui/go-bip39/wordlists"
)

// ErrorEntropySize entroy size error
var ErrorEntropySize = errors.New("Entropy bit size must be 128, 160, 192, 224, 256")

//ErrorMnemonic menomic error
var ErrorMnemonic = errors.New("Invalid menomic")

var wordList []string
var wordMap map[string]int

type mnemonicData struct {
	entropyBitSize  int
	checksumBitSize uint
	checksumBitMask *big.Int
	mnemonicLenght  int
}

var (
	mnemonic12 = mnemonicData{128, 4, big.NewInt(0xF), 12}
	mnemonic15 = mnemonicData{160, 5, big.NewInt(0x1F), 15}
	mnemonic18 = mnemonicData{192, 6, big.NewInt(0x3F), 18}
	mnemonic21 = mnemonicData{224, 7, big.NewInt(0x7F), 21}
	mnemonic24 = mnemonicData{256, 8, big.NewInt(0xFF), 24}
	bits11Mask = big.NewInt(0x7FF)
)

func init() {
	SetWordList(wordlists.English)
}

//SetWordList set word list
func SetWordList(list []string) {
	wordList = list
	wordMap = map[string]int{}
	for i, v := range wordList {
		wordMap[v] = i
	}
}

// NewEntropy create random entropy bytes
// entroySize must be 128,160,192,224,256
func NewEntropy(entropySize int) ([]byte, error) {
	err := validateEntropySize(int(entropySize))
	if err != nil {
		return nil, err
	}
	entropy := make([]byte, entropySize/8)
	_, err = rand.Read(entropy)
	return entropy, nil
}

func validateEntropySize(entropySize int) error {
	switch entropySize {
	case 128, 160, 192, 224, 256:
		return nil
	default:
		return ErrorEntropySize
	}
}

// NewMnemonic create mnemonic
func NewMnemonic(entropy []byte) (string, error) {
	// fmt.Println(len(entropy))
	var mnemonic mnemonicData
	switch len(entropy) {
	case 16:
		mnemonic = mnemonic12
	case 20:
		mnemonic = mnemonic15
	case 24:
		mnemonic = mnemonic18
	case 28:
		mnemonic = mnemonic21
	case 32:
		mnemonic = mnemonic24
	default:
		return "", ErrorEntropySize
	}
	// fmt.Printf("%x\n", entropy)
	entropy = addChecksum2Entropy(entropy, mnemonic.checksumBitSize)
	words := make([]string, mnemonic.mnemonicLenght)
	// wordIndex := 0
	wordIndexBigInt := big.NewInt(0)
	entropyBigInt := new(big.Int).SetBytes(entropy)
	for i := 0; i < mnemonic.mnemonicLenght; i++ {
		wordIndexBigInt.And(entropyBigInt, bits11Mask)
		entropyBigInt.Rsh(entropyBigInt, 11)
		words[mnemonic.mnemonicLenght-i-1] = wordList[wordIndexBigInt.Int64()]
	}
	// fmt.Println(words)
	return strings.Join(words, " "), nil
}

// entropy bit size / 32
// checksum max bit size is 8
func addChecksum2Entropy(entropy []byte, checksumBitSize uint) []byte {
	// checksum := computeChecksum(entropy)
	checksum := sha256.Sum256(entropy)
	checksumByte := checksum[0]
	checksumBigInt := big.NewInt(int64(checksumByte))
	entropyBitInt := new(big.Int).SetBytes(entropy)
	// fmt.Printf("checksumBigInt: %b, %d\n", checksumBigInt, checksumBitSize)
	// fmt.Printf("entropy raw binary %b\n", entropyBitInt)
	// fmt.Println(entropy)
	entropyBitInt.Lsh(entropyBitInt, checksumBitSize)
	checksumBigInt.Rsh(checksumBigInt, 8-checksumBitSize)
	// fmt.Printf("checksumBigInt: %#b\n", checksumBigInt)
	entropyBitInt.Add(entropyBitInt, checksumBigInt)
	return entropyBitInt.Bytes()
}

// NewSeed create seed
func NewSeed(mnemonic, password string) []byte {
	return pbkdf2.Key([]byte(mnemonic), []byte("mnemonic"+password), 2048, 64, sha512.New)
}

// NewSeedWithValidMnemonic vaild Mnemonic and create seed
func NewSeedWithValidMnemonic(mnemonic, password string) ([]byte, error) {
	_, err := Mnemonic2Entropy(mnemonic)
	if err != nil {
		return nil, err
	}
	return NewSeed(mnemonic, password), nil
}

// Mnemonic2Entropy parse menmonic to entropy
func Mnemonic2Entropy(mnemonic string) ([]byte, error) {
	words := strings.Fields(mnemonic)
	wordCount := len(words)
	var _mnemonicInfo mnemonicData
	switch wordCount {
	case 12:
		_mnemonicInfo = mnemonic12
	case 15:
		_mnemonicInfo = mnemonic15
	case 18:
		_mnemonicInfo = mnemonic18
	case 21:
		_mnemonicInfo = mnemonic21
	case 24:
		_mnemonicInfo = mnemonic24
	default:
		return nil, ErrorMnemonic
	}
	entropyChecksummedBigInt := big.NewInt(0)
	for i, word := range words {
		wordIndex, ok := wordMap[word]
		if !ok {
			return nil, ErrorMnemonic
		}
		entropyChecksummedBigInt.Or(entropyChecksummedBigInt, big.NewInt(int64(wordIndex)))
		if i < wordCount-1 {
			entropyChecksummedBigInt.Lsh(entropyChecksummedBigInt, 11)
		}
	}
	checksumBigInt := big.NewInt(0)
	checksumBigInt.And(entropyChecksummedBigInt, _mnemonicInfo.checksumBitMask)
	entropyBigInt := big.NewInt(0)
	entropyBigInt.Rsh(entropyChecksummedBigInt, _mnemonicInfo.checksumBitSize)
	entropyBytes := entropyBigInt.Bytes()
	offset := _mnemonicInfo.entropyBitSize/8 - len(entropyBytes)
	var entropy []byte
	if offset == 0 {
		entropy = entropyBytes
	} else {
		entropy = make([]byte, _mnemonicInfo.checksumBitSize/8)
		copy(entropy[offset:], entropyBytes)
	}
	// fmt.Printf("checksum entropy: %x\n", entropyChecksummedBigInt.Bytes())
	// fmt.Printf("entropy %x\n", entropy)
	checksum := sha256.Sum256(entropy)
	// fmt.Printf("checksum %x\n", checksum)
	checksumByte := checksum[0]
	checksumBigInt2 := big.NewInt(int64(checksumByte))
	checksumBigInt2.Rsh(checksumBigInt2, 8-_mnemonicInfo.checksumBitSize)
	if checksumBigInt.Cmp(checksumBigInt2) != 0 {
		return nil, ErrorMnemonic
	}
	return entropy, nil
}

// IsMnemonic valid Mnemonic
func IsMnemonic(mnemonic string) bool {
	words := strings.Fields(mnemonic)
	wordCount := len(words)
	switch wordCount {
	case 12, 15, 18, 21, 24:
	default:
		return false
	}

	for _, word := range words {
		if _, ok := wordMap[word]; !ok {
			return false
		}
	}
	return true
}
