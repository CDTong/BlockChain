// The Times 03/Jan/2009 Chancellor on brink of second bailout for banks.

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log"
	"math"
	"math/big"
	"strconv"
	"time"
)

type Block struct {
	Timestamp     int64
	Data          []byte
	PrevBlockHash []byte
	Hash          []byte
	Nonce         int //pow
}

// Hash = sha256(PrevBlockHash+Data+Timestamp)
// func (b *Block) SetHash() {
// 	Timestamp := []byte(strconv.FormatInt(b.Timestamp, 10))
// 	headers := bytes.Join([][]byte{b.PrevBlockHash, b.Data, Timestamp}, []byte{})
// 	hash := sha256.Sum256(headers)
// 	b.Hash = hash[:]
// }

// new
func NewBlock(data string, prevBlockHash []byte) *Block {
	block := &Block{time.Now().Unix(), []byte(data), prevBlockHash, []byte{}, 0}
	pow := NewProofOfWork(block)
	nonce, hash := pow.Run()

	block.Hash = hash[:]
	block.Nonce = nonce
	return block
}

// first
type Blockchain struct {
	blocks []*Block
}

// add
func (bc *Blockchain) AddBlock(data string) {
	prevBlock := bc.blocks[len(bc.blocks)-1]
	newBlock := NewBlock(data, prevBlock.Hash)
	bc.blocks = append(bc.blocks, newBlock)
}

// genesis block
func NewGenesisBlock() *Block {
	return NewBlock("Genesis Block", []byte{})
}

// the blockchain
func NewBlockChain() *Blockchain {
	return &Blockchain{[]*Block{NewGenesisBlock()}}
}

// Proof of Work
const targetBits = 24

type ProofOfWork struct {
	block  *Block
	target *big.Int
}

func NewProofOfWork(b *Block) *ProofOfWork {
	target := big.NewInt(1)
	target.Lsh(target, uint(256-targetBits))
	pow := &ProofOfWork{b, target}
	return pow
}

// int64 -> array
func IntToHex(num int64) []byte {
	buff := new(bytes.Buffer)
	err := binary.Write(buff, binary.BigEndian, num)
	if err != nil {
		log.Panic(err)
	}
	return buff.Bytes()
}

func (pow *ProofOfWork) prepareData(nonce int) []byte {
	data := bytes.Join(
		[][]byte{
			pow.block.PrevBlockHash,
			pow.block.Data,
			IntToHex(pow.block.Timestamp),
			IntToHex(int64(targetBits)),
			IntToHex(int64(nonce)),
		},
		[]byte{},
	)
	return data
}

// pow
var (
	maxNonce = math.MaxInt64
)

func (pow *ProofOfWork) Run() (int, []byte) {
	var hashInt big.Int
	var hash [32]byte
	nonce := 0 //counter

	fmt.Printf("Mining the block contain: \"%s\"\n", pow.block.Data)
	for nonce < maxNonce {
		data := pow.prepareData(nonce)
		hash = sha256.Sum256(data)
		hashInt.SetBytes(hash[:])

		if hashInt.Cmp(pow.target) == -1 {
			fmt.Printf("\r%x", hash)
			break
		} else {
			nonce++
		}
	}
	fmt.Printf("\n\n")
	return nonce, hash[:]
}

// validate
func (pow *ProofOfWork) Validate() bool {
	var hashInt big.Int
	data := pow.prepareData(pow.block.Nonce)
	hash := sha256.Sum256(data)
	hashInt.SetBytes(hash[:])
	isValid := hashInt.Cmp(pow.target) == -1
	return isValid
}

func main() {
	bc := NewBlockChain()
	bc.AddBlock("Send 1 BTC to Satoshi")
	bc.AddBlock("Send 3 BTC to Vitalik")

	for _, block := range bc.blocks {
		fmt.Printf("Prev Hash: %x\n", block.PrevBlockHash)
		fmt.Printf("Data: %s\n", block.Data)
		fmt.Printf("Hash: %x\n", block.Hash)
		fmt.Println()
		pow := NewProofOfWork(block)
		fmt.Printf("PoW: %s\n", strconv.FormatBool((pow.Validate())))
		fmt.Println()
	}
}

// show(it may take some time)
// Mining the block contain: "Genesis Block"
// 0000001f5bb50de9d3fa8122866295499bf42a1b25375348e469c29dd9952f79

// Mining the block contain: "Send 1 BTC to Satoshi"
// 000000a6ea418d173757e73b3bb5df524f3c834ea68b40956ea0dd6d670dd0f5

// Mining the block contain: "Send 3 BTC to Vitalik"
// 0000001f801442d5590b6d9024717c1828fa99db2720f289075b318dc018067a

// Prev Hash:
// Data: Genesis Block
// Hash: 0000001f5bb50de9d3fa8122866295499bf42a1b25375348e469c29dd9952f79

// PoW: true

// Prev Hash: 0000001f5bb50de9d3fa8122866295499bf42a1b25375348e469c29dd9952f79
// Data: Send 1 BTC to Satoshi
// Hash: 000000a6ea418d173757e73b3bb5df524f3c834ea68b40956ea0dd6d670dd0f5

// PoW: true

// Prev Hash: 000000a6ea418d173757e73b3bb5df524f3c834ea68b40956ea0dd6d670dd0f5
// Data: Send 3 BTC to Vitalik
// Hash: 0000001f801442d5590b6d9024717c1828fa99db2720f289075b318dc018067a

// PoW: true
