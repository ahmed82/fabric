/*
 Copyright Ahmed AlSalih @UNCC All Rights Reserved.

 SPDX-License-Identifier: Apache-2.0
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.

*/

package bdls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"sync"
	"time"

	"code.cloudfoundry.org/clock"
	"github.com/BDLS-bft/bdls"
	"github.com/BDLS-bft/bdls/crypto/blake2b"
	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-protos-go/orderer"

	//bdlspb "github.com/hyperledger/fabric/orderer/consensus/bdls/protos"

	//bdlspb "github.com/hyperledger/fabric-protos-go/orderer/bdls"
	"protos"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric/orderer/common/cluster"
	"github.com/hyperledger/fabric/orderer/common/types"
	"github.com/hyperledger/fabric/orderer/consensus"
	"github.com/pkg/errors"

	//"google.golang.org/protobuf/proto"
	"github.com/golang/protobuf/proto"

	"github.com/hyperledger/fabric/protoutil"
)

// None is a placeholder node ID used when there is no leader.
const None uint64 = 0

//go:generate counterfeiter -o mocks/mock_rpc.go . RPC

// RPC is used to mock the transport layer in tests.
type RPC interface {
	SendConsensus(dest uint64, msg *orderer.ConsensusRequest) error
	SendSubmit(dest uint64, request *orderer.SubmitRequest, report func(err error)) error
}

//go:generate counterfeiter -o mocks/mock_blockpuller.go . BlockPuller

// BlockPuller is used to pull blocks from other OSN
type BlockPuller interface {
	PullBlock(seq uint64) *common.Block
	HeightsByEndpoints() (map[string]uint64, error)
	Close()
}

// CreateBlockPuller is a function to create BlockPuller on demand.
// It is passed into chain initializer so that tests could mock this.
type CreateBlockPuller func() (BlockPuller, error)

//go:generate mockery -dir . -name Configurator -case underscore -output ./mocks/

// Configurator is used to configure the communication layer
// when the chain starts.
type Configurator interface {
	Configure(channel string, newNodes []cluster.RemoteNode)
}

// Chain implements consensus.Chain interface.
type Chain struct {
	configurator Configurator
	rpc          RPC

	// the starting time point for consensus
	Epoch time.Time

	bdlsID uint64
	id     bdls.Identity

	channelID string
	consensus *bdls.Consensus

	config  *bdls.Config
	submitC chan *submit //chan *orderer.SubmitRequest
	applyC  chan apply

	commitC  chan *common.Block
	observeC chan<- uint64 // Notifies external observer on leader change (passed in optionally as an argument for tests)

	support consensus.ConsenterSupport

	haltC   chan struct{} // Signals to goroutines that the chain is halting
	doneC   chan struct{} // Closes when the chain halts
	startC  chan struct{} // Closes when the node is started
	resignC chan struct{} // Notifies node that it is no longer the leader

	clock clock.Clock // Tests can inject a fake clock

	errorCLock sync.RWMutex
	errorC     chan struct{} // returned by Errored()

	confChangeInProgress *bdls.Message

	//[FAB-14240] Do not use support.Height in chain
	//Commitment of block is doen aync win blockwritter, therefore
	//`support.Height` may not correctly reflect the actual number
	//of latest block. Decision made based on `support.Height` while
	//chain is running may lead to replaying of same block.
	// https://github.com/BDLS-bft/fabric/commit/dc170d497b0a474787fc00694c0a0942697399d8
	lastBlock       *common.Block
	appliedIndex    uint64
	lastConfigBlock *common.Block
	createPuller    CreateBlockPuller // func used to create BlockPuller on demand
	Metrics         *Metrics
	// BCCSP instance
	CryptoProvider bccsp.BCCSP
	// participants is the consensus group, current leader is r % quorum // Consensus Group
	participants []bdls.Identity

	opts   Options
	logger *flogging.FabricLogger

	bdlsMetadataLock sync.RWMutex

	statusReportMutex sync.Mutex
	consensusRelation types.ConsensusRelation
	status            types.Status

	configInflight bool // this is true when there is config block or ConfChange in flight
	blockInflight  int  // number of in flight blocks

	bdlsStart bool
	// as the block will be exchanged via <roundchange> message,
	// we need to validate these blocks in-flight, so we need processBlock at given height with state,
	// and compare the results with related fields in block header.

	//stateAt       func( hash c.lastBlock.Header.DataHash) (hash ,err error)
	//hasBadBlock   func(hash common.Hash) bool
	//processBlock  func(block *types.Block, statedb *state.StateDB) (types.Receipts, []*types.Log, uint64, error)
	//validateState func(block *types.Block, statedb *state.StateDB, receipts types.Receipts, usedGas uint64) error
}

// Options contains necessary artifacts to start Bdls-based chain
type Options struct {
	BdlsID uint64
	id     bdls.Identity
	// the starting time point for consensus
	Epoch time.Time // time.Duration

	RPCTimeout time.Duration
	// timeouts in different stage
	rcTimeout          time.Time // roundchange status timeout: Delta_0
	lockTimeout        time.Time // lock status timeout: Delta_1
	commitTimeout      time.Time // commit status timeout: Delta_2
	lockReleaseTimeout time.Time // lock-release status timeout: Delta_3

	// all connected peers
	Peers []bdls.Identity

	// participants is the consensus group, current leader is r % quorum // Consensus Group
	participants []bdls.Identity

	Clock clock.Clock

	WALDir string

	MaxInflightBlocks int
	TickInterval      time.Duration
	MaxSizePerMsg     uint64

	// CurrentHeight
	CurrentHeight uint64
	// PrivateKey
	PrivateKey *ecdsa.PrivateKey

	// EnableCommitUnicast sets to true to enable <commit> message to be delivered via unicast
	// if not(by default), <commit> message will be broadcasted
	EnableCommitUnicast bool

	Logger *flogging.FabricLogger

	// BCCSP instance
	CryptoProvider bccsp.BCCSP

	Cert []byte

	// BlockMetadata and Consenters should only be modified while under lock
	// of bdlsMetadataLock
	BlockMetadata *protos.BlockMetadata
	Consenters    map[uint64]*protos.Consenter
}

type submit struct {
	req *orderer.SubmitRequest
	//leader chan uint64
}

type gc struct {
	index uint64
	state bdls.SignedProto
	data  []byte
}

/*
const (
	baseLatency               = 500 * time.Millisecond
	maxBaseLatency            = 10 * time.Second
	proposalCollectionTimeout = 3 * time.Second
	updatePeriod              = 100 * time.Millisecond
	resendPeriod              = 10 * time.Second
)*/

// NewChain constructs a chain object.
func NewChain(
	support consensus.ConsenterSupport,
	opts Options,
	conf Configurator,
	rpc RPC,
	cryptoProvider bccsp.BCCSP,
	//remoteNodes []cluster.RemoteNode,
	f CreateBlockPuller,
	haltCallback func(),
	//observeC chan<- bdls
) (*Chain, error) {

	b := support.Block(support.Height() - 1)
	/*	if b == nil {
			return nil, errors.Errorf("failed to get last block")
		}
		var nodes []uint64
		for _, n := range remoteNodes {
			nodes = append(nodes, n.ID)
		}
		nodes = append(nodes, 0)
		sort.Slice(nodes, func(i, j int) bool {
			return nodes[i] < nodes[j]
		})
		n := uint64(len(nodes))*/
	c := &Chain{
		// Setup communication with list of remotes notes for the new channel
		configurator: conf,

		rpc:       rpc,
		channelID: support.ChannelID(),
		bdlsID:    opts.BdlsID,
		submitC:   make(chan *submit), //make(chan *orderer.SubmitRequest),
		commitC:   make(chan *common.Block),
		haltC:     make(chan struct{}),
		doneC:     make(chan struct{}),
		resignC:   make(chan struct{}),
		startC:    make(chan struct{}),
		lastBlock: b,
		//observeC:     observeC,
		support: support,
		clock:   opts.Clock,
		logger:  opts.Logger.With("channel", support.ChannelID() /*, "node", opts.RaftID)*/),
		//storage:      opts.Storage,
		//confState:         cc,
		createPuller:      f,
		opts:              opts,
		status:            types.StatusActive,
		CryptoProvider:    cryptoProvider,
		consensusRelation: types.ConsensusRelationConsenter,
	}
	// Sets initial values for metrics
	c.Metrics.ClusterSize.Set(float64(len(c.opts.BlockMetadata.ConsenterIds)))
	//c.Metrics.IsLeader.Set(float64(0)) // all nodes start out as followers
	c.Metrics.ActiveNodes.Set(float64(0))
	c.Metrics.CommittedBlockNumber.Set(float64(c.lastBlock.Header.Number))
	//c.Metrics.SnapshotBlockNumber.Set(float64(c.lastSnapBlockNum))
	c.bdlsStart = true
	return c, nil
}

// GetLatestState returns latest state
func (c *Chain) GetLatestState() (height uint64, round uint64, data bdls.State) {
	c.statusReportMutex.Lock()
	defer c.statusReportMutex.Unlock()
	return c.consensus.CurrentState()
}

func (c *Chain) Order(env *common.Envelope, configSeq uint64) error {
	//return c.Submit(&orderer.SubmitRequest{LastValidationSeq: configSeq, Payload: env, Channel: c.channelID}, 0)
	seq := c.support.Sequence()
	if configSeq < seq {
		c.logger.Warnf("Normal message was validated against %d, although current config seq has advanced (%d)", configSeq, seq)
		if _, err := c.support.ProcessNormalMsg(env); err != nil {
			return errors.Errorf("bad normal message: %s", err)
		}
	}

	return c.submit(env, configSeq)
}

func (c *Chain) Configure(env *common.Envelope, configSeq uint64) error {
	seq := c.support.Sequence()
	if configSeq < seq {
		c.logger.Warnf("Normal message was validated against %d, although current config seq has advanced (%d)", configSeq, seq)
		if configEnv, _, err := c.support.ProcessConfigMsg(env); err != nil {
			return errors.Errorf("bad normal message: %s", err)
		} else {
			return c.submit(configEnv, configSeq)
		}
	}

	return c.submit(env, configSeq)
}

func (c *Chain) WaitReady() error {
	//TODO
	return nil
}

// Errored returns a channel that closes when the chain stops.
func (c *Chain) Errored() <-chan struct{} {
	c.errorCLock.RLock()
	defer c.errorCLock.RUnlock()
	return c.errorC
}
func (c *Chain) configureComm() error {

	nodes, err := c.remotePeers()
	if err != nil {
		return err
	}

	c.configurator.Configure(c.channelID, nodes)
	return nil
}

// Start instructs the orderer to begin serving the chain and keep it current.
func (c *Chain) Start() {
	c.logger.Infof("Starting Bdls node")
	// retrieve the state at parent height
	/*parentState, err := c.stateAt(c.lastBlock.Header.PreviousHash)
	if err != nil {
		return
	}*/
	if err := c.configureComm(); err != nil {
		c.logger.Errorf("Failed to start chain, aborting: +%v", err)
		close(c.doneC)
		return
	}
	// create a consensus config to validate this message at the correct height
	config := &bdls.Config{
		Epoch:         time.Now(),
		CurrentHeight: c.lastBlock.Header.Number - 1, //0 .Will use Zero for testing
		StateCompare:  func(a bdls.State, b bdls.State) int { return bytes.Compare(a, b) },
		StateValidate: func(bdls.State) bool { return true },
	}

	config.Participants = append(config.Participants, c.participants...) // &bdls.DefaultPubKeyToIdentity())

	// create BDLS consensus Object
	consensus, err := bdls.NewConsensus(config)
	if err != nil {
		c.logger.Error("bdls.NewConsensus", "err", err)
		return
	}

	// Set the BDLS consensus Latency time
	consensus.SetLatency(200 * time.Millisecond)

	// start updater
	_ = consensus.Update(time.Now())
	// check if new block confirmed
	newHeight, newRound, newState := consensus.CurrentState()
	if newHeight > c.lastBlock.Header.Number {
		c.sealBlock(newHeight, newRound, newState)
		return
	}

	close(c.startC)

	go c.run()

}

const (
	HashLength = 32

	// AbdicationMaxAttempts determines how many retries of leadership abdication we do
	// for a transaction that removes ourselves from reconfiguration.
	AbdicationMaxAttempts = 5
)

// Hash represents the 32 byte Keccak256 hash of arbitrary data.
type Hash [HashLength]byte

// BytesToHash sets b to hash.
// If b is larger than len(h), b will be cropped from the left.
func (c *Chain) BytesToHash(b []byte) Hash {
	var h Hash
	h.SetBytes(b)
	return h
}

// SetBytes sets the hash to the value of b.
// If b is larger than len(h), b will be cropped from the left.
func (h *Hash) SetBytes(b []byte) {
	if len(b) > len(h) {
		b = b[len(b)-HashLength:]
	}

	copy(h[HashLength-len(b):], b)
}

// if a block hash has received it's decide message
func (c *Chain) sealBlock(newHeight uint64, newRound uint64, newState bdls.State) {
	// DECIDED
	hash := c.BytesToHash(newState)
	c.logger.Info("BDLS CONSENSUS <decide>", "HEIGHT", newHeight, "ROUND", newRound, "SEALHASH", hash)

	// every validator can finalize this block to it's local blockchain now
	newblock := &blockCreator{
		hash:   protoutil.BlockHeaderHash(c.lastBlock.Header),
		number: c.lastBlock.Header.Number,
		logger: c.logger,
	}
	if newblock != nil {
		// mined by me
		header := newblock.number
		// CurrentProof returns current <decide> message for current height
		bts, err := c.consensus.CurrentProof().Marshal()
		if err != nil {
			c.logger.Info("consensusMessenger", "consensus.CurrentProof", err)
			panic(err)
		}

		// seal the the proof in block header
		//header.Decision = bts
		c.logger.Info("Seal block at header:%d , and:%d ", header, bts)
		// broadcast the mined block
		//mined := newblock.WithSeal(header)

	}
}

func (c *Chain) propose(ch chan<- *common.Block, bc *blockCreator, batches ...[]*common.Envelope) {
	for _, batch := range batches {
		b := bc.createNextBlock(batch)
		c.logger.Infof("Created block [%d], there are %d blocks in flight", b.Header.Number, c.blockInflight)

		select {
		case ch <- b:
		default:
			c.logger.Panic("Programming error: limit of in-flight blocks does not properly take effect or block is proposed by follower")
		}

		// if it is config block, then we should wait for the commit of the block
		if protoutil.IsConfigBlock(b) {
			c.configInflight = true
		}

		c.blockInflight++
	}
}

// Submit forwards the incoming request to:
// - the local run goroutine if this is leader
// - the actual leader via the transport mechanism
// The call fails if there's no leader elected yet.
func (c *Chain) submit(env *common.Envelope, configSeq uint64) error {
	reqBytes, err := proto.Marshal(env)
	if err != nil {
		return errors.Wrapf(err, "failed to marshal request envelope")
	}

	c.logger.Debugf("Consensus.Propose ")
	//if err := c.consensus.ReceiveMessage(reqBytes, time.Now()); err != nil {
	/*if err := c.rpc.SendSubmit(0, reqBytes); err != nil {
		return errors.Wrapf(err, "failed to submit request")
	}*/
	report := func(err error) {
	}

	c.rpc.SendSubmit(0, &orderer.SubmitRequest{LastValidationSeq: configSeq, Payload: env, Channel: c.channelID}, report)
	// Propose the message to the current BDLS node due to
	// all orderer Node must resive the message to be validated
	// all BDLS node write the block on their own node

	//c.consensus.Propose(reqBytes)

	_ = c.consensus.SubmitRequest(reqBytes, time.Now()) // input to the BDLS core consensus to create (messageTuple)
	// check if new block confirmed
	newHeight, newRound, newState := c.consensus.CurrentState()
	if newHeight == c.lastBlock.Header.Number {
		c.sealBlock(newHeight, newRound, newState)
	}

	return nil
}

func (c *Chain) isRunning() error {
	select {
	case <-c.startC:
	default:
		return errors.Errorf("chain is not started")
	}

	select {
	case <-c.doneC:
		return errors.Errorf("chain is stopped")
	default:
	}

	return nil
}

// Consensus passes the given ConsensusRequest message to the bdls instance
func (c *Chain) Consensus(req *orderer.ConsensusRequest, sender uint64) error {
	if err := c.isRunning(); err != nil {
		return err
	}

	stepMsg := &bdls.Message{}
	if err := proto.Unmarshal(req.Payload, stepMsg); err != nil {
		return fmt.Errorf("failed to unmarshal StepRequest payload to BDLS Message: %s", err)
	}

	clusterMetadata := &protos.ClusterMetadata{}
	if err := proto.Unmarshal(req.Metadata, clusterMetadata); err != nil {
		return errors.Errorf("failed to unmarshal ClusterMetadata: %s", err)
	}

	return nil
}

func (c *Chain) commitBatches(batches ...[]*common.Envelope) error {
	for _, batch := range batches {
		b := c.support.CreateNextBlock(batch)
		data := protoutil.MarshalOrPanic(b)
		//TODO
		c.logger.Info(data)
		/*	if err := c.node.Propose(context.TODO(), data); err != nil {
				return errors.Errorf("failed to propose data to Bdls node: %s", err)
			}
		*/
		select {
		case block := <-c.commitC:
			if protoutil.IsConfigBlock(block) {
				c.support.WriteConfigBlock(block, nil)
			} else {
				c.support.WriteBlock(block, nil)
			}

		//case <-c.resignC:
		//	return errors.Errorf("aborted block committing: lost leadership")

		case <-c.doneC:
			return nil
		}
	}

	return nil
}

// Halt stops the chain.
func (c *Chain) Halt() {
	select {
	case c.haltC <- struct{}{}:
	case <-c.doneC:
		return
	}
	<-c.doneC
}

func (c *Chain) isConfig(env *common.Envelope) (bool, error) {
	h, err := protoutil.ChannelHeader(env)
	if err != nil {
		c.logger.Errorf("failed to extract channel header from envelope")
		return false, err
	}

	return h.Type == int32(common.HeaderType_CONFIG) || h.Type == int32(common.HeaderType_ORDERER_TRANSACTION), nil
}

func (c *Chain) remotePeers() ([]cluster.RemoteNode, error) {
	c.bdlsMetadataLock.RLock()
	defer c.bdlsMetadataLock.RUnlock()

	var nodes []cluster.RemoteNode
	for id, consenter := range c.opts.Consenters {
		// No need to know yourself
		//TODO get BDLS ID and diclear it in the Chain Stuct
		/*
			if id == 0 //c.id
			{
				continue
			}*/
		serverCertAsDER, err := pemToDER(consenter.ServerTlsCert, id, "server", c.logger)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		clientCertAsDER, err := pemToDER(consenter.ClientTlsCert, id, "client", c.logger)
		if err != nil {
			return nil, errors.WithStack(err)
		}

		nodes = append(nodes, cluster.RemoteNode{
			NodeAddress: cluster.NodeAddress{
				ID:       id,
				Endpoint: fmt.Sprintf("%s:%d", consenter.Host, consenter.Port),
			},
			NodeCerts: cluster.NodeCerts{
				ServerTLSCert: serverCertAsDER,
				ClientTLSCert: clientCertAsDER,
			},
		})

		// BDLS participants
		priv := new(ecdsa.PrivateKey)
		priv.PublicKey.Curve = bdls.S256Curve
		//priv.D = consenter.ServerTlsCert
		priv.PublicKey.X, priv.PublicKey.Y = bdls.S256Curve.ScalarBaseMult(consenter.ServerTlsCert)

		// Generate Bdls Consensus Group Participants []Identity
		/*cert, err := crypto.PublicKeyFromCertificate(consenter.ServerTlsCert)*/

		// set validator sequence
		c.participants = append(c.participants, bdls.DefaultPubKeyToIdentity(&priv.PublicKey))

	}
	return nodes, nil
}

func pemToDER(pemBytes []byte, id uint64, certType string, logger *flogging.FabricLogger) ([]byte, error) {
	bl, _ := pem.Decode(pemBytes)
	if bl == nil {
		logger.Errorf("Rejecting PEM block of %s TLS cert for node %d, offending PEM is: %s", certType, id, string(pemBytes))
		return nil, errors.Errorf("invalid PEM block")
	}
	return bl.Bytes, nil
}

// publicKeyFromCertificate returns the public key of the given ASN1 DER certificate.
/*func publicKeyFromCertificate(der []byte) ([]byte, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return x509.MarshalPKIXPublicKey(cert.PublicKey)
}*/

// blockCreator holds number and hash of latest block
// so that next block will be created based on it.
/*type blockCreator struct {
	hash   []byte
	number uint64

	logger *flogging.FabricLogger
}*/

func (c *Chain) writeBlock(block *common.Block, index uint64) {
	if block.Header.Number > c.lastBlock.Header.Number+1 {
		c.logger.Panicf("Got block [%d], expect block [%d]", block.Header.Number, c.lastBlock.Header.Number+1)
	} else if block.Header.Number < c.lastBlock.Header.Number+1 {
		c.logger.Infof("Got block [%d], expect block [%d], this node was forced to catch up", block.Header.Number, c.lastBlock.Header.Number+1)
		return
	}

	if c.blockInflight > 0 {
		c.blockInflight-- // only reduce on leader
	}
	c.lastBlock = block

	c.logger.Infof("Writing block [%d] (Raft index: %d) to ledger", block.Header.Number, index)

	if protoutil.IsConfigBlock(block) {
		//c.writeConfigBlock(block, index)
		return
	}

	c.bdlsMetadataLock.Lock()
	c.opts.BlockMetadata.BdlsIndex = index
	m := protoutil.MarshalOrPanic(c.opts.BlockMetadata)
	c.bdlsMetadataLock.Unlock()

	c.support.WriteBlock(block, m)
}

// Orders the envelope in the `msg` content. SubmitRequest.
// Returns
//
//	-- batches [][]*common.Envelope; the batches cut,
//	-- pending bool; if there are envelopes pending to be ordered,
//	-- err error; the error encountered, if any.
//
// It takes care of config messages as well as the revalidation of messages if the config sequence has advanced.
func (c *Chain) ordered(msg *orderer.SubmitRequest) (batches [][]*common.Envelope, pending bool, err error) {
	seq := c.support.Sequence()

	isconfig, err := c.isConfig(msg.Payload)
	if err != nil {
		return nil, false, errors.Errorf("bad message: %s", err)
	}

	if isconfig {
		// ConfigMsg
		if msg.LastValidationSeq < seq {
			c.logger.Warnf("Config message was validated against %d, although current config seq has advanced (%d)", msg.LastValidationSeq, seq)
			msg.Payload, _, err = c.support.ProcessConfigMsg(msg.Payload)
			if err != nil {
				c.Metrics.ProposalFailures.Add(1)
				return nil, true, errors.Errorf("bad config message: %s", err)
			}
		}

		batch := c.support.BlockCutter().Cut()
		batches = [][]*common.Envelope{}
		if len(batch) != 0 {
			batches = append(batches, batch)
		}
		batches = append(batches, []*common.Envelope{msg.Payload})
		return batches, false, nil
	}
	// it is a normal message
	if msg.LastValidationSeq < seq {
		c.logger.Warnf("Normal message was validated against %d, although current config seq has advanced (%d)", msg.LastValidationSeq, seq)
		if _, err := c.support.ProcessNormalMsg(msg.Payload); err != nil {
			c.Metrics.ProposalFailures.Add(1)
			return nil, true, errors.Errorf("bad normal message: %s", err)
		}
	}
	batches, pending = c.support.BlockCutter().Ordered(msg.Payload)
	return batches, pending, nil
}

func (c *Chain) run() {
	ticking := false
	timer := c.clock.NewTimer(time.Second)
	// we need a stopped timer rather than nil,
	// because we will be select waiting on timer.C()
	if !timer.Stop() {
		<-timer.C()
	}

	// if timer is already started, this is a no-op
	startTimer := func() {
		if !ticking {
			ticking = true
			timer.Reset(c.support.SharedConfig().BatchTimeout())
		}
	}

	stopTimer := func() {
		if !timer.Stop() && ticking {
			// we only need to drain the channel if the timer expired (not explicitly stopped)
			<-timer.C()
		}
		ticking = false
	}

	//var soft bdls.State
	submitC := c.submitC
	var bc *blockCreator

	var propC chan<- *common.Block
	var cancelProp context.CancelFunc
	cancelProp = func() {} // no-op as initial value

	becomeLeader := func() (chan<- *common.Block, context.CancelFunc) {

		c.blockInflight = 0

		submitC = nil
		ch := make(chan *common.Block, c.opts.MaxInflightBlocks)

		ctx, cancel := context.WithCancel(context.Background())
		go func(ctx context.Context, ch <-chan *common.Block) {
			for {
				select {
				case b := <-ch:
					data := protoutil.MarshalOrPanic(b)
					c.consensus.Propose(data)

					newHeight, newRound, newState := c.consensus.CurrentState()
					if newHeight > b.Header.Number {
						h := blake2b.Sum256(newState)
						log.Printf("<decide> at height:%v round:%v hash:%v", newHeight, newRound, hex.EncodeToString(h[:]))
						b.Header.Number = newHeight
					}
					c.logger.Debugf("Proposed block [%d] to BDLS consensus", b.Header.Number)

				case <-ctx.Done():
					c.logger.Debugf("Quit proposing blocks, discarded %d blocks in the queue", len(ch))
					return
				}
			}
		}(ctx, ch)

		return ch, cancel
	}
	c.logger.Info("becomeLeader: [%d]", becomeLeader)
	for {
		select {
		case s := <-submitC:
			if s == nil {
				// polled by `WaitReady`
				continue
			}

			batches, pending, err := c.ordered(s.req)
			if err != nil {
				c.logger.Errorf("Failed to order message: %s", err)
				continue
			}

			if !pending && len(batches) == 0 {
				continue
			}

			if pending {
				startTimer() // no-op if timer is already started
			} else {
				stopTimer()
			}

			c.propose(propC, bc, batches...)

			if c.configInflight {
				c.logger.Info("Received config transaction, pause accepting transaction till it is committed")
				submitC = nil
			} else if c.blockInflight >= c.opts.MaxInflightBlocks {
				c.logger.Debugf("Number of in-flight blocks (%d) reaches limit (%d), pause accepting transaction",
					c.blockInflight, c.opts.MaxInflightBlocks)
				submitC = nil
			}

		case app := <-c.applyC:

			c.apply(app.entries)
			// No need to check for a leader we assume is always true as all BDLS nodes need to commit the message
			//	if true {
			msgInflight := c.opts.BdlsID > c.appliedIndex
			if msgInflight {
				c.logger.Debugf("There are in flight blocks, new leader should not serve requests")
				//continue
			}

			if c.configInflight {
				c.logger.Debugf("There is config block in flight, new leader should not serve requests")
				//continue
			}

			c.logger.Infof("Start accepting requests as BDLS Node at block [%d]", c.lastBlock.Header.Number)
			bc = &blockCreator{
				hash:   protoutil.BlockHeaderHash(c.lastBlock.Header),
				number: c.lastBlock.Header.Number,
				logger: c.logger,
			}
			submitC = c.submitC
			//c.justElected = false
			//}
			if c.configInflight {
				c.logger.Info("Config block or ConfChange in flight, pause accepting transaction")
				submitC = nil
			} else if c.blockInflight < c.opts.MaxInflightBlocks {
				submitC = c.submitC
			}

		case <-timer.C():
			ticking = false

			batch := c.support.BlockCutter().Cut()
			if len(batch) == 0 {
				c.logger.Warningf("Batch timer expired with no pending requests, this might indicate a bug")
				continue
			}

			c.logger.Debugf("Batch timer expired, creating block")
			c.propose(propC, bc, batch) // we are certain this is normal block, no need to block

		case <-c.doneC:
			stopTimer()
			cancelProp()

			select {
			case <-c.errorC: // avoid closing closed channel
			default:
				close(c.errorC)
			}

			c.logger.Infof("Stop serving requests")
			//c.periodicChecker.Stop()
			return
		}
	}
}

type apply struct {
	entries []bdls.Message
	soft    *bdls.State
}

func (c *Chain) apply(ents []bdls.Message) {
	if len(ents) == 0 {
		return
	}

	if ents[0].Round > c.appliedIndex+1 {
		c.logger.Panicf("first index of committed entry[%d] should <= appliedIndex[%d]+1", ents[0].Round, c.appliedIndex)
	}

	for i := range ents {
		switch ents[i].Type {
		case bdls.MessageType_Decide:

			if len(ents[i].State) == 0 {
				break
			}

			/*
				// We need to strictly avoid re-applying normal entries,
				// otherwise we are writing the same block twice.
				if ents[i].Round <= c.appliedIndex {
					c.logger.Debugf("Received block with Bdls version (%d) <= applied index (%d), skip", ents[i].version, c.appliedIndex)
					break
				}
			*/
			block := protoutil.UnmarshalBlockOrPanic(ents[i].GetState())
			c.writeBlock(block, ents[i].GetRound())
			c.Metrics.CommittedBlockNumber.Set(float64(block.Header.Number))

		}

	}

}

/* replaced with c.lastBlock based on [FAB-14240]
func PreviousConfigBlockFromLedgerOrPanic(ledger Ledger, logger Logger) *cb.Block {
	block, err := previousConfigBlockFromLedger(ledger)
	if err != nil {
		logger.Panicf("Failed retrieving previous config block: %v", err)
	}
	return block
}

// LastConfigBlock returns the last config block relative to the given block.
func LastConfigBlock(block *com
	mon.Block, blockRetriever BlockRetriever) (*common.Block, error) {
	if block == nil {
		return nil, errors.New("nil block")
	}
	if blockRetriever == nil {
		return nil, errors.New("nil blockRetriever")
	}
	lastConfigBlockNum, err := protoutil.GetLastConfigIndexFromBlock(block)
	if err != nil {
		return nil, err
	}
	lastConfigBlock := blockRetriever.Block(lastConfigBlockNum)
	if lastConfigBlock == nil {
		return nil, errors.Errorf("unable to retrieve last config block [%d]", lastConfigBlockNum)
	}
	return lastConfigBlock, nil
}
*/
