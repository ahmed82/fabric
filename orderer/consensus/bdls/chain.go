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
	"encoding/pem"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"code.cloudfoundry.org/clock"
	"github.com/BDLS-bft/bdls"
	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-protos-go/orderer"
	bdlspb "github.com/hyperledger/fabric-protos-go/orderer/bdls"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric/orderer/common/cluster"
	"github.com/hyperledger/fabric/orderer/common/types"
	"github.com/hyperledger/fabric/orderer/consensus"
	"github.com/pkg/errors"
	"go.etcd.io/etcd/raft/v3"

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

	bdlsID    uint64
	channelID string
	consensus *bdls.Consensus

	config   *bdls.Config
	submitC  chan *submit //chan *orderer.SubmitRequest
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
	lastConfigBlock *common.Block
	createPuller    CreateBlockPuller // func used to create BlockPuller on demand

	// BCCSP instance
	CryptoProvider bccsp.BCCSP

	opts   Options
	logger *flogging.FabricLogger

	bdlsMetadataLock sync.RWMutex

	statusReportMutex sync.Mutex
	consensusRelation types.ConsensusRelation
	status            types.Status

	configInflight bool // this is true when there is config block or ConfChange in flight
	blockInflight  int  // number of in flight blocks

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
	BlockMetadata *bdlspb.BlockMetadata
	Consenters    map[uint64]*bdlspb.Consenter
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
	observeC chan<- raft.SoftState,
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

	return c, nil
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

// Start instructs the orderer to begin serving the chain and keep it current.
func (c *Chain) Start() {
	c.logger.Infof("Starting Bdls node")
	// retrieve the state at parent height
	/*parentState, err := c.stateAt(c.lastBlock.Header.PreviousHash)
	if err != nil {
		return
	}*/
	// create a consensus config to validate this message at the correct height
	config := &bdls.Config{
		Epoch:         time.Now(),
		CurrentHeight: c.lastBlock.Header.Number, //0 .Will use Zero for testing
		StateCompare:  func(a bdls.State, b bdls.State) int { return bytes.Compare(a, b) },
		StateValidate: func(bdls.State) bool { return true },
	}

	config.Participants = c.opts.participants

	// create BDLS consensus Object
	consensus, err := bdls.NewConsensus(config)
	if err != nil {
		c.logger.Error("bdls.NewConsensus", "err", err)
		return
	}

	// Set the BDLS consensus Latency time
	consensus.SetLatency(200 * time.Millisecond)

	// start updater
	consensus.Update(time.Now())

	close(c.startC)

	go c.run()

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

	var state bdls.State
	submitC := c.submitC
	var bc *blockCreator

	var propC chan<- *common.Block
	var cancelProp context.CancelFunc
	cancelProp = func() {} // no-op as initial value

	becomeLeader := func() (chan<- *common.Block, context.CancelFunc) {
		//	c.Metrics.IsLeader.Set(1)

		c.blockInflight = 0
		//	c.justElected = true
		submitC = nil
		ch := make(chan *common.Block, c.opts.MaxInflightBlocks)

		// All DBLS Orderer nodes should call Propose in go routine, because this method may be blocked
		// if node is leaderless (this can happen when leader steps down in a heavily
		// loaded network). We need to make sure applyC can still be consumed properly.
		ctx, cancel := context.WithCancel(context.Background())
		go func(ctx context.Context, ch <-chan *common.Block) {
			for {
				select {
				case b := <-ch:
					data := protoutil.MarshalOrPanic(b)
					if err := c.consensus.Propose(ctx, data); err != nil {
						c.logger.Errorf("Failed to propose block [%d] to raft and discard %d blocks in queue: %s", b.Header.Number, len(ch), err)
						return
					}
					c.logger.Debugf("Proposed block [%d] to raft consensus", b.Header.Number)

				case <-ctx.Done():
					c.logger.Debugf("Quit proposing blocks, discarded %d blocks in the queue", len(ch))
					return
				}
			}
		}(ctx, ch)

		return ch, cancel
	}

	/*becomeFollower := func() {
		cancelProp()
		c.blockInflight = 0
		_ = c.support.BlockCutter().Cut()
		stopTimer()
		submitC = c.submitC
		bc = nil
		c.Metrics.IsLeader.Set(0)
	}*/

	for {
		select {
		case s := <-submitC:
			if s == nil {
				// polled by `WaitReady`
				continue
			}

			/*if state == raft.StatePreCandidate || soft.RaftState == raft.StateCandidate {
				s.leader <- raft.None
				continue
			}

			s.leader <- soft.Lead
			if soft.Lead != c.raftID {
				continue
			}*/

			// It takes care of config messages as well as the revalidation of messages if the config sequence has advanced.
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
			if app.soft != nil {
				newLeader := atomic.LoadUint64(&app.soft.Lead) // etcdraft requires atomic access
				if newLeader != soft.Lead {
					c.logger.Infof("Raft leader changed: %d -> %d", soft.Lead, newLeader)
					c.Metrics.LeaderChanges.Add(1)

					atomic.StoreUint64(&c.lastKnownLeader, newLeader)

					if newLeader == c.raftID {
						propC, cancelProp = becomeLeader()
					}

					if soft.Lead == c.raftID {
						becomeFollower()
					}
				}

				foundLeader := soft.Lead == raft.None && newLeader != raft.None
				quitCandidate := isCandidate(soft.RaftState) && !isCandidate(app.soft.RaftState)

				if foundLeader || quitCandidate {
					c.errorCLock.Lock()
					c.errorC = make(chan struct{})
					c.errorCLock.Unlock()
				}

				if isCandidate(app.soft.RaftState) || newLeader == raft.None {
					atomic.StoreUint64(&c.lastKnownLeader, raft.None)
					select {
					case <-c.errorC:
					default:
						nodeCount := len(c.opts.BlockMetadata.ConsenterIds)
						// Only close the error channel (to signal the broadcast/deliver front-end a consensus backend error)
						// If we are a cluster of size 3 or more, otherwise we can't expand a cluster of size 1 to 2 nodes.
						if nodeCount > 2 {
							close(c.errorC)
						} else {
							c.logger.Warningf("No leader is present, cluster size is %d", nodeCount)
						}
					}
				}

				soft = raft.SoftState{Lead: newLeader, RaftState: app.soft.RaftState}

				// notify external observer
				select {
				case c.observeC <- soft:
				default:
				}

				lcs := c.Node.leaderChangeSubscription.Load()
				if lcs != nil {
					if soft.Lead != raft.None {
						subscription := lcs.(func(uint64))
						subscription(soft.Lead)
					}
				}
			}

			c.apply(app.entries)

			/*if c.justElected {
				msgInflight := c.Node.lastIndex() > c.appliedIndex
				if msgInflight {
					c.logger.Debugf("There are in flight blocks, new leader should not serve requests")
					continue
				}

				if c.configInflight {
					c.logger.Debugf("There is config block in flight, new leader should not serve requests")
					continue
				}

				c.logger.Infof("Start accepting requests as Raft leader at block [%d]", c.lastBlock.Header.Number)
				bc = &blockCreator{
					hash:   protoutil.BlockHeaderHash(c.lastBlock.Header),
					number: c.lastBlock.Header.Number,
					logger: c.logger,
				}
				submitC = c.submitC
				c.justElected = false
			} else if c.configInflight {
				c.logger.Info("Config block or ConfChange in flight, pause accepting transaction")
				submitC = nil
			} else if c.blockInflight < c.opts.MaxInflightBlocks {
				submitC = c.submitC
			}*/

		case <-timer.C():
			ticking = false

			batch := c.support.BlockCutter().Cut()
			if len(batch) == 0 {
				c.logger.Warningf("Batch timer expired with no pending requests, this might indicate a bug")
				continue
			}

			c.logger.Debugf("Batch timer expired, creating block")
			c.propose(propC, bc, batch) // we are certain this is normal block, no need to block

		/*case sn := <-c.snapC:
		if sn.Metadata.Index != 0 {
			if sn.Metadata.Index <= c.appliedIndex {
				c.logger.Debugf("Skip snapshot taken at index %d, because it is behind current applied index %d", sn.Metadata.Index, c.appliedIndex)
				break
			}

			c.confState = sn.Metadata.ConfState
			c.appliedIndex = sn.Metadata.Index
		} else {
			c.logger.Infof("Received artificial snapshot to trigger catchup")
		}

		if err := c.catchUp(sn); err != nil {
			c.logger.Panicf("Failed to recover from snapshot taken at Term %d and Index %d: %s",
				sn.Metadata.Term, sn.Metadata.Index, err)
		}*/

		case <-c.doneC:
			stopTimer()
			cancelProp()

			select {
			case <-c.errorC: // avoid closing closed channel
			default:
				close(c.errorC)
			}

			c.logger.Infof("Stop serving requests")
			c.periodicChecker.Stop()
			return
		}
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

	// Propose the message to the current BDLS node due to
	// all orderer Node must resive the message to be validated
	// all BDLS node write the block on their own node
	c.consensus.Propose(reqBytes)
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

	clusterMetadata := &bdlspb.ClusterMetadata{}
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
		if id == 0 /*c.id */ {
			continue
		}
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

// blockCreator holds number and hash of latest block
// so that next block will be created based on it.
/*type blockCreator struct {
	hash   []byte
	number uint64

	logger *flogging.FabricLogger
}*/
