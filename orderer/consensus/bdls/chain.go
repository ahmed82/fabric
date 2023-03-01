/*
 Copyright Ahmed AlSalih @UNCC All Rights Reserved.

 SPDX-License-Identifier: Apache-2.0
*/

package bdls

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/pem"
	"fmt"
	"sync"
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

	//[FAB-14240] Do not use support.Height in chain
	//Commitment of block is doen aync win blockwritter, therefore
	//`support.Height` may not correctly reflect the actual number
	//of latest block. Decision made based on `support.Height` while
	//chain is running may lead to replaying of same block.
	// https://github.com/BDLS-bft/fabric/commit/dc170d497b0a474787fc00694c0a0942697399d8
	lastBlock *common.Block

	createPuller CreateBlockPuller // func used to create BlockPuller on demand

	// BCCSP instance
	CryptoProvider bccsp.BCCSP

	opts   Options
	logger *flogging.FabricLogger

	bdlsMetadataLock sync.RWMutex

	statusReportMutex sync.Mutex
	consensusRelation types.ConsensusRelation
	status            types.Status
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
	participants []*bdls.Identity

	Clock clock.Clock

	WALDir string

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

// NewChain constructs a chain object.
func NewChain(
	support consensus.ConsenterSupport,
	opts Options,
	conf Configurator,
	rpc RPC,
	cryptoProvider bccsp.BCCSP,
	f CreateBlockPuller,
	haltCallback func(),
	observeC chan<- raft.SoftState,
) (*Chain, error) {

	b := support.Block(support.Height() - 1)
	if b == nil {
		return nil, errors.Errorf("failed to get last block")
	}
	c := &Chain{
		configurator: conf,
		rpc:          rpc,
		channelID:    support.ChannelID(),
		bdlsID:       opts.BdlsID,
		submitC:      make(chan *submit), //make(chan *orderer.SubmitRequest),
		commitC:      make(chan *common.Block),
		haltC:        make(chan struct{}),
		doneC:        make(chan struct{}),
		resignC:      make(chan struct{}),
		startC:       make(chan struct{}),
		lastBlock:    b,
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
type submit struct {
	req *orderer.SubmitRequest
	//leader chan uint64
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
	//TODO
	return nil
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

	// create a consensus config to validate this message at the correct height
	config := &bdls.Config{
		Epoch:         time.Now(),
		CurrentHeight: c.lastBlock.Header.Number, //0 I will Zero for testing
		StateCompare:  func(a bdls.State, b bdls.State) int { return bytes.Compare(a, b) },
		StateValidate: func(bdls.State) bool { return true },
	}

	config.Participants = c.opts.Peers

	// create BDLS consensus Object
	consensus, err := bdls.NewConsensus(config)
	if err != nil {
		return
	}

	// Set the BDLS consensus Latency time
	consensus.SetLatency(200 * time.Millisecond)
	close(c.startC)

	//go c.run()

}

func (c *Chain) submit(env *common.Envelope, configSeq uint64) error {
	reqBytes, err := proto.Marshal(env)
	if err != nil {
		return errors.Wrapf(err, "failed to marshal request envelope")
	}

	c.logger.Debugf("Consensus.ReceiveMessage, node id ")
	if err := c.consensus.ReceiveMessage(reqBytes, time.Now()); err != nil {
		return errors.Wrapf(err, "failed to submit request")
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
