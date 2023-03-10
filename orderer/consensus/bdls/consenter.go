/*
 Copyright All Rights Reserved.

 SPDX-License-Identifier: Apache-2.0
*/

package bdls

import (
	"encoding/pem"
	"path"

	"code.cloudfoundry.org/clock"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-protos-go/orderer"
	"github.com/mitchellh/mapstructure"

	//"github.com/hyperledger/fabric-protos-go/orderer/bdls"
	bdlspb "github.com/hyperledger/fabric-protos-go/orderer/bdls"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/common/crypto"
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric/common/metrics"
	"github.com/hyperledger/fabric/internal/pkg/comm"
	"github.com/hyperledger/fabric/orderer/common/cluster"
	"github.com/hyperledger/fabric/orderer/common/localconfig"
	"github.com/hyperledger/fabric/orderer/common/types"
	"github.com/hyperledger/fabric/orderer/consensus"
	"github.com/pkg/errors"
)

// Consenter implements BDLS consenter
type Consenter struct {
	Cert                  []byte
	Logger                *flogging.FabricLogger
	BdlsConfig            Config
	Communication         cluster.Communicator
	OrdererConfig         localconfig.TopLevel
	InactiveChainRegistry InactiveChainRegistry
	ChainManager          ChainManager
	Metrics               *Metrics
	BCCSP                 bccsp.BCCSP
	Dialer                *cluster.PredicateDialer
	*Dispatcher
}

// TargetChannel extracts the channel from the given proto.Message.
// Returns an empty string on failure.
func (c *Consenter) TargetChannel(message proto.Message) string {
	switch req := message.(type) {
	case *orderer.ConsensusRequest:
		return req.Channel
	case *orderer.SubmitRequest:
		return req.Channel
	default:
		return ""
	}
}

// ReceiverByChain returns the MessageReceiver for the given channelID or nil
// if not found.
/*func (c *Consenter) ReceiverByChain(channelID string) MessageReceiver {
	chain := c.ChainManager.GetConsensusChain(channelID)
	if chain == nil {
		return nil
	}
	if bdlsChain, isBdlsChain := chain.(*Chain); isBdlsChain {
		return bdlsChain
	}
	c.Logger.Warningf("Chain %s is of type %v and not etcdraft.Chain", channelID, bdls.TypeOf(chain))
	return nil
}*/

// ChainManager defines the methods from multichannel.Registrar needed by the Consenter.
type ChainManager interface {
	GetConsensusChain(channelID string) consensus.Chain
	CreateChain(channelID string)
	SwitchChainToFollower(channelID string)
	ReportConsensusRelationAndStatusMetrics(channelID string, relation types.ConsensusRelation, status types.Status)
}

// InactiveChainRegistry registers chains that are inactive
type InactiveChainRegistry interface {
	// TrackChain tracks a chain with the given name, and calls the given callback
	// when this chain should be created.
	TrackChain(chainName string, genesisBlock *common.Block, createChain func())
	// Stop stops the InactiveChainRegistry. This is used when removing the
	// system channel.
	Stop()
}

// HandleChain returns a new Chain instance or an error upon failure
func (c *Consenter) HandleChain(support consensus.ConsenterSupport, metadata *common.Metadata) (consensus.Chain, error) {
	//   HandleChain(support ConsenterSupport, metadata *cb.Metadata) (Chain, error)
	m := &bdlspb.ConfigMetadata{}
	if err := proto.Unmarshal(support.SharedConfig().ConsensusMetadata(), m); err != nil {
		return nil, errors.Errorf("failed to unmarshal consensus metadata: %s", err)
	}

	if m.Options == nil {
		return nil, errors.New("BDLS options have not been provided")
	}

	blockMetadata, err := ReadBlockMetadata(metadata, m)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read BDLS metadata")
	}

	consenters := CreateConsentersMap(blockMetadata, m)

	id, err := c.detectSelfID(consenters)
	if err != nil {
		return nil, err
	}
	// TODO create BDLS Nodes []bdls.Identity
	/*peers := make([]raft.Peer, len(m.Consenters))
	for i := range peers {
		peers[i].ID = uint64(i + 1)
	}*/
	opts := Options{
		RPCTimeout:    c.OrdererConfig.General.Cluster.RPCTimeout,
		BdlsID:        id,
		Clock:         clock.NewClock(),
		Logger:        c.Logger,
		BlockMetadata: blockMetadata,
		Consenters:    consenters,
		WALDir:        path.Join(c.BdlsConfig.WALDir, support.ChannelID()),
		Cert:          c.Cert,
	}

	rpc := &cluster.RPC{
		Timeout:       c.OrdererConfig.General.Cluster.RPCTimeout,
		Logger:        c.Logger,
		Channel:       support.ChannelID(),
		Comm:          c.Communication,
		StreamsByType: cluster.NewStreamsByType(),
	}

	var haltCallback func() // called after the bdls.Chain halts when it detects eviction form the cluster.
	//return NewChain(support, opts, nil)
	//TODO
	if c.InactiveChainRegistry != nil {
		// when we have a system channel, we use the InactiveChainRegistry to track membership upon eviction.
		c.Logger.Info("With system channel: after eviction InactiveChainRegistry.TrackChain will be called")
		haltCallback = func() {
			c.InactiveChainRegistry.TrackChain(support.ChannelID(), nil, func() { c.ChainManager.CreateChain(support.ChannelID()) })
			c.ChainManager.ReportConsensusRelationAndStatusMetrics(support.ChannelID(), types.ConsensusRelationConfigTracker, types.StatusInactive)
		}
	} else {
		// when we do NOT have a system channel, we switch to a follower.Chain upon eviction.
		c.Logger.Info("Without system channel: after eviction Registrar.SwitchToFollower will be called")
		haltCallback = func() { c.ChainManager.SwitchChainToFollower(support.ChannelID()) }
	}
	//return nil, errors.New("BDLS on progress integration")
	return NewChain(
		support,
		opts,
		c.Communication,
		rpc,
		c.BCCSP,
		func() (BlockPuller, error) {
			return NewBlockPuller(support, c.Dialer, c.OrdererConfig.General.Cluster, c.BCCSP)
		},
		haltCallback,
		nil,
	)
}

// New creates a BDLS Consenter
func New(
	//pmr PolicyManagerRetriever,
	//signerSerializer signerSerializer,
	clusterDialer *cluster.PredicateDialer,
	conf *localconfig.TopLevel,
	srvConf comm.ServerConfig,
	srv *comm.GRPCServer,
	registrar ChainManager, //*multichannel.Registrar,
	icr InactiveChainRegistry,
	metricsProvider metrics.Provider,
	bccsp bccsp.BCCSP,
) *Consenter {
	logger := flogging.MustGetLogger("orderer.consensus.bdls")

	var cfg Config
	err := mapstructure.Decode(conf.Consensus, &cfg)
	if err != nil {
		logger.Panicf("Failed to decode bdls configuration: %s", err)
	}

	consenter := &Consenter{
		ChainManager:          registrar,
		Cert:                  srvConf.SecOpts.Certificate,
		Logger:                logger,
		BdlsConfig:            cfg,
		OrdererConfig:         *conf,
		Dialer:                clusterDialer,
		Metrics:               NewMetrics(metricsProvider),
		InactiveChainRegistry: icr,
		BCCSP:                 bccsp,
	}
	/*consenter.Dispatcher = &Dispatcher{
		Logger:        logger,
		ChainSelector: consenter,
	}*/

	comm := createComm(clusterDialer, consenter, conf.General.Cluster, metricsProvider)
	consenter.Communication = comm
	svc := &cluster.Service{
		CertExpWarningThreshold:          conf.General.Cluster.CertExpirationWarningThreshold,
		MinimumExpirationWarningInterval: cluster.MinimumExpirationWarningInterval,
		StreamCountReporter: &cluster.StreamCountReporter{
			Metrics: comm.Metrics,
		},
		StepLogger: flogging.MustGetLogger("orderer.common.cluster.step"),
		Logger:     flogging.MustGetLogger("orderer.common.cluster"),
		Dispatcher: comm,
	}
	orderer.RegisterClusterServer(srv.Server(), svc)

	if icr == nil {
		logger.Debug("Created an BDLS consenter without a system channel, InactiveChainRegistry is nil")
	}

	return consenter
}

func createComm(clusterDialer *cluster.PredicateDialer, c *Consenter, config localconfig.Cluster, p metrics.Provider) *cluster.Comm {
	metrics := cluster.NewMetrics(p)
	logger := flogging.MustGetLogger("orderer.common.cluster")

	compareCert := cluster.CachePublicKeyComparisons(func(a, b []byte) bool {
		err := crypto.CertificatesWithSamePublicKey(a, b)
		if err != nil && err != crypto.ErrPubKeyMismatch {
			crypto.LogNonPubKeyMismatchErr(logger.Errorf, err, a, b)
		}
		return err == nil
	})

	comm := &cluster.Comm{
		MinimumExpirationWarningInterval: cluster.MinimumExpirationWarningInterval,
		CertExpWarningThreshold:          config.CertExpirationWarningThreshold,
		SendBufferSize:                   config.SendBufferSize,
		Logger:                           logger,
		Chan2Members:                     make(map[string]cluster.MemberMapping),
		Connections:                      cluster.NewConnectionStore(clusterDialer, metrics.EgressTLSConnectionCount),
		Metrics:                          metrics,
		ChanExt:                          c,
		H:                                c,
		CompareCertificate:               compareCert,
	}
	c.Communication = comm
	return comm
}
func pemToDER2(pemBytes []byte, id uint64, certType string, logger *flogging.FabricLogger) ([]byte, error) {
	bl, _ := pem.Decode(pemBytes)
	if bl == nil {
		logger.Errorf("Rejecting PEM block of %s TLS cert for node %d, offending PEM is: %s", certType, id, string(pemBytes))
		return nil, errors.Errorf("invalid PEM block")
	}
	return bl.Bytes, nil
}

// Config contains etcdraft configurations
type Config struct {
	WALDir string // WAL data of <my-channel> is stored in WALDir/<my-channel>
}

func (c *Consenter) detectSelfID(consenters map[uint64]*bdlspb.Consenter) (uint64, error) {
	thisNodeCertAsDER, err := pemToDER(c.Cert, 0, "server", c.Logger)
	if err != nil {
		return 0, err
	}

	var serverCertificates []string
	for nodeID, cst := range consenters {
		serverCertificates = append(serverCertificates, string(cst.ServerTlsCert))

		certAsDER, err := pemToDER(cst.ServerTlsCert, nodeID, "server", c.Logger)
		if err != nil {
			return 0, err
		}

		if crypto.CertificatesWithSamePublicKey(thisNodeCertAsDER, certAsDER) == nil {
			return nodeID, nil
		}
	}

	c.Logger.Warning("Could not find", string(c.Cert), "among", serverCertificates)
	return 0, cluster.ErrNotInChannel
}
