/*
 Copyright Ahmed AlSalih @UNCC All Rights Reserved.

 SPDX-License-Identifier: Apache-2.0
*/

package bdls

import (
	"encoding/pem"
	"path"

	"code.cloudfoundry.org/clock"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-protos-go/common"

	//"github.com/hyperledger/fabric-protos-go/orderer/bdls"
	bdlspb "github.com/hyperledger/fabric-protos-go/orderer/bdls"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/common/crypto"
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric/orderer/common/cluster"
	"github.com/hyperledger/fabric/orderer/common/localconfig"
	"github.com/hyperledger/fabric/orderer/common/types"
	"github.com/hyperledger/fabric/orderer/consensus"
	"github.com/pkg/errors"
	"go.etcd.io/etcd/raft/v3"
	//bdls "github.com/BDLS-bft/bdls"
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
	BCCSP                 bccsp.BCCSP
	Dialer                *cluster.PredicateDialer
}

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

	peers := make([]raft.Peer, len(m.Consenters))
	for i := range peers {
		peers[i].ID = uint64(i + 1)
	}
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
