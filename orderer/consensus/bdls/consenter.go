/*
 Copyright Ahmed AlSalih @UNCC All Rights Reserved.

 SPDX-License-Identifier: Apache-2.0
*/

package bdls

import (
	"encoding/pem"

	"github.com/golang/protobuf/proto"
	cb "github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric/common/crypto"
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric/orderer/common/cluster"
	"github.com/hyperledger/fabric/orderer/consensus"
	bdls "github.com/hyperledger/fabric/orderer/consensus/bdls/protos"

	//"github.com/hyperledger/fabric/orderer/consensus/etcdraft"
	"github.com/pkg/errors"
	"go.etcd.io/etcd/raft/v3"
	//bdls "github.com/BDLS-bft/bdls"
)

// Consenter implements BDLS consenter
type Consenter struct {
	Cert   []byte
	Logger *flogging.FabricLogger
	//ChainManager ChainManager
}

// HandleChain returns a new Chain instance or an error upon failure
func (c *Consenter) HandleChain(support consensus.ConsenterSupport, metadata *cb.Metadata) (consensus.Chain, error) {
	//   HandleChain(support ConsenterSupport, metadata *cb.Metadata) (Chain, error)
	m := &bdls.Metadata{}
	if err := proto.Unmarshal(support.SharedConfig().ConsensusMetadata(), m); err != nil {
		return nil, errors.Errorf("failed to unmarshal consensus metadata: %s", err)
	}

	id, err := c.detectRaftID(m)
	if err != nil {
		return nil, err
	}

	peers := make([]raft.Peer, len(m.Consenters))
	for i := range peers {
		peers[i].ID = uint64(i + 1)
	}

	return NewChain(support, opts, nil)
	//TODO
	return nil, errors.New("BDLS on progress integration")
}

func pemToDER2(pemBytes []byte, id uint64, certType string, logger *flogging.FabricLogger) ([]byte, error) {
	bl, _ := pem.Decode(pemBytes)
	if bl == nil {
		logger.Errorf("Rejecting PEM block of %s TLS cert for node %d, offending PEM is: %s", certType, id, string(pemBytes))
		return nil, errors.Errorf("invalid PEM block")
	}
	return bl.Bytes, nil
}

func (c *Consenter) detectSelfID(consenters []*bdls.Consenter) (uint64, error) {
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
