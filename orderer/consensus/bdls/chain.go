/*
 Copyright Ahmed AlSalih @UNCC All Rights Reserved.
 SPDX-License-Identifier: Apache-2.0
*/

package bdls

import (
	bdls "github.com/BDLS-bft/bdls"
	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric/orderer/consensus"
)

// Chain implements consensus.Chain interface.
type Chain struct {
	consensus *bdls.Consensus
	Logger    *flogging.FabricLogger
	support   consensus.ConsenterSupport
	Config    *bdls.Config
}

func (c *Chain) Order(env *common.Envelope, configSeq uint64) error {
	//TODO
	return nil
}

func (c *Chain) Configure(env *common.Envelope, configSeq uint64) error {
	//TODO
	return nil
}
