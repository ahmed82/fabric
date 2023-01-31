/*
 Copyright Ahmed AlSalih @UNCC All Rights Reserved.
 SPDX-License-Identifier: Apache-2.0
*/

package bdls

import (
	cb "github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric/orderer/consensus"
	"github.com/pkg/errors"
	//bdls "github.com/BDLS-bft/bdls"
)

// Consenter implements BDLS consenter
type Consenter struct {
	Logger *flogging.FabricLogger
}

// HandleChain returns a new Chain instance or an error upon failure
func (c *Consenter) HandleChain(support consensus.ConsenterSupport, metadata *cb.Metadata) (consensus.Chain, error) {
	//   HandleChain(support ConsenterSupport, metadata *cb.Metadata) (Chain, error)
	//TODO
	return nil, errors.New("BDLS on progress integration")
}
