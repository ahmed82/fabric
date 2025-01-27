/*
 Copyright All Rights Reserved.

 SPDX-License-Identifier: Apache-2.0
*/

package bdls

import (
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-protos-go/common"

	protos "github.com/BDLS-bft/fabric-protos-go/orderer/bdls"
	//"protos"

	//"github.com/hyperledger/fabric/orderer/consensus/bdls/protos"
	"github.com/pkg/errors"
	"go.etcd.io/etcd/client/pkg/v3/fileutil"
)

// Exist returns true if there are any files in a given directory.
func Exist(dir string) bool {
	names, err := fileutil.ReadDir(dir, fileutil.WithExt(".wal"))
	if err != nil {
		return false
	}
	return len(names) != 0
}

// CreateConsentersMap creates a map of BDLS IDs to Consenter given the block metadata and the config metadata.
func CreateConsentersMap(blockMetadata *protos.BlockMetadata, configMetadata *protos.ConfigMetadata) map[uint64]*protos.Consenter {
	consenters := map[uint64]*protos.Consenter{}
	for i, consenter := range configMetadata.Consenters {
		consenters[blockMetadata.ConsenterIds[i]] = consenter
	}
	return consenters
}

// ReadBlockMetadata attempts to read raft metadata from block metadata, if available.
// otherwise, it reads raft metadata from config metadata supplied.
func ReadBlockMetadata(blockMetadata *common.Metadata, configMetadata *protos.ConfigMetadata) (*protos.BlockMetadata, error) {
	if blockMetadata != nil && len(blockMetadata.Value) != 0 { // we have consenters mapping from block
		m := &protos.BlockMetadata{}
		if err := proto.Unmarshal(blockMetadata.Value, m); err != nil {
			return nil, errors.Wrap(err, "failed to unmarshal block's metadata")
		}
		return m, nil
	}

	m := &protos.BlockMetadata{
		NextConsenterId: 1,
		ConsenterIds:    make([]uint64, len(configMetadata.Consenters)),
	}
	// need to read consenters from the configuration
	for i := range m.ConsenterIds {
		m.ConsenterIds[i] = m.NextConsenterId
		m.NextConsenterId++
	}

	return m, nil
}
