package main

import (
	"strings"
	"testing"

	"github.com/neuvector/neuvector/share"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/protoadapt"
)

func TestNextCveDBUploadBatchHonorsByteLimit(t *testing.T) {
	const maxBatchBytes = 1500
	entries := map[string]*share.ScanVulnerability{
		"CVE-1": {Description: strings.Repeat("x", 1024), Severity: "High"},
		"CVE-2": {Description: strings.Repeat("x", 1024), Severity: "High"},
		"CVE-3": {Description: strings.Repeat("x", 1024), Severity: "High"},
	}
	data := &share.ScannerRegisterData{CVEDBVersion: "4.328", ID: "scanner"}

	batch, err := nextCveDBUploadBatch(data, entries, cvedbChunkMax, maxBatchBytes)

	require.NoError(t, err)
	require.NotEmpty(t, batch)
	assert.Less(t, len(batch), len(entries), "byte limit should split the V2 upload")
	request := *data
	request.CVEDB = batch
	assert.LessOrEqual(t, proto.Size(protoadapt.MessageV2Of(&request)), maxBatchBytes)
}

func TestNextCveDBUploadBatchRejectsOversizedEntry(t *testing.T) {
	entries := map[string]*share.ScanVulnerability{
		"CVE-1": {Description: strings.Repeat("x", 1024), Severity: "High"},
	}

	_, err := nextCveDBUploadBatch(&share.ScannerRegisterData{}, entries, cvedbChunkMax, 1)

	require.ErrorContains(t, err, "exceeding the 1 byte batch limit")
}
