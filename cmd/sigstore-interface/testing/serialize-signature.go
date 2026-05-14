package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	coSigRemote "github.com/sigstore/cosign/v3/pkg/oci/remote"
)

type CosignOCISignature struct {
	Manifest string            `json:"Manifest"`
	Layers   map[string]string `json:"Payloads"`
}

// This will take an image reference (via digest) and pull the cosign signature
// image from the same registry. The signature will then be serialized into the
// JSON format that is accepted by the main image verification binary and saved
// in a file
func main() {
	if len(os.Args) == 1 {
		panic("image reference argument required")
	}
	imageReference := os.Args[1]
	imageReferenceObj, err := name.NewDigest(imageReference)
	if err != nil {
		panic(err)
	}
	signatureReferenceObj, err := coSigRemote.SignatureTag(imageReferenceObj)
	if err != nil {
		panic(err)
	}

	img, err := remote.Image(signatureReferenceObj)
	var te *transport.Error
	if errors.As(err, &te) {
		if te.StatusCode != http.StatusNotFound {
			panic(te)
		}
	} else if err != nil {
		panic(err)
	}

	retrievedSignature := CosignOCISignature{}
	retrievedSignature.Layers = make(map[string]string)

	rawManifest, err := img.RawManifest()
	if err != nil {
		panic(err)
	}

	retrievedSignature.Manifest = string(rawManifest)

	layers, err := img.Layers()
	if err != nil {
		panic(err)
	}

	for _, layer := range layers {
		layerReader, err := layer.Uncompressed()
		if err != nil {
			panic(err)
		}
		layerBytes, err := io.ReadAll(layerReader)
		if err != nil {
			panic(err)
		}
		layerDigest, err := layer.Digest()
		if err != nil {
			panic(err)
		}
		retrievedSignature.Layers[layerDigest.String()] = string(layerBytes)
	}

	signatureJSON, err := json.Marshal(retrievedSignature)
	if err != nil {
		panic(err)
	}

	info, err := os.Stat("signatures")
	if os.IsNotExist(err) || !info.IsDir() {
		err = os.Mkdir("signatures", os.ModePerm)
		if err != nil {
			panic(err)
		}
	} else if err != nil {
		panic(err)
	}

	f, err := os.Create(fmt.Sprintf("signatures/%s.json", strings.ReplaceAll(imageReference, "/", "_")))
	if err != nil {
		panic(err)
	}

	_, err = f.Write(signatureJSON)
	if err != nil {
		panic(err)
	}
}
