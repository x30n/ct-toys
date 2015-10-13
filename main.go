package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/stvp/go-toml-config"
)

const (
	logVersion           = 0
	certificateTimestamp = 0
	treeHash             = 1
	hashSHA256           = 4
	sigECDSA             = 3
)

// const OUTDIR = "pems"
// const searchTerm = "kommit.biz"

type LogEntryType uint16

const (
	X509Entry    LogEntryType = 0
	PreCertEntry LogEntryType = 1
)

// Log represents a public log.
type Log struct {
	Root string
	Key  *ecdsa.PublicKey
}

type RawEntry struct {
	LeafInput []byte `json:"leaf_input"`
	ExtraData []byte `json:"extra_data"`
}

type entries struct {
	Entries []RawEntry `json:"entries"`
}

// Head contains a signed tree head.
type Head struct {
	Size      uint64    `json:"tree_size"`
	Time      time.Time `json:"-"`
	Hash      []byte    `json:"sha256_root_hash"`
	Signature []byte    `json:"tree_head_signature"`
	Timestamp uint64    `json:"timestamp"`
}

// Entry represents a log entry. See
// https://tools.ietf.org/html/draft-laurie-pki-sunlight-12#section-3.1
type Entry struct {
	// Timestamp is the raw time value from the log.
	Timestamp uint64
	// Time is Timestamp converted to a time.Time
	Time              time.Time
	Type              LogEntryType
	X509Cert          []byte
	PreCertIssuerHash []byte
	TBSCert           []byte
	ExtraCerts        [][]byte

	LeafInput []byte
	ExtraData []byte
}

type OperationStatus struct {
	// Start contains the requested starting index of the operation.
	Start uint64
	// Current contains the greatest index that has been processed.
	Current uint64
	// Length contains the total number of entries.
	Length uint64
}

func (status OperationStatus) Percentage() float32 {
	total := float32(status.Length - status.Start)
	done := float32(status.Current - status.Start)

	if total == 0 {
		return 100
	}
	return done * 100 / total
}

func clearLine() {
	fmt.Printf("\x1b[80D\x1b[2K")
}

func displayProgress(statusChan chan OperationStatus, wg *sync.WaitGroup) {
	fmt.Printf("displayProgress fired\n")
	wg.Add(1)

	go func() {
		defer wg.Done()
		symbols := []string{"|", "/", "-", "\\"}
		symbolIndex := 0

		status, ok := <-statusChan
		if !ok {
			return
		}

		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case status, ok = <-statusChan:
				if !ok {
					return
				}
			case <-ticker.C:
				symbolIndex = (symbolIndex + 1) % len(symbols)
			}

			clearLine()
			fmt.Printf("%s %.1f%% (%d of %d)", symbols[symbolIndex], status.Percentage(), status.Current, status.Length)
		}
	}()
}

func (log *Log) GetHead() (*Head, error) {
	// See https://tools.ietf.org/html/rfc6962#section-4.3
	resp, err := http.Get(log.Root + "/ct/v1/get-sth")
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, errors.New("ct: error from server")
	}
	if resp.ContentLength == 0 {
		return nil, errors.New("ct: body unexpectedly missing")
	}
	if resp.ContentLength > 1<<16 {
		return nil, errors.New("ct: body too large")
	}
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	head := new(Head)
	if err := json.Unmarshal(data, &head); err != nil {
		return nil, err
	}

	head.Time = time.Unix(int64(head.Timestamp/1000), int64(head.Timestamp%1000))

	// See https://tools.ietf.org/html/rfc5246#section-4.7
	if len(head.Signature) < 4 {
		return nil, errors.New("ct: signature truncated")
	}
	if head.Signature[0] != hashSHA256 {
		return nil, errors.New("ct: unknown hash function")
	}
	if head.Signature[1] != sigECDSA {
		return nil, errors.New("ct: unknown signature algorithm")
	}

	signatureBytes := head.Signature[4:]
	var sig struct {
		R, S *big.Int
	}

	if signatureBytes, err = asn1.Unmarshal(signatureBytes, &sig); err != nil {
		return nil, errors.New("ct: failed to parse signature: " + err.Error())
	}
	if len(signatureBytes) > 0 {
		return nil, errors.New("ct: trailing garbage after signature")
	}

	// See https://tools.ietf.org/html/rfc6962#section-3.5
	signed := make([]byte, 2+8+8+32)
	x := signed
	x[0] = logVersion
	x[1] = treeHash
	x = x[2:]
	binary.BigEndian.PutUint64(x, head.Timestamp)
	x = x[8:]
	binary.BigEndian.PutUint64(x, head.Size)
	x = x[8:]
	copy(x, head.Hash)

	h := sha256.New()
	h.Write(signed)
	digest := h.Sum(nil)

	if !ecdsa.Verify(log.Key, digest, sig.R, sig.S) {
		return nil, errors.New("ct: signature verification failed")
	}

	return head, nil
}

func (log *Log) GetEntries(start, end uint64) ([]RawEntry, error) {
	resp, err := http.Get(fmt.Sprintf("%s/ct/v1/get-entries?start=%d&end=%d", log.Root, start, end))
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, errors.New("certificatetransparency: error from server")
	}
	if resp.ContentLength == 0 {
		return nil, errors.New("certificatetransparency: body unexpectedly missing")
	}
	if resp.ContentLength > 1<<31 {
		return nil, errors.New("certificatetransparency: body too large")
	}
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var ents entries
	if err := json.Unmarshal(data, &ents); err != nil {
		return nil, err
	}
	return ents.Entries, nil
}

func ParseEntry(leafData, extraData []byte) (*Entry, error) {
	x := leafData
	if len(x) < 2 {
		return nil, errors.New("ct: truncated entry")
	}
	if x[0] != logVersion {
		return nil, errors.New("ct: unknown entry version")
	}
	if x[1] != 0 {
		return nil, errors.New("ct: unknown leaf type")
	}
	x = x[2:]

	entry := new(Entry)
	if len(x) < 8 {
		return nil, errors.New("ct: truncated entry")
	}
	entry.Timestamp = binary.BigEndian.Uint64(x)
	entry.Time = time.Unix(int64(entry.Timestamp/1000), int64(entry.Timestamp%1000))
	x = x[8:]

	if len(x) < 2 {
		return nil, errors.New("ct: truncated entry")
	}
	entry.Type = LogEntryType(x[1])
	x = x[2:]
	switch entry.Type {
	case X509Entry:
		if len(x) < 3 {
			return nil, errors.New("ct: truncated entry")
		}
		l := int(x[0])<<16 |
			int(x[1])<<8 |
			int(x[2])
		x = x[3:]
		if len(x) < l {
			return nil, errors.New("ct: truncated entry")
		}
		entry.X509Cert = x[:l]
		x = x[l:]
	case PreCertEntry:
		if len(x) < 32 {
			return nil, errors.New("ct: truncated entry")
		}
		entry.PreCertIssuerHash = x[:32]
		x = x[32:]
		if len(x) < 2 {
			return nil, errors.New("ct: truncated entry")
		}
		l := int(x[0])<<8 | int(x[1])
		if len(x) < l {
			return nil, errors.New("ct: truncated entry")
		}
		entry.TBSCert = x[:l]
	default:
		return nil, errors.New("ct: unknown entry type")
	}

	x = extraData
	if len(x) > 0 {
		if len(x) < 3 {
			return nil, errors.New("ct: extra data truncated (1)")
		}
		l := int(x[0])<<16 | int(x[1])<<8 | int(x[2])
		x = x[3:]

		if l != len(x) {
			return nil, errors.New("ct: extra data truncated (2)")
		}

		for len(x) > 0 {
			if len(x) < 3 {
				return nil, errors.New("ct: extra data truncated (3)")
			}
			l := int(x[0])<<16 | int(x[1])<<8 | int(x[2])
			x = x[3:]

			if l > len(x) {
				return nil, errors.New("ct: extra data truncated (4)")
			}
			entry.ExtraCerts = append(entry.ExtraCerts, x[:l])
			x = x[l:]
		}
	}

	entry.LeafInput = leafData
	entry.ExtraData = extraData

	return entry, nil
}

// func (log *Log) DownloadRange(out io.Writer, status chan<- OperationStatus, start, upTo uint64) (uint64, error) {
func (log *Log) DownloadRange(status chan<- OperationStatus, start, upTo uint64) (uint64, error) {
	if status != nil {
		defer close(status)
	}
	done := start
	for done < upTo {
		if status != nil {
			status <- OperationStatus{start, done, upTo}
		}
		max := done + 2000
		if max >= upTo {
			max = upTo - 1
		}
		ents, err := log.GetEntries(done, max)
		if err != nil {
			return done, err
		}

		for _, ent := range ents {
			// fmt.Printf("%s", ent.LeafInput)

			e, err := ParseEntry(ent.LeafInput, ent.ExtraData)
			if err != nil {
				return done, err
			}
			// fmt.Printf("Cert Number: %d\n", done)

			cert, err := x509.ParseCertificate(e.X509Cert)
			// fmt.Printf("Serial Number: %x\n", cert.SerialNumber)
			if err != nil {
				certOut, err := os.Create(fmt.Sprintf("%s/%d.pem", *outDir, done))
				if err != nil {
					ex := fmt.Sprintf("Failed to open %d.pem for writing: %s", done, err)
					return done, errors.New(ex)
				}
				pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: e.X509Cert})
				certOut.Close()
				fmt.Printf("Error Parsing Certificate: %d\n", done)
				continue
			}
			// fmt.Printf("%s\n", cert.Subject.CommonName)
			if strings.HasSuffix(cert.Subject.CommonName, *searchTerm) {
				fmt.Printf("CN Match: %s\n", cert.Subject.CommonName)
			}
			for _, san := range cert.DNSNames {
				if strings.HasSuffix(san, *searchTerm) {
					fmt.Printf("DNS Name: %s\n", san)
				}
			}

			done++
		}
	}

	return done, nil
}

func main() {

	// Parse config file
	if err := config.Parse("ct.conf"); err != nil {
		panic(err)
	}

	// Specific to Google Pilot Log.
	// TODO: Need to add support to parse current log JSON
	// from certificate-transparency.org and query all logs
	pilotKeyPEM := `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfahLEimAoz2t01p3uMziiLOl/fHT
DM0YDOhBRuiBARsV4UvxG2LdNgoIGLrtCzWE0J5APC2em4JlvR8EEEFMoA==
-----END PUBLIC KEY-----`

	block, _ := pem.Decode([]byte(pilotKeyPEM))
	key, _ := x509.ParsePKIXPublicKey(block.Bytes)
	pilotKey := key.(*ecdsa.PublicKey)
	pilotLog := &Log{Root: "https://ct.googleapis.com/pilot", Key: pilotKey}

	head, err := pilotLog.GetHead()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error Occurred: %s\n", err)
		os.Exit(1)
	}
	fmt.Printf("%d total entries at %s\n", head.Size, head.Time.Format(time.ANSIC))

	count := uint64(0)

	statusChan := make(chan OperationStatus, 1)
	wg := new(sync.WaitGroup)
	displayProgress(statusChan, wg)
	_, err = pilotLog.DownloadRange(statusChan, count, head.Size)
	wg.Wait()
	clearLine()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while downloading: %s\n", err)
		os.Exit(1)
	}

	// Need to verify hash, etc.
}