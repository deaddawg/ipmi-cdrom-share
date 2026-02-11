package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf16"
)

// SMB1 command codes.
const (
	smbComClose            = 0x04
	smbComEcho             = 0x2B
	smbComReadAndX         = 0x2E
	smbComTransaction2     = 0x32
	smbComTreeDisconnect   = 0x71
	smbComNegotiate        = 0x72
	smbComSessionSetupAndX = 0x73
	smbComLogoffAndX       = 0x74
	smbComTreeConnectAndX  = 0x75
	smbComNtCreateAndX     = 0xA2
)

// NT status codes.
const (
	statusOK               = 0x00000000
	statusNotImplemented   = 0xC0000002
	statusInvalidHandle    = 0xC0000008
	statusObjectNameNotFound = 0xC0000034
)

// SMB flags.
const (
	smbFlagReply      = 0x80
	smbFlagCaseless   = 0x08
	smbFlags2Unicode  = 0x8000
	smbFlags2NTStatus = 0x4000
)

// Capability flags.
const (
	capRawMode    = 0x00000001
	capUnicode    = 0x00000004
	capLargeFiles = 0x00000008
	capNTSMBs     = 0x00000010
	capNTStatus   = 0x00000040
	capLargeReadX = 0x00004000
)

// TRANS2 subcommands.
const (
	trans2FindFirst2    = 0x0001
	trans2QueryFSInfo   = 0x0003
	trans2QueryPathInfo = 0x0005
	trans2QueryFileInfo = 0x0007
)

// Query information levels.
const (
	smbQueryFileBasicInfo    = 0x0101
	smbQueryFileStandardInfo = 0x0102
	smbQueryFileAllInfo      = 0x0107
	smbFindFileBothDirInfo   = 0x0104
)

// Filesystem info levels.
const (
	smbQueryFSSizeInfo = 0x0103
	smbQueryFSDeviceInfo   = 0x0104
	smbQueryFSAttributeInfo = 0x0105
)

// File attributes.
const (
	fileAttrReadOnly  = 0x00000001
	fileAttrDirectory = 0x00000010
	fileAttrNormal    = 0x00000080
)

const maxBufferSize = 65536

// readBufPool recycles buffers for READ_ANDX responses to avoid per-request allocations.
// Each buffer is sized to hold: NetBIOS header(4) + SMB header(32) + WordCount(1) +
// words(24) + ByteCount(2) + pad(1) + max file data.
var readBufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 4+32+1+24+2+1+maxBufferSize)
		return &b
	},
}

// debugStats tracks per-request performance metrics (lock-free via atomics).
type debugStats struct {
	requests  atomic.Int64
	fileBytes atomic.Int64
	handlerNs atomic.Int64 // total handler time (parse to write-complete)
	ioNs      atomic.Int64 // time in ReadAt
	writeNs   atomic.Int64 // time in conn.Write

	// Handler latency histogram.
	latUnder50us  atomic.Int64
	latUnder200us atomic.Int64
	latUnder1ms   atomic.Int64
	latUnder5ms   atomic.Int64
	latOver5ms    atomic.Int64

	// Read size buckets.
	sizeLE2K  atomic.Int64
	sizeLE8K  atomic.Int64
	sizeLE64K atomic.Int64
	sizeGT64K atomic.Int64
}

func (d *debugStats) recordSize(n int) {
	switch {
	case n <= 2048:
		d.sizeLE2K.Add(1)
	case n <= 8192:
		d.sizeLE8K.Add(1)
	case n <= 65536:
		d.sizeLE64K.Add(1)
	default:
		d.sizeGT64K.Add(1)
	}
}

func (d *debugStats) recordLatency(ns int64) {
	switch {
	case ns < 50_000:
		d.latUnder50us.Add(1)
	case ns < 200_000:
		d.latUnder200us.Add(1)
	case ns < 1_000_000:
		d.latUnder1ms.Add(1)
	case ns < 5_000_000:
		d.latUnder5ms.Add(1)
	default:
		d.latOver5ms.Add(1)
	}
}

// runDebugDisplay prints a debug stats line to stderr every 2 seconds.
func (d *debugStats) runDebugDisplay() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	var prevReqs, prevBytes, prevHandlerNs, prevIONs, prevWriteNs int64
	var prevLat [5]int64 // <50us, <200us, <1ms, <5ms, >5ms
	var prevSize [4]int64

	for range ticker.C {
		reqs := d.requests.Load()
		bytes := d.fileBytes.Load()
		handlerNs := d.handlerNs.Load()
		ioNs := d.ioNs.Load()
		writeNs := d.writeNs.Load()
		lat := [5]int64{
			d.latUnder50us.Load(), d.latUnder200us.Load(),
			d.latUnder1ms.Load(), d.latUnder5ms.Load(), d.latOver5ms.Load(),
		}
		size := [4]int64{
			d.sizeLE2K.Load(), d.sizeLE8K.Load(),
			d.sizeLE64K.Load(), d.sizeGT64K.Load(),
		}

		dReqs := reqs - prevReqs
		dBytes := bytes - prevBytes
		dHandlerNs := handlerNs - prevHandlerNs
		dIONs := ioNs - prevIONs
		dWriteNs := writeNs - prevWriteNs
		var dLat [5]int64
		for i := range dLat {
			dLat[i] = lat[i] - prevLat[i]
		}
		var dSize [4]int64
		for i := range dSize {
			dSize[i] = size[i] - prevSize[i]
		}

		prevReqs = reqs
		prevBytes = bytes
		prevHandlerNs = handlerNs
		prevIONs = ioNs
		prevWriteNs = writeNs
		prevLat = lat
		prevSize = size

		if dReqs == 0 {
			continue
		}

		reqsPerSec := float64(dReqs) / 2.0
		mbPerSec := float64(dBytes) / 2.0 / float64(1<<20)
		avgHandler := time.Duration(dHandlerNs / dReqs)
		avgIO := time.Duration(dIONs / dReqs)
		avgWrite := time.Duration(dWriteNs / dReqs)
		avgOverhead := avgHandler - avgIO - avgWrite
		avgSize := float64(dBytes) / float64(dReqs)

		// Time between requests (inverse of req/s) vs handler time = idle%.
		avgGapMs := 1000.0 / reqsPerSec
		handlerMs := float64(avgHandler.Microseconds()) / 1000.0
		idlePct := (1.0 - handlerMs/avgGapMs) * 100
		if idlePct < 0 {
			idlePct = 0
		}

		// Latency distribution as percentages.
		latPct := func(i int) float64 {
			return float64(dLat[i]) / float64(dReqs) * 100
		}

		log.Printf("[debug] %.0f req/s  %.1f MB/s  avg=%s  idle=%.0f%% | handler=%v io=%v write=%v overhead=%v | <50us:%.0f%% <200us:%.0f%% <1ms:%.0f%% <5ms:%.0f%% >5ms:%.0f%%",
			reqsPerSec, mbPerSec, formatSize(int64(avgSize)), idlePct,
			avgHandler.Round(time.Microsecond), avgIO.Round(time.Microsecond),
			avgWrite.Round(time.Microsecond), avgOverhead.Round(time.Microsecond),
			latPct(0), latPct(1), latPct(2), latPct(3), latPct(4))
	}
}

// smbHeader is the 32-byte SMB1 header.
type smbHeader struct {
	command  uint8
	status   uint32
	flags    uint8
	flags2   uint16
	pidHigh  uint16
	security [8]byte
	tid      uint16
	pidLow   uint16
	uid      uint16
	mid      uint16
}

// smbPacket is a parsed SMB1 packet.
type smbPacket struct {
	header smbHeader
	words  []byte // parameter words (WordCount * 2 bytes)
	data   []byte // data section (ByteCount bytes)
}

// session holds per-connection state.
type session struct {
	file     *os.File
	fileSize int64
	fileName string
	uid      uint16
	tid      uint16
	fid      uint16
	unicode  bool
	progress *progress
	debug    *debugStats // nil unless --debug
}

// readEvent is sent from handleRead to the progress display goroutine.
type readEvent struct {
	offset int64
	size   int
}

// speedSample records bytes read at a point in time for throughput calculation.
type speedSample struct {
	when  time.Time
	bytes int64
}

// progress tracks transfer state and renders a live terminal display.
type progress struct {
	fileSize  int64
	fileName  string
	events    chan readEvent
	done      chan struct{}
	debugMode bool // when true, use log lines instead of \r overwriting

	mu     sync.Mutex
	client string // last active client IP
}

// formatSize returns a human-readable size string.
func formatSize(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// formatCount returns an integer with comma separators (e.g. 1,204).
func formatCount(n int64) string {
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	var result []byte
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			result = append(result, ',')
		}
		result = append(result, byte(c))
	}
	return string(result)
}

// formatSpeed returns a human-readable speed string.
func formatSpeed(bytesPerSec float64) string {
	switch {
	case bytesPerSec >= float64(1<<30):
		return fmt.Sprintf("%.1f GB/s", bytesPerSec/float64(1<<30))
	case bytesPerSec >= float64(1<<20):
		return fmt.Sprintf("%.1f MB/s", bytesPerSec/float64(1<<20))
	case bytesPerSec >= float64(1<<10):
		return fmt.Sprintf("%.1f KB/s", bytesPerSec/float64(1<<10))
	default:
		return fmt.Sprintf("%.0f B/s", bytesPerSec)
	}
}

// run is the display goroutine. It renders a stats line to stderr.
// In normal mode: overwrites in place every 250ms.
// In debug mode: prints a log line every 2s, suppressed when idle.
func (p *progress) run() {
	interval := 250 * time.Millisecond
	if p.debugMode {
		interval = 2 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var (
		speedBuf   []speedSample
		totalReads int64
		totalBytes int64
		started    bool
	)

	for {
		select {
		case <-p.done:
			if started && !p.debugMode {
				fmt.Fprintf(os.Stderr, "\r\033[K")
			}
			return
		case <-ticker.C:
		}

		// Drain all pending events.
		var tickBytes int64
		var tickReads int64
		for {
			select {
			case ev := <-p.events:
				tickBytes += int64(ev.size)
				tickReads++
			default:
				goto drained
			}
		}
	drained:

		totalBytes += tickBytes
		totalReads += tickReads

		if tickBytes == 0 && !started {
			continue
		}

		now := time.Now()
		if tickBytes > 0 {
			started = true
			speedBuf = append(speedBuf, speedSample{when: now, bytes: tickBytes})
		}

		// Expire old speed samples (keep 2 seconds).
		cutoff := now.Add(-2 * time.Second)
		for len(speedBuf) > 0 && speedBuf[0].when.Before(cutoff) {
			speedBuf = speedBuf[1:]
		}

		// Calculate speed.
		var totalSpeedBytes int64
		for _, s := range speedBuf {
			totalSpeedBytes += s.bytes
		}
		var speed float64
		if len(speedBuf) > 0 {
			elapsed := now.Sub(speedBuf[0].when).Seconds()
			if elapsed < 0.25 {
				elapsed = 0.25
			}
			speed = float64(totalSpeedBytes) / elapsed
		}

		p.mu.Lock()
		client := p.client
		p.mu.Unlock()

		if p.debugMode {
			// In debug mode, skip printing when idle (speed dropped to 0).
			if speed == 0 && tickBytes == 0 {
				continue
			}
			log.Printf("[stats] %s  %s  %s reads  %s transferred",
				client, formatSpeed(speed), formatCount(totalReads), formatSize(totalBytes))
		} else {
			fmt.Fprintf(os.Stderr, "\r\033[K %s  %s  %s reads  %s transferred",
				client, formatSpeed(speed), formatCount(totalReads), formatSize(totalBytes))
		}
	}
}

func main() {
	// Parse --debug flag from args.
	var debug bool
	var args []string
	for _, a := range os.Args[1:] {
		if a == "--debug" {
			debug = true
		} else {
			args = append(args, a)
		}
	}

	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s [--debug] <iso-path> [listen-addr]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Default listen address: :445\n")
		os.Exit(1)
	}

	isoPath := args[0]
	listenAddr := ":445"
	if len(args) >= 2 {
		listenAddr = args[1]
	}

	info, err := os.Stat(isoPath)
	if err != nil {
		log.Fatalf("Cannot access %s: %v", isoPath, err)
	}
	if info.IsDir() {
		log.Fatalf("%s is a directory, not a file", isoPath)
	}

	absPath, err := filepath.Abs(isoPath)
	if err != nil {
		log.Fatalf("Cannot resolve path: %v", err)
	}

	log.Printf("Serving %s (%s) on smb://%s/share/%s",
		filepath.Base(absPath), formatSize(info.Size()), listenAddr, filepath.Base(absPath))

	var dbg *debugStats
	if debug {
		dbg = &debugStats{}
		go dbg.runDebugDisplay()
		log.Printf("[debug] Performance tracing enabled (2s intervals)")
	}

	prog := &progress{
		fileSize:  info.Size(),
		fileName:  filepath.Base(absPath),
		events:    make(chan readEvent, 4096),
		done:      make(chan struct{}),
		debugMode: debug,
	}
	go prog.run()

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		go handleConnection(conn, absPath, info.Size(), prog, dbg)
	}
}

func handleConnection(conn net.Conn, isoPath string, fileSize int64, prog *progress, dbg *debugStats) {
	defer conn.Close()

	// Disable Nagle's algorithm to avoid coalescing small writes.
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}

	remote := conn.RemoteAddr().String()

	// Extract just the IP (strip port).
	clientIP := remote
	if host, _, err := net.SplitHostPort(remote); err == nil {
		clientIP = host
	}

	log.Printf("[%s] Connected", remote)
	defer log.Printf("[%s] Disconnected", remote)

	prog.mu.Lock()
	prog.client = clientIP
	prog.mu.Unlock()

	f, err := os.Open(isoPath)
	if err != nil {
		log.Printf("[%s] Failed to open ISO: %v", remote, err)
		return
	}
	defer f.Close()

	sess := &session{
		file:     f,
		fileSize: fileSize,
		fileName: filepath.Base(isoPath),
		uid:      1,
		tid:      1,
		fid:      0x4000,
		progress: prog,
		debug:    dbg,
	}

	for {
		raw, msgType, err := readNetBIOSPacket(conn)
		if err != nil {
			if err != io.EOF {
				log.Printf("[%s] Read error: %v", remote, err)
			}
			return
		}

		// Handle NetBIOS session request (port 139 compat).
		if msgType == 0x81 {
			writeNetBIOSPacket(conn, 0x82, nil)
			continue
		}
		if msgType != 0x00 {
			continue
		}

		req, err := parseSMBPacket(raw)
		if err != nil {
			log.Printf("[%s] Parse error: %v", remote, err)
			return
		}

		if req.header.flags2&smbFlags2Unicode != 0 {
			sess.unicode = true
		}

		// Fast path for READ_ANDX: build response in a single pooled buffer.
		if req.header.command == smbComReadAndX {
			var t0 time.Time
			if sess.debug != nil {
				t0 = time.Now()
			}
			wire, poolBuf, ioNs := handleReadFast(sess, req)
			if wire != nil {
				var writeStart time.Time
				if sess.debug != nil {
					writeStart = time.Now()
				}
				_, err := conn.Write(wire)
				if sess.debug != nil {
					writeNs := time.Since(writeStart).Nanoseconds()
					totalNs := time.Since(t0).Nanoseconds()
					dataLen := len(wire) - 64 // subtract headers
					sess.debug.requests.Add(1)
					sess.debug.fileBytes.Add(int64(dataLen))
					sess.debug.handlerNs.Add(totalNs)
					sess.debug.ioNs.Add(ioNs)
					sess.debug.writeNs.Add(writeNs)
					sess.debug.recordLatency(totalNs)
					sess.debug.recordSize(dataLen)
				}
				readBufPool.Put(poolBuf)
				if err != nil {
					log.Printf("[%s] Write error: %v", remote, err)
					return
				}
				continue
			}
			// Fall through to normal dispatch for error responses.
		}

		resp := dispatchCommand(sess, req)
		if resp == nil {
			continue
		}

		respRaw := buildSMBResponse(resp)
		if err := writeNetBIOSPacket(conn, 0x00, respRaw); err != nil {
			log.Printf("[%s] Write error: %v", remote, err)
			return
		}
	}
}

// --- NetBIOS session service (4-byte header: type + 24-bit length) ---

func readNetBIOSPacket(r io.Reader) ([]byte, byte, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, 0, err
	}
	msgType := hdr[0]
	length := int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
	if length == 0 {
		return nil, msgType, nil
	}
	if length > 0x100000 {
		return nil, 0, fmt.Errorf("NetBIOS length too large: %d", length)
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, 0, err
	}
	return data, msgType, nil
}

func writeNetBIOSPacket(w io.Writer, msgType byte, data []byte) error {
	length := len(data)
	// Combine header + data into a single write to avoid multiple TCP segments.
	buf := make([]byte, 4+length)
	buf[0] = msgType
	buf[1] = byte(length >> 16)
	buf[2] = byte(length >> 8)
	buf[3] = byte(length)
	copy(buf[4:], data)
	_, err := w.Write(buf)
	return err
}

// --- SMB packet parse/build ---

func parseSMBPacket(data []byte) (*smbPacket, error) {
	if len(data) < 35 {
		return nil, fmt.Errorf("packet too short: %d bytes", len(data))
	}
	if data[0] != 0xFF || data[1] != 'S' || data[2] != 'M' || data[3] != 'B' {
		return nil, fmt.Errorf("invalid SMB magic")
	}

	pkt := &smbPacket{}
	pkt.header.command = data[4]
	pkt.header.status = binary.LittleEndian.Uint32(data[5:9])
	pkt.header.flags = data[9]
	pkt.header.flags2 = binary.LittleEndian.Uint16(data[10:12])
	pkt.header.pidHigh = binary.LittleEndian.Uint16(data[12:14])
	copy(pkt.header.security[:], data[14:22])
	pkt.header.tid = binary.LittleEndian.Uint16(data[24:26])
	pkt.header.pidLow = binary.LittleEndian.Uint16(data[26:28])
	pkt.header.uid = binary.LittleEndian.Uint16(data[28:30])
	pkt.header.mid = binary.LittleEndian.Uint16(data[30:32])

	wordCount := int(data[32])
	wordsEnd := 33 + wordCount*2
	if len(data) < wordsEnd+2 {
		return nil, fmt.Errorf("packet truncated at words")
	}
	pkt.words = data[33:wordsEnd]

	byteCount := int(binary.LittleEndian.Uint16(data[wordsEnd : wordsEnd+2]))
	dataStart := wordsEnd + 2
	dataEnd := dataStart + byteCount
	if dataEnd > len(data) {
		dataEnd = len(data)
	}
	if dataStart <= len(data) {
		pkt.data = data[dataStart:dataEnd]
	}

	return pkt, nil
}

func buildSMBResponse(pkt *smbPacket) []byte {
	if pkt.words == nil {
		pkt.words = []byte{}
	}
	if pkt.data == nil {
		pkt.data = []byte{}
	}

	wordCount := len(pkt.words) / 2
	buf := make([]byte, 32+1+len(pkt.words)+2+len(pkt.data))

	buf[0] = 0xFF
	buf[1] = 'S'
	buf[2] = 'M'
	buf[3] = 'B'
	buf[4] = pkt.header.command
	binary.LittleEndian.PutUint32(buf[5:9], pkt.header.status)
	buf[9] = pkt.header.flags
	binary.LittleEndian.PutUint16(buf[10:12], pkt.header.flags2)
	binary.LittleEndian.PutUint16(buf[12:14], pkt.header.pidHigh)
	copy(buf[14:22], pkt.header.security[:])
	binary.LittleEndian.PutUint16(buf[24:26], pkt.header.tid)
	binary.LittleEndian.PutUint16(buf[26:28], pkt.header.pidLow)
	binary.LittleEndian.PutUint16(buf[28:30], pkt.header.uid)
	binary.LittleEndian.PutUint16(buf[30:32], pkt.header.mid)

	buf[32] = byte(wordCount)
	copy(buf[33:], pkt.words)
	binary.LittleEndian.PutUint16(buf[33+len(pkt.words):], uint16(len(pkt.data)))
	copy(buf[35+len(pkt.words):], pkt.data)

	return buf
}

// --- Command dispatch ---

func dispatchCommand(sess *session, req *smbPacket) *smbPacket {
	switch req.header.command {
	case smbComNegotiate:
		return handleNegotiate(sess, req)
	case smbComSessionSetupAndX:
		return handleSessionSetup(sess, req)
	case smbComTreeConnectAndX:
		return handleTreeConnect(sess, req)
	case smbComNtCreateAndX:
		return handleNtCreate(sess, req)
	case smbComReadAndX:
		return handleRead(sess, req)
	case smbComClose:
		return handleClose(sess, req)
	case smbComTransaction2:
		return handleTrans2(sess, req)
	case smbComTreeDisconnect:
		return handleTreeDisconnect(sess, req)
	case smbComLogoffAndX:
		return handleLogoff(sess, req)
	case smbComEcho:
		return handleEcho(sess, req)
	default:
		log.Printf("Unhandled command: 0x%02X", req.header.command)
		return errorResponse(req, statusNotImplemented)
	}
}

func newResponse(req *smbPacket) *smbPacket {
	resp := &smbPacket{}
	resp.header = req.header
	resp.header.flags = smbFlagReply | (req.header.flags & smbFlagCaseless)
	resp.header.flags2 = req.header.flags2 & (smbFlags2Unicode | smbFlags2NTStatus)
	resp.header.status = statusOK
	return resp
}

func errorResponse(req *smbPacket, status uint32) *smbPacket {
	resp := newResponse(req)
	resp.header.status = status
	return resp
}

// --- NEGOTIATE (0x72) ---

func handleNegotiate(sess *session, req *smbPacket) *smbPacket {
	// Find "NT LM 0.12" dialect.
	dialectIndex := uint16(0xFFFF)
	idx := uint16(0)
	pos := 0
	for pos < len(req.data) {
		if req.data[pos] != 0x02 {
			break
		}
		pos++
		end := pos
		for end < len(req.data) && req.data[end] != 0x00 {
			end++
		}
		if string(req.data[pos:end]) == "NT LM 0.12" {
			dialectIndex = idx
		}
		idx++
		pos = end + 1
	}

	if dialectIndex == 0xFFFF {
		log.Printf("Warning: NT LM 0.12 dialect not found in client request")
	}

	resp := newResponse(req)
	resp.header.flags2 = smbFlags2Unicode | smbFlags2NTStatus

	// WordCount = 17 (34 bytes).
	words := make([]byte, 34)
	binary.LittleEndian.PutUint16(words[0:2], dialectIndex)
	words[2] = 0x00 // SecurityMode: share-level, no passwords
	binary.LittleEndian.PutUint16(words[3:5], 50)
	binary.LittleEndian.PutUint16(words[5:7], 1)
	binary.LittleEndian.PutUint32(words[7:11], maxBufferSize)
	binary.LittleEndian.PutUint32(words[11:15], maxBufferSize)
	binary.LittleEndian.PutUint32(words[15:19], 0) // SessionKey
	caps := uint32(capRawMode | capUnicode | capLargeFiles | capNTSMBs | capNTStatus | capLargeReadX)
	binary.LittleEndian.PutUint32(words[19:23], caps)
	binary.LittleEndian.PutUint64(words[23:31], timeToFiletime(time.Now()))
	binary.LittleEndian.PutUint16(words[31:33], 0) // ServerTimeZone (UTC)
	words[33] = 0                                   // ChallengeLength
	resp.words = words

	// Data: pad for Unicode alignment + empty domain + empty server.
	// Offset to data start: 32+1+34+2 = 69 (odd), need pad byte.
	resp.data = []byte{0x00, 0x00, 0x00, 0x00, 0x00} // pad + 2 Unicode nulls

	sess.unicode = true
	return resp
}

// --- SESSION_SETUP_ANDX (0x73) ---

func handleSessionSetup(sess *session, req *smbPacket) *smbPacket {
	resp := newResponse(req)
	resp.header.uid = sess.uid

	// WordCount = 3 (6 bytes).
	words := make([]byte, 6)
	words[0] = 0xFF // AndXCommand: none
	binary.LittleEndian.PutUint16(words[4:6], 0x0001) // Action: guest
	resp.words = words

	if sess.unicode {
		// Offset to data: 32+1+6+2=41 (odd), need pad.
		var data []byte
		data = append(data, 0x00) // pad
		data = append(data, encodeUTF16LE("Unix")...)
		data = append(data, 0x00, 0x00)
		data = append(data, encodeUTF16LE("IPMI CD Share")...)
		data = append(data, 0x00, 0x00)
		data = append(data, encodeUTF16LE("WORKGROUP")...)
		data = append(data, 0x00, 0x00)
		resp.data = data
	} else {
		resp.data = []byte("Unix\x00IPMI CD Share\x00WORKGROUP\x00")
	}

	return resp
}

// --- TREE_CONNECT_ANDX (0x75) ---

func handleTreeConnect(sess *session, req *smbPacket) *smbPacket {
	resp := newResponse(req)
	resp.header.tid = sess.tid

	// WordCount = 3 (6 bytes).
	words := make([]byte, 6)
	words[0] = 0xFF // AndXCommand: none
	resp.words = words

	// Service type "A:" (disk share) + native filesystem.
	resp.data = []byte("A:\x00FAT\x00")
	return resp
}

// --- NT_CREATE_ANDX (0xA2) ---

func handleNtCreate(sess *session, req *smbPacket) *smbPacket {
	fileName := extractCreateFileName(sess, req)
	log.Printf("NT_CREATE: %q", fileName)

	// Root directory request.
	if fileName == "" {
		return ntCreateDirResponse(sess, req)
	}

	// Match against our served file.
	if !strings.EqualFold(fileName, sess.fileName) {
		return errorResponse(req, statusObjectNameNotFound)
	}

	resp := newResponse(req)
	resp.header.tid = sess.tid
	now := timeToFiletime(time.Now())

	// WordCount = 34 (68 bytes).
	words := make([]byte, 68)
	words[0] = 0xFF // AndXCommand: none
	binary.LittleEndian.PutUint16(words[5:7], sess.fid)
	binary.LittleEndian.PutUint32(words[7:11], 1) // CreateAction: opened
	binary.LittleEndian.PutUint64(words[11:19], now)
	binary.LittleEndian.PutUint64(words[19:27], now)
	binary.LittleEndian.PutUint64(words[27:35], now)
	binary.LittleEndian.PutUint64(words[35:43], now)
	binary.LittleEndian.PutUint32(words[43:47], fileAttrReadOnly)
	binary.LittleEndian.PutUint64(words[47:55], uint64(sess.fileSize))
	binary.LittleEndian.PutUint64(words[55:63], uint64(sess.fileSize))
	// FileType(2)=0, DeviceState(2)=0, Directory(1)=0 are already zero.
	resp.words = words
	return resp
}

func ntCreateDirResponse(sess *session, req *smbPacket) *smbPacket {
	resp := newResponse(req)
	resp.header.tid = sess.tid
	now := timeToFiletime(time.Now())

	words := make([]byte, 68)
	words[0] = 0xFF
	binary.LittleEndian.PutUint16(words[5:7], 0x4001) // FID for directory
	binary.LittleEndian.PutUint32(words[7:11], 1)
	binary.LittleEndian.PutUint64(words[11:19], now)
	binary.LittleEndian.PutUint64(words[19:27], now)
	binary.LittleEndian.PutUint64(words[27:35], now)
	binary.LittleEndian.PutUint64(words[35:43], now)
	binary.LittleEndian.PutUint32(words[43:47], fileAttrDirectory)
	words[67] = 1 // Directory = true
	resp.words = words
	return resp
}

func extractCreateFileName(sess *session, req *smbPacket) string {
	if len(req.words) < 48 {
		return ""
	}
	nameLen := int(binary.LittleEndian.Uint16(req.words[5:7]))
	if nameLen == 0 || len(req.data) == 0 {
		return ""
	}

	nameData := req.data
	// Skip Unicode alignment pad byte.
	if sess.unicode && len(nameData) > 0 && nameData[0] == 0 {
		nameData = nameData[1:]
	}

	var name string
	if sess.unicode {
		if len(nameData) >= nameLen {
			name = decodeUTF16LE(nameData[:nameLen])
		} else {
			name = decodeUTF16LE(nameData)
		}
	} else {
		if len(nameData) >= nameLen {
			name = string(nameData[:nameLen])
		} else {
			name = string(nameData)
		}
	}

	name = strings.TrimPrefix(name, "\\")
	name = strings.TrimPrefix(name, "/")
	name = strings.TrimRight(name, "\x00")
	return name
}

// --- READ_ANDX (0x2E) ---

// handleReadFast builds the complete wire-format response (NetBIOS header + SMB + data)
// in a single pooled buffer with zero intermediate allocations. It returns the raw bytes
// to write and the pool buffer to recycle, or nil if the request should fall back to the
// normal path (e.g. for error responses).
func handleReadFast(sess *session, req *smbPacket) (wire []byte, poolBuf *[]byte, ioNs int64) {
	if len(req.words) < 20 {
		return nil, nil, 0
	}

	fid := binary.LittleEndian.Uint16(req.words[4:6])
	if fid != sess.fid {
		return nil, nil, 0
	}

	offsetLow := binary.LittleEndian.Uint32(req.words[6:10])
	maxCount := int(binary.LittleEndian.Uint16(req.words[10:12]))
	offset := int64(offsetLow)

	// 64-bit offset support (WordCount >= 12).
	if len(req.words) >= 24 {
		offsetHigh := binary.LittleEndian.Uint32(req.words[20:24])
		offset = int64(offsetHigh)<<32 | int64(offsetLow)
	}

	// Clamp read size.
	maxData := maxBufferSize - 60 // leave room for headers
	if maxCount > maxData {
		maxCount = maxData
	}
	if offset >= sess.fileSize {
		maxCount = 0
	} else if offset+int64(maxCount) > sess.fileSize {
		maxCount = int(sess.fileSize - offset)
	}

	// Get a pooled buffer. Layout:
	//   [0:4]     NetBIOS header
	//   [4:36]    SMB header (32 bytes)
	//   [36]      WordCount = 12
	//   [37:61]   Words (24 bytes)
	//   [61:63]   ByteCount
	//   [63]      Pad byte
	//   [64:]     File data
	const hdrSize = 4 + 32 + 1 + 24 + 2 + 1 // = 64
	bp := readBufPool.Get().(*[]byte)
	buf := *bp

	// Read file data directly into the final position.
	n := 0
	if maxCount > 0 {
		var ioStart time.Time
		if sess.debug != nil {
			ioStart = time.Now()
		}
		var err error
		n, err = sess.file.ReadAt(buf[hdrSize:hdrSize+maxCount], offset)
		if sess.debug != nil {
			ioNs = time.Since(ioStart).Nanoseconds()
		}
		if err != nil && err != io.EOF {
			log.Printf("ReadAt error at offset %d: %v", offset, err)
			n = 0
		}
		if n > 0 && sess.progress != nil {
			select {
			case sess.progress.events <- readEvent{offset: offset, size: n}:
			default:
			}
		}
	}

	// Total SMB payload size (everything after NetBIOS header).
	smbLen := 32 + 1 + 24 + 2 + 1 + n // = 60 + n
	totalLen := 4 + smbLen

	// NetBIOS header.
	buf[0] = 0x00
	buf[1] = byte(smbLen >> 16)
	buf[2] = byte(smbLen >> 8)
	buf[3] = byte(smbLen)

	// SMB header at offset 4.
	smb := buf[4:]
	smb[0] = 0xFF
	smb[1] = 'S'
	smb[2] = 'M'
	smb[3] = 'B'
	smb[4] = req.header.command
	binary.LittleEndian.PutUint32(smb[5:9], statusOK)
	smb[9] = smbFlagReply | (req.header.flags & smbFlagCaseless)
	binary.LittleEndian.PutUint16(smb[10:12], req.header.flags2&(smbFlags2Unicode|smbFlags2NTStatus))
	binary.LittleEndian.PutUint16(smb[12:14], req.header.pidHigh)
	copy(smb[14:22], req.header.security[:])
	smb[22] = 0
	smb[23] = 0
	binary.LittleEndian.PutUint16(smb[24:26], req.header.tid)
	binary.LittleEndian.PutUint16(smb[26:28], req.header.pidLow)
	binary.LittleEndian.PutUint16(smb[28:30], req.header.uid)
	binary.LittleEndian.PutUint16(smb[30:32], req.header.mid)

	// WordCount = 12.
	smb[32] = 12

	// Words at smb[33:57] (24 bytes).
	words := smb[33:57]
	// Zero out words region.
	for i := range words {
		words[i] = 0
	}
	words[0] = 0xFF // AndXCommand: none
	binary.LittleEndian.PutUint16(words[4:6], 0xFFFF)     // Remaining
	binary.LittleEndian.PutUint16(words[10:12], uint16(n)) // DataLength
	binary.LittleEndian.PutUint16(words[12:14], 60)        // DataOffset

	// ByteCount = 1 (pad) + n.
	binary.LittleEndian.PutUint16(smb[57:59], uint16(1+n))

	// Pad byte.
	smb[59] = 0x00

	// File data is already at smb[60:60+n] from ReadAt above.

	return buf[:totalLen], bp, ioNs
}

// handleRead is the fallback for error cases.
func handleRead(sess *session, req *smbPacket) *smbPacket {
	if len(req.words) < 20 {
		return errorResponse(req, statusInvalidHandle)
	}
	fid := binary.LittleEndian.Uint16(req.words[4:6])
	if fid != sess.fid {
		return errorResponse(req, statusInvalidHandle)
	}
	return errorResponse(req, statusInvalidHandle)
}

// --- CLOSE (0x04) ---

func handleClose(sess *session, req *smbPacket) *smbPacket {
	return newResponse(req)
}

// --- TRANSACTION2 (0x32) ---

func handleTrans2(sess *session, req *smbPacket) *smbPacket {
	if len(req.words) < 28 {
		return errorResponse(req, statusNotImplemented)
	}

	setupCount := int(req.words[26])
	if setupCount < 1 || len(req.words) < 28+setupCount*2 {
		return errorResponse(req, statusNotImplemented)
	}
	subcommand := binary.LittleEndian.Uint16(req.words[28:30])

	paramCount := int(binary.LittleEndian.Uint16(req.words[18:20]))
	paramOffset := int(binary.LittleEndian.Uint16(req.words[20:22]))

	// Convert paramOffset (from SMB header start) to data section offset.
	headerLen := 32 + 1 + len(req.words) + 2
	transParamStart := paramOffset - headerLen
	var transParams []byte
	if transParamStart >= 0 && transParamStart+paramCount <= len(req.data) {
		transParams = req.data[transParamStart : transParamStart+paramCount]
	} else if transParamStart >= 0 && transParamStart < len(req.data) {
		transParams = req.data[transParamStart:]
	}

	switch subcommand {
	case trans2FindFirst2:
		return handleFindFirst2(sess, req, transParams)
	case trans2QueryFSInfo:
		return handleQueryFSInfo(sess, req, transParams)
	case trans2QueryPathInfo:
		return handleQueryPathInfo(sess, req, transParams)
	case trans2QueryFileInfo:
		return handleQueryFileInfo(sess, req, transParams)
	default:
		log.Printf("Unhandled TRANS2 subcommand: 0x%04X", subcommand)
		return errorResponse(req, statusNotImplemented)
	}
}

func handleQueryFSInfo(sess *session, req *smbPacket, transParams []byte) *smbPacket {
	if len(transParams) < 2 {
		return errorResponse(req, statusNotImplemented)
	}
	infoLevel := binary.LittleEndian.Uint16(transParams[0:2])
	log.Printf("QUERY_FS_INFO level=0x%04X", infoLevel)

	var infoData []byte

	switch infoLevel {
	case smbQueryFSSizeInfo:
		// TotalUnits(8) + FreeUnits(8) + SectorsPerUnit(4) + BytesPerSector(4)
		infoData = make([]byte, 24)
		totalUnits := uint64(sess.fileSize) / 4096
		binary.LittleEndian.PutUint64(infoData[0:8], totalUnits)
		// FreeUnits = 0 (read-only)
		binary.LittleEndian.PutUint32(infoData[16:20], 8) // sectors per unit
		binary.LittleEndian.PutUint32(infoData[20:24], 512) // bytes per sector

	case smbQueryFSDeviceInfo:
		// DeviceType(4) + Characteristics(4)
		infoData = make([]byte, 8)
		binary.LittleEndian.PutUint32(infoData[0:4], 0x00000007) // FILE_DEVICE_DISK
		binary.LittleEndian.PutUint32(infoData[4:8], 0x00000020) // READ_ONLY_DEVICE

	case smbQueryFSAttributeInfo:
		// Attributes(4) + MaxNameLen(4) + FSNameLen(4) + FSName
		fsName := encodeUTF16LE("FAT")
		infoData = make([]byte, 12+len(fsName))
		binary.LittleEndian.PutUint32(infoData[0:4], 0x0001) // CASE_SENSITIVE_SEARCH
		binary.LittleEndian.PutUint32(infoData[4:8], 255)
		binary.LittleEndian.PutUint32(infoData[8:12], uint32(len(fsName)))
		copy(infoData[12:], fsName)

	default:
		log.Printf("Unhandled FS info level: 0x%04X", infoLevel)
		return errorResponse(req, statusNotImplemented)
	}

	return buildTrans2Response(req, nil, infoData)
}

func handleQueryPathInfo(sess *session, req *smbPacket, transParams []byte) *smbPacket {
	if len(transParams) < 6 {
		return errorResponse(req, statusNotImplemented)
	}

	infoLevel := binary.LittleEndian.Uint16(transParams[0:2])
	pathBytes := transParams[6:]

	var path string
	if sess.unicode {
		path = decodeUTF16LE(pathBytes)
	} else {
		path = strings.TrimRight(string(pathBytes), "\x00")
	}
	path = strings.TrimPrefix(path, "\\")

	log.Printf("QUERY_PATH_INFO level=0x%04X path=%q", infoLevel, path)

	if path == "" {
		return buildFileInfoResponse(req, infoLevel, true, 0)
	}
	if strings.EqualFold(path, sess.fileName) {
		return buildFileInfoResponse(req, infoLevel, false, sess.fileSize)
	}
	return errorResponse(req, statusObjectNameNotFound)
}

func handleQueryFileInfo(sess *session, req *smbPacket, transParams []byte) *smbPacket {
	if len(transParams) < 4 {
		return errorResponse(req, statusNotImplemented)
	}

	fid := binary.LittleEndian.Uint16(transParams[0:2])
	infoLevel := binary.LittleEndian.Uint16(transParams[2:4])

	log.Printf("QUERY_FILE_INFO fid=0x%04X level=0x%04X", fid, infoLevel)

	if fid == sess.fid {
		return buildFileInfoResponse(req, infoLevel, false, sess.fileSize)
	}
	return buildFileInfoResponse(req, infoLevel, true, 0)
}

func buildFileInfoResponse(req *smbPacket, infoLevel uint16, isDir bool, size int64) *smbPacket {
	now := timeToFiletime(time.Now())
	attr := uint32(fileAttrReadOnly)
	if isDir {
		attr = fileAttrDirectory
	}

	var infoData []byte

	switch infoLevel {
	case smbQueryFileBasicInfo:
		infoData = make([]byte, 40)
		binary.LittleEndian.PutUint64(infoData[0:8], now)
		binary.LittleEndian.PutUint64(infoData[8:16], now)
		binary.LittleEndian.PutUint64(infoData[16:24], now)
		binary.LittleEndian.PutUint64(infoData[24:32], now)
		binary.LittleEndian.PutUint32(infoData[32:36], attr)

	case smbQueryFileStandardInfo:
		infoData = make([]byte, 22)
		binary.LittleEndian.PutUint64(infoData[0:8], uint64(size))
		binary.LittleEndian.PutUint64(infoData[8:16], uint64(size))
		binary.LittleEndian.PutUint32(infoData[16:20], 1)
		if isDir {
			infoData[21] = 1
		}

	case smbQueryFileAllInfo:
		infoData = make([]byte, 72)
		binary.LittleEndian.PutUint64(infoData[0:8], now)
		binary.LittleEndian.PutUint64(infoData[8:16], now)
		binary.LittleEndian.PutUint64(infoData[16:24], now)
		binary.LittleEndian.PutUint64(infoData[24:32], now)
		binary.LittleEndian.PutUint32(infoData[32:36], attr)
		// Pad at 36:40
		binary.LittleEndian.PutUint64(infoData[40:48], uint64(size))
		binary.LittleEndian.PutUint64(infoData[48:56], uint64(size))
		binary.LittleEndian.PutUint32(infoData[56:60], 1) // NumberOfLinks
		if isDir {
			infoData[61] = 1
		}
		// EaSize(4) at 64, FileNameLength(4) at 68 = 0

	default:
		return errorResponse(req, statusNotImplemented)
	}

	return buildTrans2Response(req, nil, infoData)
}

func handleFindFirst2(sess *session, req *smbPacket, transParams []byte) *smbPacket {
	if len(transParams) < 12 {
		return errorResponse(req, statusNotImplemented)
	}

	infoLevel := binary.LittleEndian.Uint16(transParams[6:8])
	patternBytes := transParams[12:]

	var pattern string
	if sess.unicode {
		pattern = decodeUTF16LE(patternBytes)
	} else {
		pattern = strings.TrimRight(string(patternBytes), "\x00")
	}
	log.Printf("FIND_FIRST2 level=0x%04X pattern=%q", infoLevel, pattern)

	now := timeToFiletime(time.Now())
	var nameBytes []byte
	if sess.unicode {
		nameBytes = encodeUTF16LE(sess.fileName)
	} else {
		nameBytes = []byte(sess.fileName)
	}

	var entryData []byte

	switch infoLevel {
	case smbFindFileBothDirInfo:
		entryData = make([]byte, 94+len(nameBytes))
		// NextEntryOffset(4)=0, FileIndex(4)=0
		binary.LittleEndian.PutUint64(entryData[8:16], now)
		binary.LittleEndian.PutUint64(entryData[16:24], now)
		binary.LittleEndian.PutUint64(entryData[24:32], now)
		binary.LittleEndian.PutUint64(entryData[32:40], now)
		binary.LittleEndian.PutUint64(entryData[40:48], uint64(sess.fileSize))
		binary.LittleEndian.PutUint64(entryData[48:56], uint64(sess.fileSize))
		binary.LittleEndian.PutUint32(entryData[56:60], fileAttrReadOnly)
		binary.LittleEndian.PutUint32(entryData[60:64], uint32(len(nameBytes)))
		// EaSize(4)=0, ShortNameLength(1)=0, Reserved(1)=0, ShortName(24)=zeros
		copy(entryData[94:], nameBytes)

	default:
		// FILE_DIRECTORY_INFO fallback.
		entryData = make([]byte, 64+len(nameBytes))
		binary.LittleEndian.PutUint64(entryData[8:16], now)
		binary.LittleEndian.PutUint64(entryData[16:24], now)
		binary.LittleEndian.PutUint64(entryData[24:32], now)
		binary.LittleEndian.PutUint64(entryData[32:40], now)
		binary.LittleEndian.PutUint64(entryData[40:48], uint64(sess.fileSize))
		binary.LittleEndian.PutUint64(entryData[48:56], uint64(sess.fileSize))
		binary.LittleEndian.PutUint32(entryData[56:60], fileAttrReadOnly)
		binary.LittleEndian.PutUint32(entryData[60:64], uint32(len(nameBytes)))
		copy(entryData[64:], nameBytes)
	}

	// FIND_FIRST2 response parameters.
	respParams := make([]byte, 10)
	binary.LittleEndian.PutUint16(respParams[0:2], 0x0001) // SID
	binary.LittleEndian.PutUint16(respParams[2:4], 1)      // SearchCount
	binary.LittleEndian.PutUint16(respParams[4:6], 1)      // EndOfSearch
	return buildTrans2Response(req, respParams, entryData)
}

func buildTrans2Response(req *smbPacket, transParams, transData []byte) *smbPacket {
	if transParams == nil {
		transParams = []byte{}
	}
	if transData == nil {
		transData = []byte{}
	}

	resp := newResponse(req)

	// WordCount = 10 (20 bytes).
	words := make([]byte, 20)
	binary.LittleEndian.PutUint16(words[0:2], uint16(len(transParams)))
	binary.LittleEndian.PutUint16(words[2:4], uint16(len(transData)))
	binary.LittleEndian.PutUint16(words[6:8], uint16(len(transParams)))

	// ParameterOffset: header(32) + WC(1) + words(20) + BC(2) + pad(1) = 56.
	paramOffset := 56
	binary.LittleEndian.PutUint16(words[8:10], uint16(paramOffset))

	binary.LittleEndian.PutUint16(words[12:14], uint16(len(transData)))

	// DataOffset: after params, with alignment padding.
	dataOffset := paramOffset + len(transParams)
	dataPad := 0
	if len(transData) > 0 && dataOffset%2 != 0 {
		dataPad = 1
		dataOffset++
	}
	binary.LittleEndian.PutUint16(words[14:16], uint16(dataOffset))
	resp.words = words

	// Data section: pad(1) + transParams + dataPad + transData.
	data := make([]byte, 1+len(transParams)+dataPad+len(transData))
	data[0] = 0x00 // alignment pad
	copy(data[1:1+len(transParams)], transParams)
	copy(data[1+len(transParams)+dataPad:], transData)
	resp.data = data

	return resp
}

// --- TREE_DISCONNECT (0x71) ---

func handleTreeDisconnect(sess *session, req *smbPacket) *smbPacket {
	return newResponse(req)
}

// --- LOGOFF_ANDX (0x74) ---

func handleLogoff(sess *session, req *smbPacket) *smbPacket {
	resp := newResponse(req)
	words := make([]byte, 4)
	words[0] = 0xFF // AndXCommand: none
	resp.words = words
	return resp
}

// --- ECHO (0x2B) ---

func handleEcho(sess *session, req *smbPacket) *smbPacket {
	resp := newResponse(req)
	words := make([]byte, 2)
	binary.LittleEndian.PutUint16(words[0:2], 1) // SequenceNumber
	resp.words = words
	resp.data = req.data
	return resp
}

// --- Helpers ---

func timeToFiletime(t time.Time) uint64 {
	// Windows FILETIME: 100ns intervals since 1601-01-01.
	const epochDiff = 116444736000000000
	return uint64(t.UnixNano()/100) + epochDiff
}

func encodeUTF16LE(s string) []byte {
	codes := utf16.Encode([]rune(s))
	b := make([]byte, len(codes)*2)
	for i, c := range codes {
		binary.LittleEndian.PutUint16(b[i*2:], c)
	}
	return b
}

func decodeUTF16LE(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	for len(u16) > 0 && u16[len(u16)-1] == 0 {
		u16 = u16[:len(u16)-1]
	}
	return string(utf16.Decode(u16))
}
