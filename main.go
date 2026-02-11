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
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <iso-path> [listen-addr]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Default listen address: :445\n")
		os.Exit(1)
	}

	isoPath := os.Args[1]
	listenAddr := ":445"
	if len(os.Args) >= 3 {
		listenAddr = os.Args[2]
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

	log.Printf("Serving %s (%d bytes) on smb://%s/share/%s",
		absPath, info.Size(), listenAddr, filepath.Base(absPath))

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
		go handleConnection(conn, absPath, info.Size())
	}
}

func handleConnection(conn net.Conn, isoPath string, fileSize int64) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()
	log.Printf("[%s] Connected", remote)
	defer log.Printf("[%s] Disconnected", remote)

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
	hdr := []byte{
		msgType,
		byte(length >> 16),
		byte(length >> 8),
		byte(length),
	}
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	if len(data) > 0 {
		_, err := w.Write(data)
		return err
	}
	return nil
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

func handleRead(sess *session, req *smbPacket) *smbPacket {
	if len(req.words) < 20 {
		return errorResponse(req, statusInvalidHandle)
	}

	fid := binary.LittleEndian.Uint16(req.words[4:6])
	if fid != sess.fid {
		return errorResponse(req, statusInvalidHandle)
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

	// Read file data.
	buf := make([]byte, maxCount)
	n := 0
	if maxCount > 0 {
		var err error
		n, err = sess.file.ReadAt(buf, offset)
		if err != nil && err != io.EOF {
			log.Printf("ReadAt error at offset %d: %v", offset, err)
			n = 0
		}
	}

	resp := newResponse(req)
	resp.header.tid = req.header.tid

	// WordCount = 12 (24 bytes).
	words := make([]byte, 24)
	words[0] = 0xFF // AndXCommand: none
	binary.LittleEndian.PutUint16(words[4:6], 0xFFFF)     // Remaining
	binary.LittleEndian.PutUint16(words[10:12], uint16(n)) // DataLength
	// DataOffset: header(32) + WC(1) + words(24) + BC(2) + pad(1) = 60.
	binary.LittleEndian.PutUint16(words[12:14], 60)
	resp.words = words

	// Data: 1 pad byte + file data.
	resp.data = make([]byte, 1+n)
	copy(resp.data[1:], buf[:n])
	return resp
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
