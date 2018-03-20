// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package flow provides functionality for constructing packet processing graph

// Preparations of construction:
// All construction should be between SystemInit and SystemStart functions.
// User command line options should be added as flags before SystemInit option - it will
// parse them as well as internal library options.

// Packet processing graph construction:
// NFF-GO library provides nine so-called Flow Functions for packet processing graph
// construction. They operate term "flow" however it is just abstraction for connecting
// them. Not anything beyond this. These nine flow functions are:
// Receive, Generate - for adding packets to graph
// Send, Stop - for removing packets from graph
// Handle - for handling packets inside graph
// Separate, Split, Count, Merge for combining flows inside graph
// All this functions can be added to the graph be "Set" functions like
// SetReceiver, SetSplitter, etc.

// Flow functions Generate, Handle, Separate and Split use user defined functions
// for processing. These functions are received each packet from flow (or new
// allocated packet in generate). Function types of user defined functions are
// also defined in this file.

// Package flow is the main package of NFF-GO library and should be always imported by
// user application.
package flow

import (
	"os"
	"runtime"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/intel-go/nff-go/asm"
	"github.com/intel-go/nff-go/common"
	"github.com/intel-go/nff-go/low"
	"github.com/intel-go/nff-go/packet"
)

var openFlowsNumber = uint32(0)
var ringName = 1
var createdPorts []port
var schedState *scheduler
var vEach [10][burstSize]uint8

type processLine struct {
	out      []*low.Ring
	contexts []*UserContext
}

// Flow is an abstraction for connecting flow functions with each other.
// Flow shouldn't be understood in any way beyond this.
type Flow struct {
	current  *low.Ring
	line     *processLine
	previous **sFunc
}

type partitionCtx struct {
	currentAnswer       int
	currentCompare      uint64
	currentPacketNumber uint64
	N                   uint64
	M                   uint64
}

func (c partitionCtx) Copy() interface{} {
	n := new(partitionCtx)
	n.N = c.N
	n.M = c.M
	n.currentCompare = c.N
	return n
}

func (c partitionCtx) Delete() {
}

type sFunc struct {
	handleFunction   HandleFunction
	separateFunction SeparateFunction
	splitFunction    SplitFunction
	Func             func(*packet.Packet, *sFunc, UserContext) int
	next             [](*sFunc)
	bufIndex         int
	contextIndex     int
}

type vFunc struct {
	handleFunction   VectorHandleFunction
	separateFunction VectorSeparateFunction
	splitFunction    VectorSplitFunction
	Func             func([]*packet.Packet, *[burstSize]bool, *[burstSize]uint8, *vFunc)
	next             [](*vFunc)
	bufIndex         int
	contextIndex     int
	followingNumber  uint8
}

// GenerateFunction is a function type for user defined function which generates packets.
// Function receives preallocated packet where user should add
// its size and content.
type GenerateFunction func(*packet.Packet, UserContext)

// VectorGenerateFunction is a function type like GenerateFunction for vector generating
type VectorGenerateFunction func([]*packet.Packet, uint, UserContext)

// HandleFunction is a function type for user defined function which handles packets.
// Function receives a packet from flow. User should parse it
// and make necessary changes. It is prohibit to free packet in this
// function.
type HandleFunction func(*packet.Packet, UserContext)

// VectorHandleFunction is a function type like GenerateFunction for vector handling
type VectorHandleFunction func([]*packet.Packet, *[burstSize]bool, *[burstSize]uint8, UserContext)

// SeparateFunction is a function type for user defined function which separates packets
// based on some rule for two flows. Functions receives a packet from flow.
// User should parse it and decide whether this packet should remains in
// this flow - return true, or should be sent to new added flow - return false.
type SeparateFunction func(*packet.Packet, UserContext) bool

// VectorSeparateFunction is a function type like GenerateFunction for vector separation
type VectorSeparateFunction func([]*packet.Packet, *[burstSize]bool, *[burstSize]uint8, UserContext)

// SplitFunction is a function type for user defined function which splits packets
// based in some rule for multiple flows. Function receives a packet from
// flow. User should parse it and decide in which output flows this packet
// should be sent. Return number of flow shouldn't exceed target number
// which was put to SetSplitter function. Also it is assumed that "0"
// output flow is used for dropping packets - "Stop" function should be
// set after "Split" function in it.
type SplitFunction func(*packet.Packet, UserContext) uint

type VectorSplitFunction func([]*packet.Packet, *[burstSize]bool, *[burstSize]uint8, UserContext)

// Kni is a high level struct of KNI device. The device itself is stored
// in C memory in low.c and is defined by its port which is equal to port
// in this structure
type Kni struct {
	portId uint8
}

type receiveParameters struct {
	out  *low.Ring
	port *low.Port
	kni  bool
}

func addReceiver(portId uint8, kni bool, out *low.Ring) {
	par := new(receiveParameters)
	par.port = low.GetPort(portId)
	par.out = out
	par.kni = kni
	if kni {
		schedState.addFF("receiver", nil, recvKNI, nil, par, nil, nil, sendReceiveKNI)
	} else {
		schedState.addFF("receiver", nil, recvRSS, nil, par, nil, nil, receiveRSS)
	}
}

type generateParameters struct {
	out                    *low.Ring
	generateFunction       GenerateFunction
	vectorGenerateFunction VectorGenerateFunction
	mempool                *low.Mempool
	targetSpeed            float64
}

func addGenerator(out *low.Ring, generateFunction GenerateFunction) {
	par := new(generateParameters)
	par.out = out
	par.generateFunction = generateFunction
	schedState.addFF("generator", generateOne, nil, nil, par, nil, nil, other)
}

func addFastGenerator(out *low.Ring, generateFunction GenerateFunction,
	vectorGenerateFunction VectorGenerateFunction, targetSpeed uint64, context UserContext) {
	par := new(generateParameters)
	par.out = out
	par.generateFunction = generateFunction
	par.mempool = low.CreateMempool()
	par.vectorGenerateFunction = vectorGenerateFunction
	par.targetSpeed = float64(targetSpeed)
	ctx := make([]UserContext, 1, 1)
	ctx[0] = context
	schedState.addFF("fast generator", nil, nil, generatePerf, par, make(chan uint64, 50), &ctx, fastGenerate)
}

type sendParameters struct {
	in    *low.Ring
	queue int16
	port  uint8
}

func addSender(port uint8, queue int16, in *low.Ring) {
	par := new(sendParameters)
	par.port = port
	par.queue = queue
	par.in = in
	schedState.addFF("sender", nil, send, nil, par, nil, nil, sendReceiveKNI)
}

type copyParameters struct {
	in      *low.Ring
	out     *low.Ring
	outCopy *low.Ring
	mempool *low.Mempool
}

func addCopier(in *low.Ring, out *low.Ring, outCopy *low.Ring) {
	par := new(copyParameters)
	par.in = in
	par.out = out
	par.outCopy = outCopy
	par.mempool = low.CreateMempool()
	schedState.addFF("copy", nil, nil, pcopy, par, make(chan uint64, 50), nil, lineCopy)
}

// TODO add vector partitioner
func makePartitioner(N uint64, M uint64) *sFunc {
	f := new(sFunc)
	f.Func = partition
	f.next = make([]*sFunc, 2, 2)
	return f
}

func makeSeparator(separateFunction SeparateFunction) *sFunc {
	f := new(sFunc)
	f.separateFunction = separateFunction
	f.Func = separate
	f.next = make([]*sFunc, 2, 2)
	return f
}

func makeSplitter(splitFunction SplitFunction) *sFunc {
	f := new(sFunc)
	f.splitFunction = splitFunction
	f.Func = split
	f.next = make([]*sFunc, 20, 20) // TODO parameter
	return f
}

func makeHandler(handleFunction HandleFunction) *sFunc {
	f := new(sFunc)
	f.handleFunction = handleFunction
	f.Func = handle
	f.next = make([]*sFunc, 1, 1)
	return f
}

type writeParameters struct {
	in       *low.Ring
	filename string
}

func addWriter(filename string, in *low.Ring) {
	par := new(writeParameters)
	par.in = in
	par.filename = filename
	schedState.addFF("writer", write, nil, nil, par, nil, nil, other)
}

type readParameters struct {
	out      *low.Ring
	filename string
	repcount int32
}

func addReader(filename string, out *low.Ring, repcount int32) {
	par := new(readParameters)
	par.out = out
	par.filename = filename
	par.repcount = repcount
	schedState.addFF("reader", read, nil, nil, par, nil, nil, other)
}

func makeSlice(out *low.Ring, line *processLine) *sFunc {
	f := new(sFunc)
	f.Func = constructSlice
	line.out = append(line.out, out)
	f.bufIndex = len(line.out)
	return f
}

type lineParameters struct {
	in         *low.Ring
	out        *([](*low.Ring))
	firstSFunc *sFunc
	firstVFunc *vFunc
}

func addLine(in *low.Ring, firstS *sFunc) *processLine {
	par := new(lineParameters)
	par.in = in
	par.firstSFunc = firstS
	line := new(processLine)
	line.out = make([](*low.Ring), 0, 0)
	line.contexts = make([](*UserContext), 0, 0)
	par.out = &line.out
	schedState.addFF("line", nil, nil, lineProcess, par, make(chan uint64, 50), nil, lineCopy)
	return line
}

const burstSize = 32

var sizeMultiplier uint
var schedTime uint
var hwtxchecksum bool

type port struct {
	wasRequested   bool // has user requested any send/receive operations at this port
	txQueuesNumber int16
	willReceive    bool // will this port receive packets
	port           uint8
}

// Config is a struct with all parameters, which user can pass to NFF-GO library
type Config struct {
	// Specifies cores which will be available for scheduler to place
	// flow functions and their clones.
	CPUList string
	// If true, scheduler is disabled entirely. Default value is false.
	DisableScheduler bool
	// If true, scheduler does not stop any previously cloned flow
	// function threads. Default value is false.
	PersistentClones bool
	// If true, Stop routine gets a dedicated CPU core instead of
	// running together with scheduler. Default value is false.
	StopOnDedicatedCore bool
	// Calculate IPv4, UDP and TCP checksums in hardware. This flag
	// slows down general TX processing, so it should be enabled if
	// applications intends to modify packets often, and therefore
	// needs to recalculate their checksums. If application doesn't
	// modify many packets, it may chose to calculate checksums in SW
	// and leave this flag off. Default value is false.
	HWTXChecksum bool
	// Specifies number of mbufs in mempool per port. Default value is
	// 8191.
	MbufNumber uint
	// Specifies number of mbufs in per-CPU core cache in
	// mempool. Default value is 250.
	MbufCacheSize uint
	// Number of burstSize groups in all rings. This should be power
	// of 2. Default value is 256.
	RingSize uint
	// Time between scheduler actions in miliseconds. Default value is
	// 1500.
	ScaleTime uint
	// Time in miliseconds for scheduler to check changing of flow
	// function behaviour. Default value is 10000.
	CheckTime uint
	// Time in miliseconds for scheduler to display statistics.
	// Default value is 1000.
	DebugTime uint
	// Specifies logging type. Default value is common.No |
	// common.Initialization | common.Debug.
	LogType common.LogType
	// Command line arguments to pass to DPDK initialization.
	DPDKArgs []string
	// Is user going to use KNI
	NeedKNI bool
}

// SystemInit is initialization of system. This function should be always called before graph construction.
// Function can panic during execution.
func SystemInit(args *Config) error {
	CPUCoresNumber := runtime.NumCPU()
	var cpus []int
	var err error
	if args.CPUList != "" {
		if cpus, err = common.HandleCPUList(args.CPUList, CPUCoresNumber); err != nil {
			return err
		}
	} else {
		cpus = common.GetDefaultCPUs(CPUCoresNumber)
	}

	schedulerOff := args.DisableScheduler
	schedulerOffRemove := args.PersistentClones
	stopDedicatedCore := args.StopOnDedicatedCore
	hwtxchecksum = args.HWTXChecksum

	mbufNumber := uint(4 * 8191)
	if args.MbufNumber != 0 {
		mbufNumber = args.MbufNumber
	}

	mbufCacheSize := uint(250)
	if args.MbufCacheSize != 0 {
		mbufCacheSize = args.MbufCacheSize
	}

	sizeMultiplier = 256
	if args.RingSize != 0 {
		sizeMultiplier = args.RingSize
	}

	schedTime = 500
	if args.ScaleTime != 0 {
		schedTime = args.ScaleTime
	}

	checkTime := uint(10000)
	if args.CheckTime != 0 {
		checkTime = args.CheckTime
	}

	debugTime := uint(1000)
	if args.DebugTime != 0 {
		debugTime = args.DebugTime
	}

	if debugTime < schedTime {
		common.LogFatal(common.Initialization, "debugTime should be larger or equal to schedTime")
	}

	needKNI := 0
	if args.NeedKNI != false {
		needKNI = 1
	}

	logType := common.No | common.Initialization | common.Debug
	if args.LogType != 0 {
		logType = args.LogType
	}
	common.SetLogType(logType)

	argc, argv := low.InitDPDKArguments(args.DPDKArgs)
	// We want to add new clone if input ring is approximately 80% full
	maxPacketsToClone := uint32(sizeMultiplier * burstSize / 5 * 4)
	// TODO all low level initialization here! Now everything is default.
	// Init eal
	common.LogTitle(common.Initialization, "------------***-------- Initializing DPDK --------***------------")
	low.InitDPDK(argc, argv, burstSize, mbufNumber, mbufCacheSize, needKNI)
	// Init Ports
	common.LogTitle(common.Initialization, "------------***-------- Initializing ports -------***------------")
	createdPorts = make([]port, low.GetPortsNumber(), low.GetPortsNumber())
	for i := range createdPorts {
		createdPorts[i].port = uint8(i)
	}
	// Init scheduler
	common.LogTitle(common.Initialization, "------------***------ Initializing scheduler -----***------------")
	StopRing := low.CreateRing(generateRingName(), burstSize*sizeMultiplier)
	common.LogDebug(common.Initialization, "Scheduler can use cores:", cpus)
	schedState = newScheduler(cpus, schedulerOff, schedulerOffRemove, stopDedicatedCore, StopRing, checkTime, debugTime, maxPacketsToClone)
	common.LogTitle(common.Initialization, "------------***------ Filling FlowFunctions ------***------------")
	// Init packet processing
	packet.SetHWTXChecksumFlag(hwtxchecksum)
	// Init low performance mempool
	packet.SetNonPerfMempool(low.CreateMempool())
	for i := 0; i < 10; i++ {
		for j := 0; j < burstSize; j++ {
			vEach[i][j] = uint8(i)
		}
	}
	return nil
}

// SystemStart starts system - begin packet receiving and packet sending.
// This functions should be always called after flow graph construction.
// Function can panic during execution.
func SystemStart() error {
	common.LogTitle(common.Initialization, "------------***--------- Checking system ---------***------------")
	if openFlowsNumber != 0 {
		return common.WrapWithNFError(nil, "Some flows are left open at the end of configuration!", common.OpenedFlowAtTheEnd)
	}
	common.LogTitle(common.Initialization, "------------***---------- Creating ports ---------***------------")
	for i := range createdPorts {
		if createdPorts[i].wasRequested {
			if err := low.CreatePort(createdPorts[i].port, createdPorts[i].willReceive,
				uint16(createdPorts[i].txQueuesNumber), hwtxchecksum); err != nil {
				return err
			}
		}
	}
	// Timeout is needed for ports to start up. This way is used in pktgen.
	// Pktgen also has checks for link status for all ports, but we compensate it
	// by additional time.
	// Timeout prevents loss of starting packets in generated flow.
	time.Sleep(time.Second * 2)

	common.LogTitle(common.Initialization, "------------***------ Starting FlowFunctions -----***------------")
	if err := schedState.systemStart(); err != nil {
		return common.WrapWithNFError(err, "scheduler start failed", common.Fail)
	}
	common.LogTitle(common.Initialization, "------------***--------- NFF-GO-GO Started --------***------------")
	schedState.schedule(schedTime)
	return nil
}

func generateRingName() string {
	s := strconv.Itoa(ringName)
	ringName++
	return s
}

// SetSenderFile adds write function to flow graph.
// Gets flow which packets will be written to file and
// target file name.
// Function can panic during execution.
func SetSenderFile(IN *Flow, filename string) error {
	if err := checkFlow(IN); err != nil {
		return err
	}
	addWriter(filename, finishFlow(IN))
	return nil
}

// SetReceiverFile adds read function to flow graph.
// Gets name of pcap formatted file and number of reads. If repcount = -1,
// file is read infinitely in circle.
// Returns new opened flow with read packets.
// Function can panic during execution.
func SetReceiverFile(filename string, repcount int32) (OUT *Flow) {
	ring := low.CreateRing(generateRingName(), burstSize*sizeMultiplier)
	addReader(filename, ring, repcount)
	return newFlow(ring)
}

// SetReceiver adds receive function to flow graph.
// Gets port number from which packets will be received.
// Receive queue will be added to port automatically.
// Returns new opened flow with received packets
// Function can panic during execution.
func SetReceiver(portId uint8) (OUT *Flow, err error) {
	if portId >= uint8(len(createdPorts)) {
		return nil, common.WrapWithNFError(nil, "Requested receive port exceeds number of ports which can be used by DPDK (bind to DPDK).", common.ReqTooManyPorts)
	}
	if createdPorts[portId].willReceive {
		return nil, common.WrapWithNFError(nil, "Requested receive port was already set to receive. Two receives from one port are prohibited.", common.MultipleReceivePort)
	}
	createdPorts[portId].wasRequested = true
	createdPorts[portId].willReceive = true
	ring := low.CreateRing(generateRingName(), burstSize*sizeMultiplier)
	addReceiver(portId, false, ring)
	return newFlow(ring), nil
}

// SetReceiverKNI adds function receive from KNI to flow graph.
// Gets KNI device from which packets will be received.
// Receive queue will be added to port automatically.
// Returns new opened flow with received packets
// Function can panic during execution.
func SetReceiverKNI(kni *Kni) (OUT *Flow) {
	ring := low.CreateRing(generateRingName(), burstSize*sizeMultiplier)
	addReceiver(kni.portId, true, ring)
	return newFlow(ring)
}

// SetFastGenerator adds clonable generate function to flow graph.
// Gets user-defined generate function, target speed of generation user wants to achieve and context.
// Returns new open flow with generated packets.
// Function tries to achieve target speed by cloning.
// Function can panic during execution.
func SetFastGenerator(f func(*packet.Packet, UserContext), targetSpeed uint64, context UserContext) (OUT *Flow, err error) {
	ring := low.CreateRing(generateRingName(), burstSize*sizeMultiplier)
	if targetSpeed > 0 {
		addFastGenerator(ring, GenerateFunction(f), nil, targetSpeed, context)
	} else {
		return nil, common.WrapWithNFError(nil, "Target speed value should be > 0", common.BadArgument)
	}
	return newFlow(ring), nil
}

// SetVectorFastGenerator adds clonable vector generate function to flow graph.
// Gets user-defined vector generate function, target speed of generation user wants to achieve and context.
// Returns new open flow with generated packets.
// Function tries to achieve target speed by cloning.
// Function can panic during execution.
func SetVectorFastGenerator(f func([]*packet.Packet, uint, UserContext), targetSpeed uint64, context UserContext) (OUT *Flow, err error) {
	ring := low.CreateRing(generateRingName(), burstSize*sizeMultiplier)
	if targetSpeed > 0 {
		addFastGenerator(ring, nil, VectorGenerateFunction(f), targetSpeed, context)
	} else {
		return nil, common.WrapWithNFError(nil, "Target speed value should be > 0", common.BadArgument)
	}
	return newFlow(ring), nil
}

// SetGenerator adds non-clonable generate flow function to flow graph.
// Gets user-defined generate function and context.
// Returns new open flow with generated packets.
// Single packet non-clonable flow function will be added. It can be used for waiting of
// input user packets.
// Function can panic during execution.
func SetGenerator(f func(*packet.Packet, UserContext), context UserContext) (OUT *Flow) {
	ring := low.CreateRing(generateRingName(), burstSize*sizeMultiplier)
	addGenerator(ring, GenerateFunction(f))
	return newFlow(ring)
}

// SetSender adds send function to flow graph.
// Gets flow which will be closed and its packets will be send and port number for which packets will be sent.
// Send queue will be added to port automatically.
// Function can panic during execution.
func SetSender(IN *Flow, portId uint8) error {
	if err := checkFlow(IN); err != nil {
		return err
	}
	if portId >= uint8(len(createdPorts)) {
		return common.WrapWithNFError(nil, "Requested send port exceeds number of ports which can be used by DPDK (bind to DPDK).", common.ReqTooManyPorts)
	}
	createdPorts[portId].wasRequested = true
	addSender(portId, createdPorts[portId].txQueuesNumber, finishFlow(IN))
	createdPorts[portId].txQueuesNumber++
	return nil
}

// SetSenderKNI adds function sending to KNI to flow graph.
// Gets flow which will be closed and its packets will be send to given KNI device.
// Send queue will be added to port automatically.
// Function can panic during execution.
func SetSenderKNI(IN *Flow, kni *Kni) error {
	if err := checkFlow(IN); err != nil {
		return err
	}
	addSender(kni.portId, -1, finishFlow(IN))
	return nil
}

// SetCopier adds copy function to flow graph.
// Gets flow which will be copied.
// Function can panic during execution.
func SetCopier(IN *Flow) (OUT *Flow, err error) {
	if err := checkFlow(IN); err != nil {
		return nil, err
	}
	ringFirst := low.CreateRing(generateRingName(), burstSize*sizeMultiplier)
	ringSecond := low.CreateRing(generateRingName(), burstSize*sizeMultiplier)
	addCopier(IN.current, ringFirst, ringSecond)
	IN.current = ringFirst
	return newFlow(ringSecond), nil
}

// SetPartitioner adds partition function to flow graph.
// Gets input flow and N and M constants. Returns new opened flow.
// Each loop N packets will be remained in input flow, next M packets will be sent to new flow.
// It is advised not to use this function less then (75, 75) for performance reasons.
// Function can panic during execution.
// We make partition function unclonable. The most complex task is (1,1).
// It means that if you would like to simply divide a flow
// it is recommended to use (75,75) instead of (1,1) for performance reasons.
func SetPartitioner(IN *Flow, N uint64, M uint64) (OUT *Flow, err error) {
	if err := checkFlow(IN); err != nil {
		return nil, err
	}
	if N == 0 || M == 0 {
		common.LogWarning(common.Initialization, "One of SetPartitioner function's arguments is zero.")
	}
	partition := makePartitioner(N, M)
	ctx := new(partitionCtx)
	ctx.N = N
	ctx.M = M
	lineInsert(IN, partition, false, *ctx)
	return newFlowLine(IN.line, &partition.next[1]), nil
}

// SetSeparator adds separate function to flow graph.
// Gets flow, user defined separate function and context. Returns new opened flow.
// Each packet from input flow will be remain inside input packet if
// user defined function returns "true" and is sent to new flow otherwise.
// Function can panic during execution.
func SetSeparator(IN *Flow, f func(*packet.Packet, UserContext) bool, context UserContext) (OUT *Flow, err error) {
	if err := checkFlow(IN); err != nil {
		return nil, err
	}
	separate := makeSeparator(SeparateFunction(f))
	lineInsert(IN, separate, false, context)
	return newFlowLine(IN.line, &separate.next[1]), nil
}

// SetVectorSeparator adds vector separate function to flow graph.
// Gets flow, user defined vector separate function and context. Returns new opened flow.
// Each packet from input flow will be remain inside input packet if
// user defined function returns "true" and is sent to new flow otherwise.
// Function can panic during execution.
func SetVectorSeparator(IN *Flow, f func([]*packet.Packet, []bool, uint, UserContext), context UserContext) (OUT *Flow, err error) {
	//if err := checkFlow(IN); err != nil {
	//	return nil, err
	//}
	//OUT = new(Flow)
	//ringTrue := low.CreateRing(generateRingName(), burstSize*sizeMultiplier)
	//ringFalse := low.CreateRing(generateRingName(), burstSize*sizeMultiplier)
	//openFlowsNumber++
	//addSeparator(IN.current, ringTrue, ringFalse, nil, VectorSeparateFunction(f), "vector separator", context)
	//IN.current = ringTrue
	//OUT.current = ringFalse
	return OUT, nil
}

// SetSplitter adds split function to flow graph.
// Gets flow, user defined split function, flowNumber of new flows and context.
// Returns array of new opened flows with corresponding length.
// Each packet from input flow will be sent to one of new flows based on
// user defined function output for this packet.
// Function can panic during execution.
func SetSplitter(IN *Flow, splitFunction SplitFunction, flowNumber uint, context UserContext) (OutArray [](*Flow), err error) {
	if err := checkFlow(IN); err != nil {
		return nil, err
	}
	OutArray = make([](*Flow), flowNumber, flowNumber)
	split := makeSplitter(splitFunction)
	for i := range OutArray {
		OutArray[i] = newFlowLine(IN.line, &split.next[i])
	}
	lineInsert(IN, split, true, context)
	return OutArray, nil
}

// SetStopper adds stop function to flow graph.
// Gets flow which will be closed and all packets from each will be dropped.
// Function can panic during execution.
func SetStopper(IN *Flow) error {
	if err := checkFlow(IN); err != nil {
		return err
	}
	if IN.line == nil {
		merge(IN.current, schedState.StopRing)
		closeFlow(IN)
	} else {
		ms := makeSlice(schedState.StopRing, IN.line)
		lineInsert(IN, ms, true, nil)
	}
	return nil
}

// SetHandler adds handle function to flow graph.
// Gets flow, user defined handle function and context.
// Each packet from input flow will be handle inside user defined function
// and sent further in the same flow.
// Function can panic during execution.
func SetHandler(IN *Flow, f func(*packet.Packet, UserContext), context UserContext) error {
	if err := checkFlow(IN); err != nil {
		return err
	}
	handle := makeHandler(HandleFunction(f))
	lineInsert(IN, handle, false, context)
	return nil
}

// SetVectorHandler adds vector handle function to flow graph.
// Gets flow, user defined vector handle function and context.
// Each packet from input flow will be handle inside user defined function
// and sent further in the same flow.
// Function can panic during execution.
func SetVectorHandler(IN *Flow, f func([]*packet.Packet, uint, UserContext), context UserContext) error {
	//if err := checkFlow(IN); err != nil {
	//	return err
	//}
	//ring := low.CreateRing(generateRingName(), burstSize*sizeMultiplier)
	//addHandler(IN.current, ring, nil, VectorHandleFunction(f), "vector handler", context)
	//IN.current = ring
	return nil
}

// SetHandlerDrop adds vector handle function to flow graph.
// Gets flow, user defined handle function and context.
// User defined function can return boolean value.
// If user function returns false after handling a packet it is dropped automatically.
// Function can panic during execution.
func SetHandlerDrop(IN *Flow, f func(*packet.Packet, UserContext) bool, context UserContext) error {
	if err := checkFlow(IN); err != nil {
		return err
	}
	separate := makeSeparator(SeparateFunction(f))
	lineInsert(IN, separate, false, context)
	SetStopper(newFlowLine(IN.line, &separate.next[1]))
	return nil
}

// SetVectorHandlerDrop adds vector handle function to flow graph.
// Gets flow, user defined vector handle function and context.
// User defined function can return boolean value.
// If user function returns false after handling a packet it is dropped automatically.
// Function can panic during execution.
func SetVectorHandlerDrop(IN *Flow, f func([]*packet.Packet, []bool, uint, UserContext), context UserContext) error {
	//if err := checkFlow(IN); err != nil {
	//	return err
	//}
	//ring := low.CreateRing(generateRingName(), burstSize*sizeMultiplier)
	//addSeparator(IN.current, ring, schedState.StopRing, nil, VectorSeparateFunction(f), "vector handler", context)
	//IN.current = ring
	return nil
}

// SetMerger adds merge function to flow graph.
// Gets any number of flows. Returns new opened flow.
// All input flows will be closed. All packets from all these flows will be sent to new flow.
// This function isn't use any cores. It changes output flows of other functions at initialization stage.
// TODO
func SetMerger(InArray ...*Flow) (OUT *Flow, err error) {
	ring := low.CreateRing(generateRingName(), burstSize*sizeMultiplier)
	for i := range InArray {
		if err := checkFlow(InArray[i]); err != nil {
			return nil, err
		}
		if InArray[i].line == nil {
			merge(InArray[i].current, ring)
			closeFlow(InArray[i])
		} else {
			ms := makeSlice(ring, InArray[i].line)
			lineInsert(InArray[i], ms, true, nil)
		}
	}
	OUT = new(Flow)
	OUT.current = ring
	openFlowsNumber++
	return OUT, nil
}

// GetPortMACAddress returns default MAC address of an Ethernet port.
func GetPortMACAddress(port uint8) [common.EtherAddrLen]uint8 {
	return low.GetPortMACAddress(port)
}

// Service functions for Flow
func newFlow(ring *low.Ring) *Flow {
	OUT := new(Flow)
	OUT.current = ring
	openFlowsNumber++
	return OUT
}

func newFlowLine(line *processLine, previous **sFunc) *Flow {
	OUT := newFlow(nil)
	OUT.line = line
	OUT.previous = previous
	return OUT
}

func finishFlow(IN *Flow) *low.Ring {
	var ring *low.Ring
	if IN.line == nil {
		ring = IN.current
	} else {
		ring = low.CreateRing(generateRingName(), burstSize*sizeMultiplier)
		ms := makeSlice(ring, IN.line)
		lineInsert(IN, ms, true, nil)
	}
	closeFlow(IN)
	return ring
}

func closeFlow(IN *Flow) {
	IN.current = nil
	openFlowsNumber--
}

func lineInsert(IN *Flow, f *sFunc, willClose bool, context UserContext) {
	if IN.line == nil {
		IN.line = addLine(IN.current, f)
	} else {
		*IN.previous = f
	}
	if willClose {
		closeFlow(IN)
	} else {
		IN.previous = &f.next[0]
	}
	IN.line.contexts = append(IN.line.contexts, &context)
	f.contextIndex = len(IN.line.contexts)
}

func lineProcess(parameters interface{}, stopper chan int, report chan uint64, context []UserContext) {
	// For scalar and vector parts
	lp := parameters.(*lineParameters)
	IN := lp.in
	OUT := *lp.out
	scalar := (lp.firstSFunc != nil)
	outNumber := len(*lp.out)
	InputMbufs := make([]uintptr, burstSize, burstSize)
	OutputMbufs := make([][]uintptr, outNumber)
	countOfPackets := make([]int, outNumber)
	for index := range OutputMbufs {
		OutputMbufs[index] = make([]uintptr, burstSize)
		countOfPackets[index] = 0
	}
	var currentSpeed uint64
	tick := time.Tick(time.Duration(schedTime) * time.Millisecond)
	var pause int
	// For scalar part
	firstFuncS := lp.firstSFunc
	var tempPacket *packet.Packet
	var tempPacketAddr uintptr
	// For vector part
	firstFuncV := lp.firstVFunc
	tempPackets := make([]*packet.Packet, burstSize)
	type pair struct {
		f    *vFunc
		mask [burstSize]bool
	}
	def := make([]pair, 30, 30)
	var answers [burstSize]uint8

	for {
		select {
		case pause = <-stopper:
			if pause == -1 {
				// It is time to close this clone
				close(stopper)
				for i := range context {
					if context[i] != nil {
						context[i].Delete()
					}
				}
				// We don't close report channel because all clones of one function use it.
				// As one function entity will be working endlessly we don't close it anywhere.
				return
			}
		case <-tick:
			report <- currentSpeed
			currentSpeed = 0
		default:
			n := IN.DequeueBurst(InputMbufs, burstSize)
			if n == 0 {
				if pause != 0 {
					time.Sleep(time.Duration(pause) * time.Nanosecond)
				}
				continue
			}
			// TODO prefetch
			// Scalar code
			if scalar {
				currentFunc := firstFuncS
				for i := uint(0); i < n; i++ {
					tempPacketAddr = packet.ExtractPacketAddr(InputMbufs[i])
					tempPacket = packet.ToPacket(tempPacketAddr)
					for {
						nextIndex := currentFunc.Func(tempPacket, currentFunc, context[currentFunc.contextIndex])
						if nextIndex < 0 {
							// Previous func was constructSlice
							index := nextIndex*-1 - 1
							OutputMbufs[index][countOfPackets[index]] = InputMbufs[i]
							countOfPackets[index]++
							break
						}
						currentFunc = currentFunc.next[nextIndex]
					}
					for index := 0; index < outNumber; index++ {
						if countOfPackets[index] == 0 {
							continue
						}
						safeEnqueue(OUT[index], OutputMbufs[index], uint(countOfPackets[index]))
						currentSpeed += uint64(countOfPackets[index])
						countOfPackets[index] = 0
					}
				}
				// Vector code
			} else {
				packet.ExtractPackets(tempPackets, InputMbufs, n)
				def[0].f = firstFuncV
				st := 0
				for st != 0 {
					cur := def[st].f
					cur.Func(tempPackets, &def[st].mask, &answers, cur)
					if cur.followingNumber == 0 {
						count := FillSliceFromMask(InputMbufs, &def[st].mask, OutputMbufs[0])
						safeEnqueue(OUT[answers[0]], OutputMbufs[0], uint(count))
						currentSpeed += uint64(count)
					}
					if cur.followingNumber == 1 {
						// Mask remain the same
						def[st].f = cur.next[0]
					}
					for i := len(cur.next) - 1; i >= 0; i-- {
						cont := asm.GenerateMask(&answers, &(vEach[i]), &def[st].mask)
						if !cont {
							def[st].f = cur.next[i]
							st++
						}
					}
					st--
				}
			}
		}
	}
}

func recvRSS(parameters interface{}, flag *int, coreID int) {
	srp := parameters.(*receiveParameters)
	low.Receive(uint8(srp.port.PortId), int16(srp.port.QueuesNumber-1), srp.out, flag, coreID)
}

func recvKNI(parameters interface{}, flag *int, coreID int) {
	srp := parameters.(*receiveParameters)
	low.Receive(uint8(srp.port.PortId), -1, srp.out, flag, coreID)
}

func generateOne(parameters interface{}) {
	gp := parameters.(*generateParameters)
	OUT := gp.out
	generateFunction := gp.generateFunction
	for {
		tempPacket, err := packet.NewPacket()
		if err != nil {
			common.LogFatal(common.Debug, err)
		}
		generateFunction(tempPacket, nil)
		safeEnqueueOne(OUT, tempPacket.ToUintptr())
	}
}

func generatePerf(parameters interface{}, stopper chan int, report chan uint64, context []UserContext) {
	gp := parameters.(*generateParameters)
	OUT := gp.out
	generateFunction := gp.generateFunction
	vectorGenerateFunction := gp.vectorGenerateFunction
	mempool := gp.mempool
	vector := (vectorGenerateFunction != nil)

	bufs := make([]uintptr, burstSize)
	var tempPacket *packet.Packet
	tempPackets := make([]*packet.Packet, burstSize)
	var currentSpeed uint64
	tick := time.Tick(time.Duration(schedTime) * time.Millisecond)
	var pause int

	for {
		select {
		case pause = <-stopper:
			if pause == -1 {
				// It is time to close this clone
				close(stopper)
				if context[0] != nil {
					context[0].Delete()
				}
				// We don't close report channel because all clones of one function use it.
				// As one function entity will be working endlessly we don't close it anywhere.
				return
			}
		case <-tick:
			report <- currentSpeed
			currentSpeed = 0
		default:
			err := low.AllocateMbufs(bufs, mempool, burstSize)
			if err != nil {
				common.LogFatal(common.Debug, err)
			}
			if vector == false {
				for i := range bufs {
					// TODO Maybe we need to prefetcht here?
					tempPacket = packet.ExtractPacket(bufs[i])
					generateFunction(tempPacket, context[0])
				}
			} else {
				packet.ExtractPackets(tempPackets, bufs, burstSize)
				vectorGenerateFunction(tempPackets, burstSize, context[0])
			}
			safeEnqueue(OUT, bufs, burstSize)
			currentSpeed = currentSpeed + uint64(burstSize)
			// GO parks goroutines while Sleep. So Sleep lasts more time than our precision
			// we just want to slow goroutine down without parking, so loop is OK for this.
			// time.Now lasts approximately 70ns and this satisfies us
			if pause != 0 {
				a := time.Now()
				for time.Since(a) < time.Duration(pause*int(burstSize))*time.Nanosecond {
				}
			}
		}
	}
}

// TODO reassembled packets are not supported
func pcopy(parameters interface{}, stopper chan int, report chan uint64, context []UserContext) {
	cp := parameters.(*copyParameters)
	IN := cp.in
	OUT := cp.out
	OUTCopy := cp.outCopy
	mempool := cp.mempool

	bufs1 := make([]uintptr, burstSize)
	bufs2 := make([]uintptr, burstSize)
	var tempPacket1 *packet.Packet
	var tempPacket2 *packet.Packet
	var currentSpeed uint64
	tick := time.Tick(time.Duration(schedTime) * time.Millisecond)
	var pause int

	for {
		select {
		case pause = <-stopper:
			if pause == -1 {
				// It is time to close this clone
				close(stopper)
				// We don't close report channel because all clones of one function use it.
				// As one function entity will be working endlessly we don't close it anywhere.
				return
			}
		case <-tick:
			report <- currentSpeed
			currentSpeed = 0
		default:
			n := IN.DequeueBurst(bufs1, burstSize)
			if n != 0 {
				if err := low.AllocateMbufs(bufs2, mempool, n); err != nil {
					common.LogFatal(common.Debug, err)
				}
				for i := range bufs1 {
					// TODO Maybe we need to prefetcht here?
					tempPacket1 = packet.ExtractPacket(bufs1[i])
					tempPacket2 = packet.ExtractPacket(bufs2[i])
					packet.GeneratePacketFromByte(tempPacket2, tempPacket1.GetRawPacketBytes())
				}
				safeEnqueue(OUT, bufs1, uint(n))
				safeEnqueue(OUTCopy, bufs2, uint(n))
				currentSpeed = currentSpeed + uint64(n)
			}
			// GO parks goroutines while Sleep. So Sleep lasts more time than our precision
			// we just want to slow goroutine down without parking, so loop is OK for this.
			// time.Now lasts approximately 70ns and this satisfies us
			if pause != 0 {
				a := time.Now()
				for time.Since(a) < time.Duration(pause*int(burstSize))*time.Nanosecond {
				}
			}
		}
	}
}

func send(parameters interface{}, flag *int, coreID int) {
	srp := parameters.(*sendParameters)
	low.Send(srp.port, srp.queue, srp.in, coreID)
}

func merge(from *low.Ring, to *low.Ring) {
	// We should change out rings in all flow functions which we added before
	// and change them to one "after merge" ring.
	// We don't proceed stop and send functions here because they don't have
	// out rings. Also we don't proceed merge function because they are added
	// strictly one after another. The next merge will change previous "after merge"
	// ring automatically.
	for i := range schedState.ff {
		switch schedState.ff[i].Parameters.(type) {
		case *receiveParameters:
			if schedState.ff[i].Parameters.(*receiveParameters).out == from {
				schedState.ff[i].Parameters.(*receiveParameters).out = to
			}
		case *generateParameters:
			if schedState.ff[i].Parameters.(*generateParameters).out == from {
				schedState.ff[i].Parameters.(*generateParameters).out = to
			}
		case *readParameters:
			if schedState.ff[i].Parameters.(*readParameters).out == from {
				schedState.ff[i].Parameters.(*readParameters).out = to
			}
		case *copyParameters:
			if schedState.ff[i].Parameters.(*copyParameters).out == from {
				schedState.ff[i].Parameters.(*copyParameters).out = to
			}
			if schedState.ff[i].Parameters.(*copyParameters).outCopy == from {
				schedState.ff[i].Parameters.(*copyParameters).outCopy = to
			}
		}
	}
}

func separate(packet *packet.Packet, sc *sFunc, ctx UserContext) int {
	if sc.separateFunction(packet, ctx) == true {
		return 0
	}
	return 1
}

func vSeparate(packets []*packet.Packet, mask *[burstSize]bool, answers *[burstSize]uint8, ve *vFunc, ctx UserContext) {
	ve.separateFunction(packets, mask, answers, ctx)
}

// partition doesn't need packets - just mbufs. However it will probably be
// among other functions. So this overhead is not much.
func partition(packet *packet.Packet, sc *sFunc, ctx UserContext) int {
	context := ctx.(partitionCtx)
	context.currentPacketNumber++
	if context.currentPacketNumber == context.currentCompare {
		context.currentAnswer = context.currentAnswer ^ 1
		context.currentCompare = context.N + context.M - context.currentCompare
		context.currentPacketNumber = 0
	}
	return context.currentAnswer
}

func split(packet *packet.Packet, sc *sFunc, ctx UserContext) int {
	return int(sc.splitFunction(packet, ctx))
}

func vSplit(packets []*packet.Packet, mask *[burstSize]bool, answers *[burstSize]uint8, ve *vFunc, ctx UserContext) {
	ve.splitFunction(packets, mask, answers, ctx)
}

func handle(packet *packet.Packet, sc *sFunc, ctx UserContext) int {
	sc.handleFunction(packet, ctx)
	return 0
}

func vHandle(packets []*packet.Packet, mask *[burstSize]bool, answers *[burstSize]uint8, ve *vFunc, ctx UserContext) {
	ve.handleFunction(packets, mask, answers, ctx)
}

func constructSlice(packet *packet.Packet, sc *sFunc, ctx UserContext) int {
	return -1 * sc.bufIndex
}

func vConstructSlice(packets []*packet.Packet, mask [burstSize]bool, answers [burstSize]uint8, ve *vFunc, ctx UserContext) {
	answers[0] = uint8(ve.bufIndex)
}

func write(parameters interface{}) {
	wp := parameters.(*writeParameters)
	IN := wp.in
	filename := wp.filename

	bufIn := make([]uintptr, 1)
	var tempPacket *packet.Packet

	f, err := os.Create(filename)
	if err != nil {
		common.LogFatal(common.Debug, err)
	}
	defer f.Close()

	err = packet.WritePcapGlobalHdr(f)
	if err != nil {
		common.LogFatal(common.Debug, err)
	}
	for {
		n := IN.DequeueBurst(bufIn, 1)
		if n == 0 {
			continue
		}
		tempPacket = packet.ExtractPacket(bufIn[0])
		err := tempPacket.WritePcapOnePacket(f)
		if err != nil {
			common.LogFatal(common.Debug, err)
		}
		low.DirectStop(1, bufIn)
	}
}

func read(parameters interface{}) {
	rp := parameters.(*readParameters)
	OUT := rp.out
	filename := rp.filename
	repcount := rp.repcount

	f, err := os.Open(filename)
	if err != nil {
		common.LogFatal(common.Debug, err)
	}
	defer f.Close()

	// Read pcap global header once
	var glHdr packet.PcapGlobHdr
	if err := packet.ReadPcapGlobalHdr(f, &glHdr); err != nil {
		common.LogFatal(common.Debug, err)
	}

	count := int32(0)

	for {
		tempPacket, err := packet.NewPacket()
		if err != nil {
			common.LogFatal(common.Debug, err)
		}
		isEOF, err := tempPacket.ReadPcapOnePacket(f)
		if err != nil {
			common.LogFatal(common.Debug, err)
		}
		if isEOF {
			atomic.AddInt32(&count, 1)
			if count == repcount {
				break
			}
			if _, err := f.Seek(packet.PcapGlobHdrSize, 0); err != nil {
				common.LogFatal(common.Debug, err)
			}
			if _, err := tempPacket.ReadPcapOnePacket(f); err != nil {
				common.LogFatal(common.Debug, err)
			}
		}
		// TODO we need packet reassembly here. However we don't
		// use mbuf packet_type here, so it is impossible.
		safeEnqueueOne(OUT, tempPacket.ToUintptr())
	}
}

// This function tries to write elements to input ring. However
// if this ring can't get these elements they will be placed
// inside stop ring which is emptied in separate thread.
func safeEnqueue(place *low.Ring, data []uintptr, number uint) {
	done := place.EnqueueBurst(data, number)
	if done < number {
		schedState.Dropped += number - uint(done)
		done2 := schedState.StopRing.EnqueueBurst(data[done:number], number-uint(done))
		// If stop ring is crowded a function will call C stop directly without
		// moving forward. It prevents constant crowd stop and increases
		// performance on "long accelerating" topologies in 1.5x times.
		if done2 < number-uint(done) {
			common.LogWarning(common.Verbose, "Normal fast stop is crowded. Use slow C stop instead.")
			low.DirectStop(int(number-uint(done)-uint(done2)), data[done+done2:number])
		}
	}
	// TODO we need to investigate whether we need to return actual number of enqueued packets.
	// We can use this number if controlling speed, however it is not clear what is better:
	// to use actual number or to use simply number of packets processed by a function like now.
}

// This function makes []uintptr and is inefficient. Only for non-performance critical tasks
func safeEnqueueOne(place *low.Ring, data uintptr) {
	slice := make([]uintptr, 1, 1)
	slice[0] = data
	safeEnqueue(place, slice, 1)
}

func checkFlow(f *Flow) error {
	if f == nil {
		return common.WrapWithNFError(nil, "One of the flows is nil!", common.UseNilFlowErr)
	}
	if f.current == nil {
		return common.WrapWithNFError(nil, "One of the flows is used after it was closed!", common.UseClosedFlowErr)
	}
	return nil
}

// CreateKniDevice creates KNI device for using in receive or send functions.
// Gets port, core (not from NFF-GO list), and unique name of future KNI device.
func CreateKniDevice(portId uint8, core uint8, name string) *Kni {
	low.CreateKni(portId, core, name)
	kni := new(Kni)
	// Port will be identifier of this KNI
	// KNI structure itself is stored inside low.c
	kni.portId = portId
	return kni
}

func FillSliceFromMask(input []uintptr, mask *[burstSize]bool, output []uintptr) uint8 {
	count := 0
	for i := 0; i < burstSize; i++ {
		if (*mask)[i] != false {
			output[count] = input[i]
			count++
		}
	}
	return uint8(count)
}
