#define _BSD_SOURCE 1
#include <cstdio>
#include <fcntl.h>
#include <cerrno>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <cinttypes>
#include <cassert>
#include <deque>
#include <atomic>
#include <time.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <infiniband/verbs.h>
#include <netdb.h>
#include <sys/socket.h>

#include <thread>
#include <mutex>
#include <iostream>
#include <map>
#include <algorithm>
#include <unordered_map>

#include "docopt.h"

#include "Tub.h"
#include "IpAddress.h"
#include "LargeBlockOfMemory.h"
#include "CycleCounter.h"
#include "SpinLock.h"

#include <fstream>
#include <iterator>
#define ZIPFIAN_SETUP 1

static const int PORT = 12240;

static const uint32_t MAX_INLINE_DATA = 0;
static const uint32_t MAX_SHARED_RX_QUEUE_DEPTH = 32;

// Since we always use at most 1 SGE per receive request, there is no need
// to set this parameter any higher. In fact, larger values for this
// parameter result in increased descriptor size, which means that the
// Infiniband controller needs to fetch more data from host memory,
// which results in a higher number of on-controller cache misses.
static const uint32_t MAX_SHARED_RX_SGE_COUNT = 1;
static const uint32_t MAX_TX_QUEUE_DEPTH = 128;

static const uint32_t MAX_TX_QUEUE_DEPTH_PER_THREAD = 4;

// Storing a vector of 10 million Zipfian skewed start addresses so as to 
// not take a perf hit while generating them in critical path
// Change the theta value here to adjust skew
static const double THETA = 0.50;
static const uint32_t MAX_ZIPFIAN_ADDRESSES = 10000000;

void write_vector_to_file(std::vector<uint32_t> *v, const char *path) {
    std::ofstream output_file(path);
    std::ostream_iterator<uint32_t> output_iterator(output_file, "\n");
    std::copy(v->begin(), v->end(), output_iterator);
}


// With 64 KB seglets 1 MB is fractured into 16 or 17 pieces, plus we
// need an entry for the headers.
// 31 seems to be the limit on this. Not sure why, because the qp's are
// initialized with a max sge limit of 1 anyway.
const uint32_t MAX_TX_SGE_COUNT = 32;
const uint32_t MIN_CHUNK_ZERO_COPY_LEN = 0;

static const uint32_t QP_EXCHANGE_MAX_TIMEOUTS = 10;

#define HTONS(x) \
    static_cast<uint16_t>((((x) >> 8) & 0xff) | (((x) & 0xff) << 8))
#define NTOHS HTONS

#define check_error_null(x, s)                              \
    do {                                                    \
        if ((x) == NULL) {                                  \
            LOG(ERROR, "%s", s);                            \
            exit(-1);                                       \
        }                                                   \
    } while (0)

ibv_srq*     serverSrq;         // shared receive work queue for server
ibv_srq*     clientSrq;         // shared receive work queue for client
ibv_cq*      serverRxCq;        // completion queue for incoming requests
ibv_cq*      clientRxCq;        // completion queue for client wait
ibv_cq*      commonTxCq;        // common completion queue for all transmits
int          ibPhysicalPort = 1;
int          lid;               // local id for this HCA and physical port
int          serverSetupSocket; // UDP socket for incoming setup requests;
                                // -1 means we're not a server
int          clientSetupSocket; // UDP socket for outgoing setup requests
int          clientPort;        // Port number associated with

static const size_t logSize = 4lu * 1024 * 1024 * 1024;

struct ThreadMetrics {
    ThreadMetrics()
        : postSendCycles{}
        , getTransmitCycles{}
        , memCpyCycles{}
        , addingGECycles{}
        , setupWRCycles{}
        , miscCycles{}
        , chunksTransmitted{}
        , chunksTransmittedZeroCopy{}
        , transmissions{}
        , transmittedBytes{}
    {}

    void reset() { new (this) ThreadMetrics{}; }

    static void dumpHeader() {
        printf("copied server chunksPerMessage chunkSize "
                "deltasPerMessage deltaSize "
                "seconds warmupSeconds "
                "totalSecs totalNSecs "
                "sendNSecs getTxNSecs memcpyNSecs addingGENSecs setupWRNSecs "
                "miscCycles "
                "chunksTx chunksTxZeroCopy transmissions transmittedBytes mbs\n");
    }

    void dump(bool copied,
              const char* server,
              uint64_t cycles,
              int chunksPerMessage,
              size_t chunkSize,
              int deltasPerMessage,
              size_t deltaSize,
              double seconds,
              double warmupSeconds)
    {
        const double mbs =
            chunkSize * chunksTransmitted / seconds / (1024 * 1024);
        printf("%d %s %d %lu %d %lu %f %f %f %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %f\n",
               copied,
               server,
               chunksPerMessage,
               chunkSize,
               deltasPerMessage,
               deltaSize,
               seconds,
               warmupSeconds,
               Cycles::toSeconds(cycles),
               Cycles::toNanoseconds(cycles),
               Cycles::toNanoseconds(postSendCycles),
               Cycles::toNanoseconds(getTransmitCycles),
               Cycles::toNanoseconds(memCpyCycles),
               Cycles::toNanoseconds(addingGECycles),
               Cycles::toNanoseconds(setupWRCycles),
               Cycles::toNanoseconds(miscCycles),
               chunksTransmitted,
               chunksTransmittedZeroCopy,
               transmissions,
               transmittedBytes,
               mbs);
        fflush(stdout);
    }

    uint64_t postSendCycles;     // Cycles for post send calls per client;
    uint64_t getTransmitCycles;  // Cycles for getting transmit buffers per client;
    uint64_t memCpyCycles;       // Cycles for mem copying objects in copied=1 mode;
    uint64_t addingGECycles;     // Cycles adding gather list entries for zero-copy;
    uint64_t setupWRCycles;      // Cycles to create the WR sent to post_send;
    uint64_t miscCycles;         // Cycle counter for perf debugging.

    uint64_t chunksTransmitted;
    uint64_t chunksTransmittedZeroCopy;
    uint64_t transmissions;
    uint64_t transmittedBytes;
};

thread_local ThreadMetrics threadMetrics{};

ibv_context* ctxt;           // device context of the HCA to use
ibv_pd* pd;

struct BufferDescriptor {
    char *          buffer;         // buf of ``bytes'' length
    uint32_t        bytes;          // length of buffer in bytes
    uint32_t        messageBytes;   // byte length of message in the buffer
    ibv_mr *        mr;             // memory region of the buffer
    size_t          threadNum;      // The thread using this buffer (client)

    BufferDescriptor(char *buffer, uint32_t bytes, ibv_mr *mr, size_t threadNum)
        : buffer(buffer), bytes(bytes), messageBytes(0), mr(mr),
	  threadNum(threadNum) {}
    BufferDescriptor()
        : buffer(NULL), bytes(0), messageBytes(0), mr(NULL), threadNum(0) {}
};

void* rxBase;
BufferDescriptor rxDescriptors[MAX_SHARED_RX_QUEUE_DEPTH * 2];

void* txBase;
BufferDescriptor txDescriptors[MAX_TX_QUEUE_DEPTH];

std::vector<std::vector<BufferDescriptor*>> freeTxBuffers{};
std::vector<RAMCloud::UnnamedSpinLock> freeTxBufferMutex;
std::vector<std::vector<uint32_t>> zipfianChunkAddresses;
std::vector<std::vector<uint32_t>> zipfianDeltaAddresses;

uintptr_t logMemoryBase = 0;
size_t logMemoryBytes = 0;
ibv_mr* logMemoryRegion;

uint64_t remoteLogVA = 0;
uint32_t remoteLogRkey = 0;

/**
 * Pin all current and future memory pages in memory so that the OS does not
 * swap them to disk. All RAMCloud server main files should call this.
 *
 * Note that future mapping operations (e.g. mmap, stack expansion, etc)
 * may fail if their memory cannot be pinned due to resource limits. Thus the
 * check below may not capture all possible failures up front. It's probably
 * best to call this at the end of initialisation (after most large allocations
 * have been made). This is also a good idea because pinning slows down mmap
 * probing in #LargeBlockOfMemory.
 */
void pinAllMemory() {
    int r = mlockall(MCL_CURRENT | MCL_FUTURE);
    if (r != 0) {
        LOG(WARNING, "Could not lock all memory pages (%s), so the OS might "
                     "swap memory later. Check your user's \"ulimit -l\" and "
                     "adjust /etc/security/limits.conf as necessary.",
                     strerror(errno));
    }
}

// Lobotomized and injected with custom PRNG from RAMCloud/src/ClusterPerf.cc
class ZipfianGenerator {
  public:
    /**
     * Construct a generator.  This may be expensive if n is large.
     *
     * \param n
     *      The generator will output random numbers between 0 and n-1.
     * \param theta
     *      The zipfian parameter where 0 < theta < 1 defines the skew; the
     *      smaller the value the more skewed the distribution will be. Default
     *      value of 0.99 comes from the YCSB default value.
     */
    explicit ZipfianGenerator(uint32_t n, double theta = 0.99, size_t seed = 1)
        : n(n)
        , theta(theta)
        , alpha(1 / (1 - theta))
        , zetan(zeta(n, theta))
        , eta((1 - pow(2.0 / static_cast<double>(n), 1 - theta)) /
              (1 - zeta(2, theta) / zetan))
        , seed(seed)
        , prng{seed}
    {}

    /**
     * Return the zipfian distributed random number between 0 and n-1.
     */
    uint32_t nextNumber()
    {
	uint32_t random;
	random = prng.generate();	
        double u = static_cast<double>(random) /
                   static_cast<double>(~0U);
        double uz = u * zetan;
        if (uz < 1)
            return 0;
        if (uz < 1 + std::pow(0.5, theta))
            return 1;
        return 0 + static_cast<uint32_t>(static_cast<double>(n) *
                                         std::pow(eta*u - eta + 1.0, alpha));
    }

  private:
    const uint32_t n;       // Range of numbers to be generated.
    const double theta;     // Parameter of the zipfian distribution.
    const double alpha;     // Special intermediate result used for generation.
    const double zetan;     // Special intermediate result used for generation.
    const double eta;       // Special intermediate result used for generation.
    const size_t seed;      // Seed for random number generator
    PRNG prng;
    /**
     * Returns the nth harmonic number with parameter theta; e.g. H_{n,theta}.
     */
    static double zeta(uint32_t n, double theta)
    {
        double sum = 0;
        for (uint32_t i = 0; i < n; i++) {
            sum = sum + 1.0/(std::pow(i+1, theta));
        }
        return sum;
    }
};

// XXX Lobotomized for now.
class Address {
    int physicalPort;   // physical port number on local device
    uint16_t lid;       // local id (address)
    uint32_t qpn;       // queue pair number
    mutable ibv_ah* ah; // address handle, may be NULL
};

class QueuePairTuple {
  public:
    QueuePairTuple() : logVA{}, rkey{}, qpn(0), psn(0), lid(0), nonce(0)
    {
        static_assert(sizeof(QueuePairTuple) == 80,
                          "QueuePairTuple has unexpected size");
    }
    QueuePairTuple(uint64_t logVA, uint32_t rkey,
                   uint16_t lid, uint32_t qpn, uint32_t psn,
                   uint64_t nonce, const char* peerName = "?unknown?")
        : logVA{logVA}, rkey{rkey},
          qpn(qpn), psn(psn), lid(lid), nonce(nonce)
    {
        snprintf(this->peerName, sizeof(this->peerName), "%s",
            peerName);
    }
    uint64_t    getLogVA() const    { return logVA; }
    uint32_t    getRkey() const     { return rkey; }
    uint16_t    getLid() const      { return lid; }
    uint32_t    getQpn() const      { return qpn; }
    uint32_t    getPsn() const      { return psn; }
    uint64_t    getNonce() const    { return nonce; }
    const char* getPeerName() const { return peerName; }

  private:
    uint64_t logVA;          // Virtual address of start of remote log.
    uint32_t rkey;           // rkey of remote log for RDMA.

    uint32_t qpn;            // queue pair number
    uint32_t psn;            // initial packet sequence number
    uint16_t lid;            // infiniband address: "local id"
    uint64_t nonce;          // random nonce used to confirm replies are
                             // for received requests
    char peerName[50];       // Optional name for the sender (intended for
                             // use in error messages); null-terminated.
} __attribute__((packed));

class QueuePair {
  public:
    QueuePair(ibv_qp_type type,
              ibv_srq *srq,
              ibv_cq *txcq,
              ibv_cq *rxcq,
              uint32_t maxSendWr,
              uint32_t maxRecvWr,
              uint32_t QKey = 0);
    // exists solely as superclass constructor for MockQueuePair derivative
    explicit QueuePair()
        : type(0),
        srq(NULL), qp(NULL), txcq(NULL), rxcq(NULL),
        initialPsn(-1), handshakeSin() {}
    ~QueuePair();
    uint32_t    getInitialPsn() const;
    uint32_t    getLocalQpNumber() const;
    uint32_t    getRemoteQpNumber() const;
    uint16_t    getRemoteLid() const;
    int         getState() const;
    bool        isError() const;
    void        plumb(QueuePairTuple *qpt);
    void        setPeerName(const char *peerName);
    const char* getPeerName() const;
    void        activate();

  //private:
    int          type;           // QP type (IBV_QPT_RC, etc.)
    ibv_srq*     srq;            // shared receive queue
    ibv_qp*      qp;             // infiniband verbs QP handle
    ibv_cq*      txcq;           // transmit completion queue
    ibv_cq*      rxcq;           // receive completion queue
    uint32_t     initialPsn;     // initial packet sequence number
    sockaddr_in  handshakeSin;   // UDP address of the remote end used to
                                 // handshake when using RC queue pairs.
    char         peerName[50];   // Optional name for the sender
                                 // (intended for use in error messages);
                                 // null-terminated.
};

/**
 * Construct a QueuePair. This object hides some of the ugly
 * initialisation of Infiniband "queue pairs", which are single-side
 * transmit and receive queues. This object can represent both reliable
 * connected (RC) and unreliable datagram (UD) queue pairs. Not all
 * methods are valid to all queue pair types.
 *
 * Somewhat confusingly, each communicating end has a QueuePair, which are
 * bound (one might say "paired", but that's even more confusing). This
 * object is somewhat analogous to a TCB in TCP.
 *
 * After this method completes, the QueuePair will be in the INIT state.
 * A later call to #plumb() will transition it into the RTS state for
 * regular use with RC queue pairs.
 *
 * \param infiniband
 *      The #Infiniband object to associate this QueuePair with.
 * \param type
 *      The type of QueuePair to create. Currently valid values are
 *      IBV_QPT_RC for reliable QueuePairs and IBV_QPT_UD for
 *      unreliable ones.
 * \param ibPhysicalPort
 *      The physical port on the HCA we will use this QueuePair on.
 *      The default is 1, though some devices have multiple ports.
 * \param srq
 *      The Verbs shared receive queue to associate this QueuePair
 *      with. All writes received will use WQEs placed on the
 *      shared queue. If NULL, do not use a shared receive queue.
 * \param txcq
 *      The Verbs completion queue to be used for transmissions on
 *      this QueuePair.
 * \param rxcq
 *      The Verbs completion queue to be used for receives on this
 *      QueuePair.
 * \param maxSendWr
 *      Maximum number of outstanding send work requests allowed on
 *      this QueuePair.
 * \param maxRecvWr
 *      Maximum number of outstanding receive work requests allowed on
 *      this QueuePair.
 * \param QKey
 *      UD Queue Pairs only. The QKey for this pair.
 */
QueuePair::QueuePair(ibv_qp_type type,
    ibv_srq *srq, ibv_cq *txcq, ibv_cq *rxcq,
    uint32_t maxSendWr, uint32_t maxRecvWr, uint32_t QKey)
    : type(type),
      srq(srq),
      qp(NULL),
      txcq(txcq),
      rxcq(rxcq),
      initialPsn(rand() & 0xffffff),
      handshakeSin()
{
    snprintf(peerName, sizeof(peerName), "?unknown?");
    if (type != IBV_QPT_RC && type != IBV_QPT_UD && type != IBV_QPT_RAW_ETH)
        DIE("invalid queue pair type");

    ibv_qp_init_attr qpia;
    memset(&qpia, 0, sizeof(qpia));
    qpia.send_cq = txcq;
    qpia.recv_cq = rxcq;
    qpia.srq = srq;                    // use the same shared receive queue
    qpia.cap.max_send_wr  = maxSendWr; // max outstanding send requests
    qpia.cap.max_recv_wr  = maxRecvWr; // max outstanding recv requests
    qpia.cap.max_send_sge = 32;        // max send scatter-gather elements
    qpia.cap.max_recv_sge = 1;         // max recv scatter-gather elements
    qpia.cap.max_inline_data =         // max bytes of immediate data on send q
        MAX_INLINE_DATA;
    qpia.qp_type = type;               // RC, UC, UD, or XRC
    qpia.sq_sig_all = 0;               // only generate CQEs on requested WQEs

    qp = ibv_create_qp(pd, &qpia);
    if (qp == NULL) {
        DIE("failed to create queue pair");
    }

    // move from RESET to INIT state
    ibv_qp_attr qpa;
    memset(&qpa, 0, sizeof(qpa));
    qpa.qp_state   = IBV_QPS_INIT;
    qpa.pkey_index = 0;
    qpa.port_num   = uint8_t(ibPhysicalPort);
    qpa.qp_access_flags = IBV_ACCESS_REMOTE_WRITE |
                          IBV_ACCESS_REMOTE_READ |
                          IBV_ACCESS_LOCAL_WRITE;
    qpa.qkey       = QKey;

    int mask = IBV_QP_STATE | IBV_QP_PORT;
    switch (type) {
    case IBV_QPT_RC:
        mask |= IBV_QP_ACCESS_FLAGS;
        mask |= IBV_QP_PKEY_INDEX;
        break;
    case IBV_QPT_UD:
        mask |= IBV_QP_QKEY;
        mask |= IBV_QP_PKEY_INDEX;
        break;
    case IBV_QPT_RAW_ETH:
        break;
    default:
        assert(0);
    }

    int ret = ibv_modify_qp(qp, &qpa, mask);
    if (ret) {
        ibv_destroy_qp(qp);
        DIE("failed to transition to INIT state errno %d", errno);
    }
}

/**
 * Destroy the QueuePair by freeing the Verbs resources allocated.
 */
QueuePair::~QueuePair()
{
    ibv_destroy_qp(qp);
}

/**
 * Bring an newly created RC QueuePair into the RTS state, enabling
 * regular bidirectional communication. This is necessary before
 * the QueuePair may be used. Note that this only applies to
 * RC QueuePairs.
 *
 * \param qpt
 *      QueuePairTuple representing the remote QueuePair. The Verbs
 *      interface requires us to exchange handshaking information
 *      manually. This includes initial sequence numbers, queue pair
 *      numbers, and the HCA infiniband addresses.
 *
 * \throw TransportException
 *      An exception is thrown if this method is called on a QueuePair
 *      that is not of type IBV_QPT_RC, or if the QueuePair is not
 *      in the INIT state.
 */
void
QueuePair::plumb(QueuePairTuple *qpt)
{
    ibv_qp_attr qpa;
    int r;

    if (type != IBV_QPT_RC)
        DIE("plumb() called on wrong qp type");

    if (getState() != IBV_QPS_INIT) {
        DIE("plumb() on qp in state %d", getState());
    }

    // now connect up the qps and switch to RTR
    memset(&qpa, 0, sizeof(qpa));
    qpa.qp_state = IBV_QPS_RTR;
    qpa.path_mtu = IBV_MTU_1024;
    qpa.dest_qp_num = qpt->getQpn();
    qpa.rq_psn = qpt->getPsn();
    qpa.max_dest_rd_atomic = 1;
    qpa.min_rnr_timer = 12;
    qpa.ah_attr.is_global = 0;
    qpa.ah_attr.dlid = qpt->getLid();
    qpa.ah_attr.sl = 0;
    qpa.ah_attr.src_path_bits = 0;
    qpa.ah_attr.port_num = uint8_t(ibPhysicalPort);

    r = ibv_modify_qp(qp, &qpa, IBV_QP_STATE |
                                IBV_QP_AV |
                                IBV_QP_PATH_MTU |
                                IBV_QP_DEST_QPN |
                                IBV_QP_RQ_PSN |
                                IBV_QP_MIN_RNR_TIMER |
                                IBV_QP_MAX_DEST_RD_ATOMIC);
    if (r) {
        DIE("failed to transition to RTR state");
    }

    // now move to RTS
    qpa.qp_state = IBV_QPS_RTS;

    // How long to wait before retrying if packet lost or server dead.
    // Supposedly the timeout is 4.096us*2^timeout.  However, the actual
    // timeout appears to be 4.096us*2^(timeout+1), so the setting
    // below creates a 135ms timeout.
    qpa.timeout = 14;

    // How many times to retry after timeouts before giving up.
    qpa.retry_cnt = 7;

    // How many times to retry after RNR (receiver not ready) condition
    // before giving up. Occurs when the remote side has not yet posted
    // a receive request.
    qpa.rnr_retry = 7; // 7 is infinite retry.
    qpa.sq_psn = initialPsn;
    qpa.max_rd_atomic = 1;

    r = ibv_modify_qp(qp, &qpa, IBV_QP_STATE |
                                IBV_QP_TIMEOUT |
                                IBV_QP_RETRY_CNT |
                                IBV_QP_RNR_RETRY |
                                IBV_QP_SQ_PSN |
                                IBV_QP_MAX_QP_RD_ATOMIC);
    if (r) {
        DIE("failed to transition to RTS state");
    }

    // the queue pair should be ready to use once the client has finished
    // setting up their end.
}

void
QueuePair::activate()
{
    ibv_qp_attr qpa;
    if (type != IBV_QPT_UD && type != IBV_QPT_RAW_ETH)
        DIE("activate() called on wrong qp type");

    if (getState() != IBV_QPS_INIT) {
        DIE("activate() on qp in state %d", getState());
    }

    // now switch to RTR
    memset(&qpa, 0, sizeof(qpa));
    qpa.qp_state = IBV_QPS_RTR;

    int ret = ibv_modify_qp(qp, &qpa, IBV_QP_STATE);
    if (ret) {
        DIE("failed to transition to RTR state");
    }

    // now move to RTS state
    qpa.qp_state = IBV_QPS_RTS;
    int flags = IBV_QP_STATE;
    if (type != IBV_QPT_RAW_ETH) {
        qpa.sq_psn = initialPsn;
        flags |= IBV_QP_SQ_PSN;
    }
    ret = ibv_modify_qp(qp, &qpa, flags);
    if (ret) {
        DIE("failed to transition to RTS state");
    }
}

/**
 * Get the initial packet sequence number for this QueuePair.
 * This is randomly generated on creation. It should not be confused
 * with the remote side's PSN, which is set in #plumb().
 */
uint32_t
QueuePair::getInitialPsn() const
{
    return initialPsn;
}

/**
 * Get the local queue pair number for this QueuePair.
 * QPNs are analogous to UDP/TCP port numbers.
 */
uint32_t
QueuePair::getLocalQpNumber() const
{
    return qp->qp_num;
}

/**
 * Get the remote queue pair number for this QueuePair, as set in #plumb().
 * QPNs are analogous to UDP/TCP port numbers.
 *
 * \throw
 *      TransportException is thrown if querying the queue pair
 *      fails.
 */
uint32_t
QueuePair::getRemoteQpNumber() const
{
    ibv_qp_attr qpa;
    ibv_qp_init_attr qpia;

    int r = ibv_query_qp(qp, &qpa, IBV_QP_DEST_QPN, &qpia);
    if (r) {
        // We should probably log something here.
        DIE("Bad things! %d", r);
    }

    return qpa.dest_qp_num;
}

/**
 * Get the remote infiniband address for this QueuePair, as set in #plumb().
 * LIDs are "local IDs" in infiniband terminology. They are short, locally
 * routable addresses.
 *
 * \throw
 *      TransportException is thrown if querying the queue pair
 *      fails.
 */
uint16_t
QueuePair::getRemoteLid() const
{
    ibv_qp_attr qpa;
    ibv_qp_init_attr qpia;

    int r = ibv_query_qp(qp, &qpa, IBV_QP_AV, &qpia);
    if (r) {
        // We should probably log something here.
        DIE("Bad things! %d", r);
    }

    return qpa.ah_attr.dlid;
}

/**
 * Get the state of a QueuePair.
 *
 * \throw
 *      TransportException is thrown if querying the queue pair
 *      fails.
 */
int
QueuePair::getState() const
{
    ibv_qp_attr qpa;
    ibv_qp_init_attr qpia;

    int r = ibv_query_qp(qp, &qpa, IBV_QP_STATE, &qpia);
    if (r) {
        // We should probably log something here.
        DIE("Bad things! %d", r);
    }
    return qpa.qp_state;
}

/**
 * Return true if the queue pair is in an error state, false otherwise.
 *
 * \throw
 *      TransportException is thrown if querying the queue pair
 *      fails.
 */
bool
QueuePair::isError() const
{
    ibv_qp_attr qpa;
    ibv_qp_init_attr qpia;

    int r = ibv_query_qp(qp, &qpa, -1, &qpia);
    if (r) {
        // We should probably log something here.
        DIE("Bad things! %d", r);
    }
    return qpa.cur_qp_state == IBV_QPS_ERR;
}

/**
 * Provide information that can be used in log messages to identify the
 * other end of this connection.
 *
 * \param name
 *      Human-readable name for the application or machine at the other
 *      end of this connection.
 */
void
QueuePair::setPeerName(const char* name)
{
    snprintf(peerName, sizeof(peerName), "%s", name);
}

const char*
QueuePair::getPeerName() const
{
    return peerName;
}

class DeviceList {
  public:
    DeviceList()
        : devices(ibv_get_device_list(NULL))
    {
        if (devices == NULL) {
            DIE("Could not open infiniband device list: %d", errno);
        }
    }

    ~DeviceList() {
        ibv_free_device_list(devices);
    }

    ibv_device*
    lookup(const char* name) {
        if (name == NULL)
            return devices[0];
        for (int i = 0; devices[i] != NULL; i++) {
            printf("%s\n", devices[i]->name);
            if (strcmp(devices[i]->name, name) == 0)
                return devices[i];
        }
        return NULL;
    }

  private:
    ibv_device** const devices;
};

Tub<DeviceList> deviceList{};

void*
xmemalign(size_t alignment, size_t len)
{
    void *p;
    int r;

    // alignment must be a power of two
    if ((alignment & (alignment - 1)) != 0) {
        DIE("xmemalign alignment (%lu) must be a power of two", alignment);
    }

    // alignment must be a multiple of sizeof(void*)
    if (alignment % sizeof(void*) != 0) { // NOLINT
        DIE("xmemalign alignment (%lu) must be a multiple of sizeof(void*)",
                alignment);
    }

    r = posix_memalign(&p, alignment, len > 0 ? len : 1);
    if (r != 0) {
        DIE("posix_memalign(%lu, %lu) failed", alignment, len);
    }

    return p;
}

bool getIpAddress(const char* hostName, uint16_t port, sockaddr* address)
{
    hostent host;
    hostent* result;
    char buffer[4096];
    int error;
    sockaddr_in* addr = (sockaddr_in*)(address);
    addr->sin_family = AF_INET;

    // Warning! The return value from getthostbyname_r is advertised
    // as being the same as what is returned at error, but it is not;
    // don't use it.
    gethostbyname_r(hostName, &host, buffer, sizeof(buffer),
            &result, &error);
    if (result == 0) {
        // If buffer is too small, an error value of ERANGE is supposed
        // to be returned, but in fact it appears that error is -1 in
        // the situation; check for both.
        if ((error == ERANGE) || (error == -1)) {
             DIE("IpAddress::IpAddress called gethostbyname_r"
                             " with too small a buffer");
        }
        DIE("couldn't find host %s", hostName);
    }
    memcpy(&addr->sin_addr, host.h_addr, sizeof(addr->sin_addr));
    addr->sin_port = htons(port);

    return true;
}

bool devSetup() {
    deviceList.construct();

    const char* name = NULL; // means match any it seems.
    ibv_device* dev = deviceList->lookup(name);
    if (dev == NULL) {
        DIE("failed to find infiniband device: %s",
                name == NULL ? "any" : name);
    }

    ctxt = ibv_open_device(dev);
    if (ctxt == NULL) {
        DIE("failed to open infiniband device: %s",
                name == NULL ? "any" : name);
    }

    pd = ibv_alloc_pd(ctxt);
    if (pd == NULL) {
        DIE("failed to allocate infiniband protection domain: %d", errno);
    }

    return true;
}

void devDestroy() {
    int rc = ibv_dealloc_pd(pd);
    if (rc != 0) {
        LOG(WARNING, "ibv_dealloc_pd failed");
    }

    rc = ibv_close_device(ctxt);
    if (rc != 0)
        LOG(WARNING, "ibv_close_device failed");
}

int
getLid(int port)
{
    ibv_port_attr ipa;
    int ret = ibv_query_port(ctxt, (uint8_t)(port), &ipa);
    if (ret) {
        DIE("ibv_query_port failed on port %u\n", port);
    }
    return ipa.lid;
}

ibv_srq*
createSharedReceiveQueue(uint32_t maxWr, uint32_t maxSge)
{
    ibv_srq_init_attr sia;
    memset(&sia, 0, sizeof(sia));
    sia.srq_context = ctxt;
    sia.attr.max_wr = maxWr;
    sia.attr.max_sge = maxSge;
    return ibv_create_srq(pd, &sia);
}

bool
setNonBlocking(int fd)
{
    int flags = fcntl(fd, F_GETFL);
    if (flags == -1) {
        return false;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK)) {
        return false;
    }
    return true;
}

void
createBuffers(void** ppBase,
              BufferDescriptor descriptors[],
              uint32_t bufferSize,
              uint32_t bufferCount,
              size_t threadNum)
{
    const size_t bytes = bufferSize * bufferCount;
    *ppBase = xmemalign(4096, bytes);

    ibv_mr *mr = ibv_reg_mr(pd, *ppBase, bytes,
        IBV_ACCESS_REMOTE_WRITE |
        IBV_ACCESS_REMOTE_READ |
        IBV_ACCESS_LOCAL_WRITE);
    if (mr == NULL) {
        DIE("failed to register buffer: %d", errno);
    }

    char* buffer = static_cast<char*>(*ppBase);
    for (uint32_t i = 0; i < bufferCount; ++i) {
        new(&descriptors[i]) BufferDescriptor(buffer, bufferSize, mr,
		threadNum);
        buffer += bufferSize;
    }
}

void
postSrqReceive(ibv_srq* srq, BufferDescriptor *bd)
{
    ibv_sge isge = {
        reinterpret_cast<uint64_t>(bd->buffer),
        bd->bytes,
        bd->mr->lkey
    };
    ibv_recv_wr rxWorkRequest;

    memset(&rxWorkRequest, 0, sizeof(rxWorkRequest));
    rxWorkRequest.wr_id = reinterpret_cast<uint64_t>(bd);// stash descriptor ptr
    rxWorkRequest.next = NULL;
    rxWorkRequest.sg_list = &isge;
    rxWorkRequest.num_sge = 1;

    ibv_recv_wr *badWorkRequest;

    int ret = ibv_post_srq_recv(srq, &rxWorkRequest, &badWorkRequest);
    if (ret) {
        DIE("Failure on ibv_post_srq_recv %d", ret);
    }
}

void
postSrqReceiveAndKickTransmit(ibv_srq* srq, BufferDescriptor *bd)
{
    postSrqReceive(srq, bd);
// XXX
#if 0
    // This condition is hacky. One idea is to wrap ibv_srq in an
    // object and make this a virtual method instead.
    if (srq == clientSrq) {
        --numUsedClientSrqBuffers;
        if (!clientSendQueue.empty()) {
            ClientRpc& rpc = clientSendQueue.front();
            clientSendQueue.pop_front();
            rpc.sendOrQueue();
            double waitTime = Cycles::toSeconds(Cycles::rdtsc()
                    - rpc.waitStart);
            if (waitTime > 1e-03) {
                LOG(WARNING, "Outgoing %s RPC delayed for %.2f ms because "
                        "of insufficient receive buffers",
                        WireFormat::opcodeSymbol(rpc.request),
                        waitTime*1e03);
            }
        }
    } else {
        ++numFreeServerSrqBuffers;
    }
#endif
}

void
handleFileEvent()
{
    sockaddr_in sin;
    socklen_t sinlen = sizeof(sin);
    QueuePairTuple incomingQpt;

    ssize_t len = recvfrom(serverSetupSocket, &incomingQpt,
        sizeof(incomingQpt), 0, reinterpret_cast<sockaddr *>(&sin), &sinlen);
    if (len <= -1) {
        if (errno == EAGAIN)
            return;
        LOG(ERROR, "recvfrom failed: %s", strerror(errno));
        return;
    } else if (len != sizeof(incomingQpt)) {
        LOG(WARNING, "recvfrom got a strange incoming size: %Zd", len);
        return;
    }

    // create a new queue pair, set it up according to our client's parameters,
    // and feed back our lid, qpn, and psn information so they can complete
    // the out-of-band handshake.

    // Note: It is possible that we already created a queue pair, but the
    // response to the client was lost and so we allocated another.
    // We should probably look up the QueuePair first using incomingQpt,
    // just to be sure, esp. if we use an unreliable means of handshaking, in
    // which case the response to the client request could have been lost.

    QueuePair *qp = new QueuePair(
            IBV_QPT_RC,
            serverSrq,
            commonTxCq,
            serverRxCq,
            MAX_TX_QUEUE_DEPTH,
            MAX_SHARED_RX_QUEUE_DEPTH);
    qp->plumb(&incomingQpt);
    qp->setPeerName(incomingQpt.getPeerName());
    LOG(DEBUG, "New queue pair for %s:%u, nonce 0x%lx, remote log VA 0x%lx, "
            "remote log rkey 0x%x",
            inet_ntoa(sin.sin_addr), HTONS(sin.sin_port),
            incomingQpt.getNonce(), incomingQpt.getLogVA(),
            incomingQpt.getRkey());
    remoteLogVA = incomingQpt.getLogVA();
    remoteLogRkey = incomingQpt.getRkey();

    // now send the client back our queue pair information so they can
    // complete the initialisation.
    QueuePairTuple outgoingQpt(uintptr_t(logMemoryRegion->addr),
                               logMemoryRegion->rkey,
                               uint16_t(lid),
                               qp->getLocalQpNumber(),
                               qp->getInitialPsn(), incomingQpt.getNonce());
    len = sendto(serverSetupSocket, &outgoingQpt,
            sizeof(outgoingQpt), 0, reinterpret_cast<sockaddr *>(&sin),
            sinlen);
    if (len != sizeof(outgoingQpt)) {
        LOG(WARNING, "sendto failed, len = %Zd", len);
        delete qp;
        return;
    }

    // store some identifying client information
    qp->handshakeSin = sin;

    // Dynamically instanciates a new InfRcServerPort associating
    // the newly created queue pair.
    // It is saved in serverPortMap with QpNumber a key.
    //serverPortMap[qp->getLocalQpNumber()] =
    //        new InfRcServerPort(qp);
}

void
pollSocket()
{
    LOG(NOTICE, "Polling for socket events");

    while (true) {
        handleFileEvent();
        sleep(1);
    }

}

/**
 * \param hostName
 *      nullptr for clients or the hostname to listen for incoming QP reqs on.
 */
bool setup(const char* hostName, size_t numThreads)
{
    clientSetupSocket = socket(PF_INET, SOCK_DGRAM, 0);
    if (clientSetupSocket == -1) {
        LOG(ERROR, "failed to create client socket: %s", strerror(errno));
        exit(-1);
    }
    sockaddr_in socketAddress;
    socketAddress.sin_family = AF_INET;
    socketAddress.sin_addr.s_addr = htonl(INADDR_ANY);
    socketAddress.sin_port = 0;
    if (bind(clientSetupSocket,
             (sockaddr * )(&socketAddress),
             sizeof(socketAddress)) == -1) {
        close(clientSetupSocket);
        LOG(WARNING, "couldn't bind port for clientSetupSocket: %s",
            strerror(errno));
        exit(-1);
    }

    if (!setNonBlocking(clientSetupSocket)) {
        close(clientSetupSocket);
        exit(-1);
    }

    socklen_t socketAddressLength = sizeof(socketAddress);
    if (getsockname(clientSetupSocket,
                    (sockaddr * )(&socketAddress),
                    &socketAddressLength) != 0) {
        close(clientSetupSocket);
        LOG(ERROR, "couldn't get port for clientSetupSocket: %s",
            strerror(errno));
        exit(-1);
    }
    clientPort = ntohs(socketAddress.sin_port);

    // If this is a server, create a server setup socket and bind it.
    if (hostName) {
        sockaddr address;
        getIpAddress(hostName, PORT, &address);

        serverSetupSocket = socket(PF_INET, SOCK_DGRAM, 0);
        if (serverSetupSocket == -1) {
            DIE("failed to create server socket: %s", strerror(errno));
        }

        if (bind(serverSetupSocket, &address, sizeof(address)))
        {
            close(serverSetupSocket);
            serverSetupSocket = -1;
            DIE("failed to bind socket for port %d: %s",
                PORT, strerror(errno));
        }

        if (!setNonBlocking(serverSetupSocket)) {
            close(serverSetupSocket);
            serverSetupSocket = -1;
            exit(-1);
        }

        LOG(NOTICE, "InfRc listening on UDP: %s:%d", hostName, PORT);

        std::thread t{pollSocket};
        t.detach();
    }
    if (!devSetup())
        DIE("Couldn't setup the Infiniband device");


    // create completion queues for server receive, client receive, and
    // server/client transmit

    if (!devSetup())
        DIE("Couldn't setup the Infiniband device");

    // Step 2:
    //  Set up the initial verbs necessities: open the device, allocate
    //  protection domain, create shared receive queue, register buffers.

    lid = getLid(ibPhysicalPort);

    // create two shared receive queues. all client queue pairs use one and all
    // server queue pairs use the other. we post receive buffer work requests
    // to these queues only. the motiviation is to avoid having to post at
    // least one buffer to every single queue pair (we may have thousands of
    // them with megabyte buffers).
    serverSrq = createSharedReceiveQueue(MAX_SHARED_RX_QUEUE_DEPTH,
                                         MAX_SHARED_RX_SGE_COUNT);
    check_error_null(serverSrq,
                     "failed to create server shared receive queue");
    clientSrq = createSharedReceiveQueue(MAX_SHARED_RX_QUEUE_DEPTH,
                                         MAX_SHARED_RX_SGE_COUNT);
    check_error_null(clientSrq,
                     "failed to create client shared receive queue");

    // Note: RPC performance is highly sensitive to the buffer size. For
    // example, as of 11/2012, using buffers of (1<<23 + 200) bytes is
    // 1.3 microseconds slower than using buffers of (1<<23 + 4096)
    // bytes.  For now, make buffers large enough for the largest RPC,
    // and round up to the next multiple of 4096.  This approach isn't
    // perfect (for example buffers of 1<<23 bytes also seem to be slow)
    // but it will work for now.
    uint32_t bufferSize = ((1u << 23) + 4095) & ~0xfff;

    createBuffers(&rxBase, rxDescriptors, bufferSize,
                  uint32_t(MAX_SHARED_RX_QUEUE_DEPTH * 2), 0);
    uint32_t j = 0;
    for (auto& bd : rxDescriptors) {
        if (j < MAX_SHARED_RX_QUEUE_DEPTH)
            postSrqReceiveAndKickTransmit(serverSrq, &bd);
        else
            postSrqReceiveAndKickTransmit(clientSrq, &bd);
        ++j;
    }
    //assert(numUsedClientSrqBuffers == 0);

    createBuffers(&txBase, txDescriptors,
        bufferSize, uint32_t(MAX_TX_QUEUE_DEPTH), 0);

    freeTxBuffers.resize(numThreads);
    freeTxBufferMutex.resize(numThreads);
#if defined ZIPFIAN_SETUP && ZIPFIAN_SETUP == 1
    zipfianChunkAddresses.resize(numThreads);
    zipfianDeltaAddresses.resize(numThreads);
#endif
    if (hostName) {
        for (auto& bd : txDescriptors)
            freeTxBuffers[0].push_back(&bd);
    } else {
        for (size_t i = 0, j = 0; i < numThreads; ++i) {
            for (size_t k = 0; k < MAX_TX_QUEUE_DEPTH_PER_THREAD; ++k, ++j) {
                txDescriptors[j].threadNum = i;
                freeTxBuffers[i].push_back(&(txDescriptors[j]));
            }
        }
    }

    // create completion queues for server receive, client receive, and
    // server/client transmit
    serverRxCq =
            ibv_create_cq(ctxt, MAX_SHARED_RX_QUEUE_DEPTH, NULL, NULL, 0);
    check_error_null(serverRxCq,
                     "failed to create server receive completion queue");

    clientRxCq =
            ibv_create_cq(ctxt, MAX_SHARED_RX_QUEUE_DEPTH, NULL, NULL, 0);
    check_error_null(clientRxCq,
                     "failed to create client receive completion queue");

    commonTxCq =
            ibv_create_cq(ctxt, MAX_TX_QUEUE_DEPTH, NULL, NULL, 0);
    check_error_null(commonTxCq,
                     "failed to create transmit completion queue");


    return true;

}



const char*
wcStatusToString(int status)
{
    static const char *lookup[] = {
        "SUCCESS",
        "LOC_LEN_ERR",
        "LOC_QP_OP_ERR",
        "LOC_EEC_OP_ERR",
        "LOC_PROT_ERR",
        "WR_FLUSH_ERR",
        "MW_BIND_ERR",
        "BAD_RESP_ERR",
        "LOC_ACCESS_ERR",
        "REM_INV_REQ_ERR",
        "REM_ACCESS_ERR",
        "REM_OP_ERR",
        "RETRY_EXC_ERR",
        "RNR_RETRY_EXC_ERR",
        "LOC_RDD_VIOL_ERR",
        "REM_INV_RD_REQ_ERR",
        "REM_ABORT_ERR",
        "INV_EECN_ERR",
        "INV_EEC_STATE_ERR",
        "FATAL_ERR",
        "RESP_TIMEOUT_ERR",
        "GENERAL_ERR"
    };

    if (status < IBV_WC_SUCCESS || status > IBV_WC_GENERAL_ERR)
        return "<status out of range!>";
    return lookup[status];
}

uint64_t txFailures = 0;

int
reapTxBuffers()
{
    ibv_wc retArray[MAX_TX_QUEUE_DEPTH];
    int n = ibv_poll_cq(commonTxCq, MAX_TX_QUEUE_DEPTH, retArray);

    for (int i = 0; i < n; i++) {
        BufferDescriptor* bd =
            reinterpret_cast<BufferDescriptor*>(retArray[i].wr_id);
        if (bd == nullptr)
            continue;

        size_t threadNum = bd->threadNum;

        std::lock_guard<RAMCloud::UnnamedSpinLock>
		lock{freeTxBufferMutex[threadNum]};
        freeTxBuffers[threadNum].push_back(bd);

        if (retArray[i].status != IBV_WC_SUCCESS) {
            LOG(ERROR, "Transmit failed for buffer %lu: %s",
                reinterpret_cast<uint64_t>(bd),
                wcStatusToString(retArray[i].status));
            ++txFailures;
            if (txFailures>=10000){
                txFailures=0;
                DIE("10K or more TxFailures occured. Exiting");
            }
        }
    }

    return n;
}

BufferDescriptor*
getTransmitBuffer(size_t threadNum)
{
    CycleCounter<> transmitCounter{&threadMetrics.getTransmitCycles};
    while (true) {
        {
            std::lock_guard<RAMCloud::UnnamedSpinLock>
  	        lock{freeTxBufferMutex[threadNum]};
            if (!freeTxBuffers[threadNum].empty()) {
                BufferDescriptor* bd = freeTxBuffers[threadNum].back();
                freeTxBuffers[threadNum].pop_back();
                return bd;
            }
        }

        reapTxBuffers();
    }
}

struct Chunk {
    void* p;
    uint32_t len;
};

void
sendStrictZeroCopy(Chunk* message,
                   uint32_t chunkCount,
                   uint32_t messageLen,
                   QueuePair* qp,
                   size_t threadNum)
{
    BufferDescriptor* bd = getTransmitBuffer(threadNum);
    bd->messageBytes = messageLen;

    ibv_sge isge[MAX_TX_SGE_COUNT];

    {
        CycleCounter<> _{&threadMetrics.addingGECycles};
        for (uint32_t i = 0 ; i < chunkCount; ++i) {
            Chunk& chunk = message[i];
#if 0
            const uintptr_t addr = reinterpret_cast<const uintptr_t>(chunk.p);

            // In-bounds.
            assert(addr >= logMemoryBase &&
                   (addr + chunk.len) <= (logMemoryBase + logMemoryBytes));
            
            // Still room.
            assert(sgesUsed < MAX_TX_SGE_COUNT - 1 ||
                              ((chunksUsed == (chunkCount -1)) &&
                               (unaddedStart == unaddedEnd)));
            // A long enough chunk to zero-copy.
            assert(chunk.len > MIN_CHUNK_ZERO_COPY_LEN);
#endif
            isge[i] = {
                reinterpret_cast<const uintptr_t>(chunk.p),
                chunk.len,
                logMemoryRegion->lkey
            };
        }
    }

    ibv_send_wr txWorkRequest;

    {
        CycleCounter<> _{&threadMetrics.setupWRCycles};
        memset(&txWorkRequest, 0, sizeof(txWorkRequest));
        txWorkRequest.wr_id = reinterpret_cast<uint64_t>(bd);// stash descriptor ptr
        txWorkRequest.next = NULL;
        txWorkRequest.sg_list = isge;
        txWorkRequest.num_sge = chunkCount;
        txWorkRequest.opcode = IBV_WR_SEND;
        txWorkRequest.send_flags = IBV_SEND_SIGNALED;

        // We can get a substantial latency improvement (nearly 2usec less per RTT)
        // by inlining data with the WQE for small messages. The Verbs library
        // automatically takes care of copying from the SGEs to the WQE.
        if (messageLen <= MAX_INLINE_DATA)
            txWorkRequest.send_flags |= IBV_SEND_INLINE;
    }

    threadMetrics.chunksTransmitted += chunkCount;
    threadMetrics.chunksTransmittedZeroCopy += chunkCount;
    threadMetrics.transmittedBytes += messageLen;
    ++threadMetrics.transmissions;

    CycleCounter<> postSendCtr{&threadMetrics.postSendCycles};
    ibv_send_wr* badTxWorkRequest;
    if (ibv_post_send(qp->qp, &txWorkRequest, &badTxWorkRequest)) {
        DIE("ibv_post_send failed");
    }
}

void
sendStrictCopy(Chunk* message,
               uint32_t chunkCount,
               uint32_t messageLen,
               QueuePair* qp,
               size_t threadNum)
{
    BufferDescriptor* bd = getTransmitBuffer(threadNum);
    bd->messageBytes = messageLen;

    {
        CycleCounter<> memcpyctr{&threadMetrics.memCpyCycles};
        char* unaddedEnd = bd->buffer;
        for (uint32_t i = 0; i < chunkCount; ++i) {
            Chunk& chunk = message[i];
            memcpy(unaddedEnd, chunk.p, chunk.len);
            unaddedEnd += chunk.len;
        }
    }

    ibv_sge isge = {
        reinterpret_cast<uint64_t>(bd->buffer),
        bd->messageBytes,
        bd->mr->lkey
    };

    ibv_send_wr txWorkRequest;
    {
        CycleCounter<> _{&threadMetrics.setupWRCycles};
        memset(&txWorkRequest, 0, sizeof(txWorkRequest));
        txWorkRequest.wr_id = reinterpret_cast<uint64_t>(bd);// stash descriptor ptr
        txWorkRequest.next = NULL;
        txWorkRequest.sg_list = &isge;
        txWorkRequest.num_sge = 1;
        txWorkRequest.opcode = IBV_WR_SEND;
        txWorkRequest.send_flags = IBV_SEND_SIGNALED;

        // We can get a substantial latency improvement (nearly 2usec less per RTT)
        // by inlining data with the WQE for small messages. The Verbs library
        // automatically takes care of copying from the SGEs to the WQE.
        if (messageLen <= MAX_INLINE_DATA)
            txWorkRequest.send_flags |= IBV_SEND_INLINE;
    }

    threadMetrics.chunksTransmitted += chunkCount;
    threadMetrics.transmittedBytes += messageLen;
    ++threadMetrics.transmissions;

    CycleCounter<> postSendCtr{&threadMetrics.postSendCycles};
    ibv_send_wr* badTxWorkRequest;
    if (ibv_post_send(qp->qp, &txWorkRequest, &badTxWorkRequest)) {
        DIE("ibv_post_send failed");
    }
}

/*
void
sendZeroCopy(Chunk* message, uint32_t chunkCount, uint32_t messageLen, QueuePair* qp, bool allowZeroCopy, size_t threadNum)
{
    BufferDescriptor* bd = getTransmitBuffer(threadNum);
    bd->messageBytes = messageLen;

    uint32_t chunksUsed = 0;
    uint32_t sgesUsed = 0;

    uint32_t lastChunkIndex = chunkCount - 1;
    ibv_sge isge[MAX_TX_SGE_COUNT];

    // The variables below allow us to collect several chunks from the
    // Buffer into a single sge in some situations. They describe a
    // range of bytes in bd that have not yet been put in an sge, but
    // must go into the next sge.
    char* unaddedStart = bd->buffer;
    char* unaddedEnd = bd->buffer;

    int chunksZeroCopied = 0;

    for (uint32_t i = 0 ; i < chunkCount; ++i) {
        Chunk& chunk = message[i];

        const uintptr_t addr = reinterpret_cast<const uintptr_t>(chunk.p);
        // See if we can transmit this chunk from its current location
        // (zero copy) vs. copying it into a transmit buffer:
        // * The chunk must lie in the range of registered memory that
        //   the NIC knows about.
        // * If we run out of sges, then everything has to be copied
        //   (but save the last sge for the last chunk, since it's the
        //   one most likely to benefit from zero copying.
        // * For small chunks, it's cheaper to copy than to send a
        //   separate descriptor to the NIC.
        //
        //   stutsman: hold back one SGE for any data copied to the tx buffer,
        //   *unless* this is the last chunk *and* the tx buffer is empty.
        const bool inBounds = addr >= logMemoryBase &&
            (addr + chunk.len) <= (logMemoryBase + logMemoryBytes);
        const bool stillRoom = (sgesUsed < MAX_TX_SGE_COUNT - 1 ||
                          ((chunksUsed == lastChunkIndex) &&
                           (unaddedStart == unaddedEnd)));
        const bool enoughLen = chunk.len > MIN_CHUNK_ZERO_COPY_LEN;
        
        if (allowZeroCopy && stillRoom && inBounds && enoughLen)
        {
            CycleCounter<> _{&threadMetrics.addingGECycles};
            if (unaddedStart != unaddedEnd) {
                isge[sgesUsed] = {
                    reinterpret_cast<uint64_t>(unaddedStart),
                    uint32_t(unaddedEnd - unaddedStart),
                    bd->mr->lkey
                };
                ++sgesUsed;
                unaddedStart = unaddedEnd;
            }

            isge[sgesUsed] = {
                addr,
                chunk.len,
                logMemoryRegion->lkey
            };
            ++sgesUsed;
            ++chunksZeroCopied;
        } else {
            if (allowZeroCopy){
                DIE("FATAL ERROR: memcpying in zero copy mode. inBounds: %s "
                    "stillRoom: %s enoughLen: %s",
                    inBounds ? "true" : "false",
                    stillRoom ? "true" : "false",
                    enoughLen ? "true" : "false");
            }
            CycleCounter<> memcpyctr{&threadMetrics.memCpyCycles};
            memcpy(unaddedEnd, chunk.p, chunk.len);
            unaddedEnd += chunk.len;
        }
        ++chunksUsed;
    }
    if (unaddedStart != unaddedEnd) {
        CycleCounter<> _{&threadMetrics.addingGECycles};
        isge[sgesUsed] = {
            reinterpret_cast<uint64_t>(unaddedStart),
            uint32_t(unaddedEnd - unaddedStart),
            bd->mr->lkey
        };
        ++sgesUsed;
        unaddedStart = unaddedEnd;
    }

    ibv_send_wr txWorkRequest;

    {
        CycleCounter<> _{&threadMetrics.setupWRCycles};
        memset(&txWorkRequest, 0, sizeof(txWorkRequest));
        txWorkRequest.wr_id = reinterpret_cast<uint64_t>(bd);// stash descriptor ptr
        txWorkRequest.next = NULL;
        txWorkRequest.sg_list = isge;
        txWorkRequest.num_sge = sgesUsed;
        txWorkRequest.opcode = IBV_WR_SEND;
        txWorkRequest.send_flags = IBV_SEND_SIGNALED;

        // We can get a substantial latency improvement (nearly 2usec less per RTT)
        // by inlining data with the WQE for small messages. The Verbs library
        // automatically takes care of copying from the SGEs to the WQE.
        if (messageLen <= MAX_INLINE_DATA)
            txWorkRequest.send_flags |= IBV_SEND_INLINE;
    }

    threadMetrics.chunksTransmitted += chunksUsed;
    threadMetrics.chunksTransmittedZeroCopy += chunksZeroCopied;
    threadMetrics.transmittedBytes += messageLen;
    ++threadMetrics.transmissions;

    ibv_send_wr* badTxWorkRequest;
    
    CycleCounter<> postSendCtr{&threadMetrics.postSendCycles};
    if (ibv_post_send(qp->qp, &txWorkRequest, &badTxWorkRequest)) {
        DIE("ibv_post_send failed");
    }
}
*/

/**
 * Asychronously transmit the packet described by 'bd' on queue pair 'qp'.
 * This function returns immediately.
 *
 * \param[in] qp
 *      The QueuePair on which to transmit the packet.
 * \param[in] bd
 *      The BufferDescriptor that contains the data to be transmitted.
 * \param[in] length
 *      The number of bytes used by the packet in the given BufferDescriptor.
 * \param[in] address
 *      UD queue pairs only. The address of the host to send to.
 * \param[in] remoteQKey
 *      UD queue pairs only. The Q_Key of the remote pair to send to.
 * \throw TransportException
 *      if the send post fails.
 */
void
postSend(QueuePair* qp, BufferDescriptor *bd, uint32_t length,
         const Address* address = NULL, uint32_t remoteQKey = 0)
{
    if (qp->type == IBV_QPT_UD) {
        assert(address != NULL);
    } else {
        assert(address == NULL);
        assert(remoteQKey == 0);
    }

    ibv_sge isge = {
        reinterpret_cast<uint64_t>(bd->buffer),
        length,
        bd->mr->lkey
    };
    ibv_send_wr txWorkRequest;

    memset(&txWorkRequest, 0, sizeof(txWorkRequest));
    txWorkRequest.wr_id = reinterpret_cast<uint64_t>(bd);// stash descriptor ptr
    // XXX Killed UD for now.
    /*
    if (qp->type == IBV_QPT_UD) {
        txWorkRequest.wr.ud.ah = address->getHandle();
        txWorkRequest.wr.ud.remote_qpn = address->getQpn();
        txWorkRequest.wr.ud.remote_qkey = remoteQKey;
    }
    */
    txWorkRequest.next = NULL;
    txWorkRequest.sg_list = &isge;
    txWorkRequest.num_sge = 1;
    txWorkRequest.opcode = IBV_WR_SEND;
    txWorkRequest.send_flags = IBV_SEND_SIGNALED;

    // We can get a substantial latency improvement (nearly 2usec less per RTT)
    // by inlining data with the WQE for small messages. The Verbs library
    // automatically takes care of copying from the SGEs to the WQE.
    if (length <= MAX_INLINE_DATA)
        txWorkRequest.send_flags |= IBV_SEND_INLINE;

    ibv_send_wr *bad_txWorkRequest;
    if (ibv_post_send(qp->qp, &txWorkRequest, &bad_txWorkRequest)) {
        DIE("ibv_post_send failed");
    }
}


/**
 * Synchronously transmit the packet described by 'bd' on queue pair 'qp'.
 * This function waits to the HCA to return a completion status before
 * returning.
 *
 * \param[in] qp
 *      The QueuePair on which to transmit the packet.
 * \param[in] bd
 *      The BufferDescriptor that contains the data to be transmitted.
 * \param[in] length
 *      The number of bytes used by the packet in the given BufferDescriptor.
 * \param[in] address
 *      UD queue pairs only. The address of the host to send to.
 * \param[in] remoteQKey
 *      UD queue pairs only. The Q_Key of the remote pair to send to.
 * \throw
 *      TransportException if the send does not result in success
 *      (IBV_WC_SUCCESS).
 */
void
postSendAndWait(QueuePair* qp, BufferDescriptor *bd,
    uint32_t length, const Address* address = NULL, uint32_t remoteQKey = 0)
{
    postSend(qp, bd, length, address, remoteQKey);

    ibv_wc wc;
    while (ibv_poll_cq(qp->txcq, 1, &wc) < 1) {}
    if (wc.status != IBV_WC_SUCCESS) {
        DIE("wc.status(%d:%s) != IBV_WC_SUCCESS",
            wc.status, wcStatusToString(wc.status));
    }
}

bool
clientTryExchangeQueuePairs(struct sockaddr_in *sin,
                            QueuePairTuple *outgoingQpt, QueuePairTuple *incomingQpt)
{
    bool haveSent = false;
    uint64_t startTime = rdtsc();
    while (1) {
        if (!haveSent) {
            ssize_t len = sendto(clientSetupSocket, outgoingQpt,
                                 sizeof(*outgoingQpt), 0, reinterpret_cast<sockaddr *>(sin),
                                 sizeof(*sin));
            if (len == -1) {
                if (errno != EINTR && errno != EAGAIN) {
                    DIE("sendto returned error %d: %s",
                        errno, strerror(errno));
                }
            } else if (len != sizeof(*outgoingQpt)) {
                DIE("sendto returned bad length (%Zd) while "
                            "sending to ip: [%s] port: [%d]", len,
                    inet_ntoa(sin->sin_addr), NTOHS(sin->sin_port));
            } else {
                haveSent = true;
            }
        }

        struct sockaddr_in recvSin;
        socklen_t sinlen = sizeof(recvSin);
        ssize_t len = recvfrom(clientSetupSocket, incomingQpt,
                               sizeof(*incomingQpt), 0,
                               reinterpret_cast<sockaddr *>(&recvSin), &sinlen);

        if (len == -1) {
            if (errno != EINTR && errno != EAGAIN) {
                DIE("recvfrom returned error %d: %s",
                    errno, strerror(errno));
            }
        } else if (len != sizeof(*incomingQpt)) {
            DIE("recvfrom returned bad length (%Zd) while "
                        "receiving from ip: [%s] port: [%d]", len,
                inet_ntoa(recvSin.sin_addr), NTOHS(recvSin.sin_port));
        } else {
            if (outgoingQpt->getNonce() == incomingQpt->getNonce())
                return true;
            LOG(INFO, "bad nonce from %s (expected 0x%016lx, "
                    "got 0x%016lx, port %d); ignoring",
                inet_ntoa(sin->sin_addr), outgoingQpt->getNonce(),
                incomingQpt->getNonce(), clientPort);
        }

        if (rdtsc() - startTime > 3lu * 50 * 1000 * 1000 * 1000)
            return false;
    }
}

QueuePair*
clientTrySetupQueuePair(const char* server, uint16_t port)
{
    IpAddress address{server, static_cast<uint16_t>(port)};
    sockaddr_in *sin = reinterpret_cast<sockaddr_in *>(&address.address);

    // Create a new QueuePair and send its parameters to the server so it
    // can create its qp and reply with its parameters.
    std::unique_ptr<QueuePair> qp{new QueuePair(IBV_QPT_RC,
                                                clientSrq,
                                                commonTxCq, clientRxCq,
                                                MAX_TX_QUEUE_DEPTH,
                                                MAX_SHARED_RX_QUEUE_DEPTH)};
    qp->setPeerName(server);

    uint32_t i;
    uint64_t nonce = rand();
    LOG(DEBUG, "starting to connect to %s via local port %d, nonce 0x%lx",
        inet_ntoa(sin->sin_addr), clientPort, nonce);

    for (i = 0; i < QP_EXCHANGE_MAX_TIMEOUTS; i++) {
        QueuePairTuple outgoingQpt(uintptr_t(logMemoryRegion->addr),
                                   logMemoryRegion->rkey,
                                   uint16_t(lid),
                                   qp->getLocalQpNumber(),
                                   qp->getInitialPsn(), nonce);
        QueuePairTuple incomingQpt;

        bool gotResponse = clientTryExchangeQueuePairs(sin, &outgoingQpt,
                                                       &incomingQpt);

        if (!gotResponse) {
            // To avoid log clutter, only print a log message for the
            // first retry.
            if (i == 0) {
                LOG(WARNING, "timed out waiting for response; retrying");
            }
            if (i > 1000) {
                DIE("Couldn't establish queue pair with %s:%u", server, port);
            }
            continue;
        }
        LOG(DEBUG, "connected to %s via local port %d",
            inet_ntoa(sin->sin_addr), clientPort);

        // plumb up our queue pair with the server's parameters.
        qp->plumb(&incomingQpt);
        LOG(DEBUG, "New queue pair nonce 0x%lx, remote log VA 0x%lx, "
                "remote log rkey 0x%x",
            incomingQpt.getNonce(), incomingQpt.getLogVA(),
            incomingQpt.getRkey());
        remoteLogVA = incomingQpt.getLogVA();
        remoteLogRkey = incomingQpt.getRkey();
        break;
    }

    if (i == QP_EXCHANGE_MAX_TIMEOUTS) {
        LOG(WARNING, "failed to exchange with server within allotted "
                "(sent request %u times, local port %d)",
            QP_EXCHANGE_MAX_TIMEOUTS,
            clientPort);
        DIE("failed to connect to host");
    }

    return qp.release();
}

struct Header
{
    uint32_t len;
    char message[0];
};

void
handleMessage(BufferDescriptor* bd, uint32_t len)
{
    //Header& header = *reinterpret_cast<Header*>(bd->buffer);
    //LOG(ERROR, "Handling a message of length %u!", len);
    //LOG(ERROR, "Message was %s!", header.message);
}

int
poll()
{
    static const int MAX_COMPLETIONS = 10;
    ibv_wc wc[MAX_COMPLETIONS];
    int foundWork = 0;

    // Next, check for incoming RPC requests (assuming that we are a server).
    if (serverSetupSocket >= 0) {
        int numRequests = ibv_poll_cq(serverRxCq, MAX_COMPLETIONS, wc);
        /*
        if ((t->numFreeServerSrqBuffers - numRequests) == 0) {
            // The receive buffer queue has run completely dry. This is bad
            // for performance: if any requests arrive while the queue is empty,
            // Infiniband imposes a long wait period (milliseconds?) before
            // the caller retries.
            RAMCLOUD_CLOG(WARNING, "Infiniband receive buffers ran out "
                    "(%d new requests arrived); could cause significant "
                    "delays", numRequests);
        }
        */
        for (int i = 0; i < numRequests; i++) {
            foundWork = 1;
            ibv_wc* request = &wc[i];

            BufferDescriptor* bd =
                reinterpret_cast<BufferDescriptor*>(request->wr_id);
            //if (request->byte_len < 1000)
                //prefetch(bd->buffer, request->byte_len);

            if (request->status != IBV_WC_SUCCESS) {
                LOG(ERROR, "failed to receive rpc!");
                postSrqReceiveAndKickTransmit(serverSrq, bd);
                goto done;
            }

            postSrqReceiveAndKickTransmit(serverSrq, bd);
            /*
            // It's very important that we don't let the receive buffer
            // queue get completely empty (if this happens, Infiniband
            // won't retry until after a long delay), so when the queue
            // starts running low we copy incoming packets in order to
            // return the buffers immediately. The constant below was
            // originally 2, but that turned out not to be sufficient.
            // Measurements of the YCSB benchmarks in 7/2015 suggest that
            // a value of 4 is (barely) okay, but we now use 8 to provide a
            // larger margin of safety, even if a burst of packets arrives.
            if (t->numFreeServerSrqBuffers < 8) {
                r->requestPayload.appendCopy(bd->buffer + sizeof(header), len);
                t->postSrqReceiveAndKickTransmit(t->serverSrq, bd);
            } else {
                // Let the request use the NIC's buffer directly in order
                // to avoid copying; it will be returned when the request
                // buffer is destroyed.
                PayloadChunk::appendToBuffer(&r->requestPayload,
                    bd->buffer + sizeof32(header),
                    len, t, t->serverSrq, bd);
            }
            */

            //port->portAlarm.requestArrived(); // Restarts the port watchdog
            //r->rpcServiceTime.start();
            handleMessage(bd, request->byte_len);
        }
    }

  done:
    // Retrieve transmission buffers from the NIC once they have been
    // sent. It's done here in the hopes that it will happen when we
    // have nothing else to do, so it's effectively free.  It's much
    // more efficient if we can reclaim several buffers at once, so wait
    // until buffers are running low before trying to reclaim.  This
    // optimization improves the throughput of "clusterperf readThroughput"
    // by about 5% (as of 7/2015).
    if (freeTxBuffers[0].size() < 3) {
        reapTxBuffers();
        if (freeTxBuffers[0].size() >= 3) {
            foundWork = 1;
        }
    }
    return foundWork;
}

void registerMemory(void* base, size_t bytes)
{
    assert(logMemoryRegion == nullptr);

    logMemoryRegion = ibv_reg_mr(pd, base, bytes,
        IBV_ACCESS_REMOTE_WRITE |
        IBV_ACCESS_REMOTE_READ |
        IBV_ACCESS_LOCAL_WRITE);
    if (logMemoryRegion == NULL) {
        DIE("ibv_reg_mr failed to register %Zd bytes at %p", bytes, base);
    }
    logMemoryBase = reinterpret_cast<uintptr_t>(base);
    logMemoryBytes = bytes;
    LOG(NOTICE, "Registered %Zd bytes at %p", bytes, base);
}

void pinTo(size_t i)
{
   cpu_set_t cpuset;
   CPU_ZERO(&cpuset);
   CPU_SET(i, &cpuset);
   int r = pthread_setaffinity_np(pthread_self(),
                                  sizeof(cpu_set_t), &cpuset);
   assert(r == 0);
}

/**
 * Runs a benchmark. Makes life easier by spawning threads and hoooking them
 * up to thread-specific stats and state, synchronizing them on start/stop,
 * etc.
 */
class Benchmark {
  public:

    class ThreadState {
      public:
        ThreadState(QueuePair* qp)
          : qp{qp}
          , chunks{}
        {}

        std::unique_ptr<QueuePair> qp;
        std::vector<Chunk> chunks;
    };

    Benchmark(const std::vector<std::string>& servers,
              size_t nChunks,
              size_t chunkSize,
              size_t nDeltas,
              size_t deltaSize,
              bool doZeroCopy,
              double seconds,
              double warmupSeconds)
      : servers{servers}
      , nChunks{nChunks}
      , chunkSize{chunkSize}
      , nDeltas{nDeltas}
      , deltaSize{deltaSize}
      , doZeroCopy{doZeroCopy}
      , seconds{seconds}
      , warmupSeconds{warmupSeconds}
      , threads{}
      , threadStates{}
      , nReady{}
      , go{}
    {
    }

    /// Start threads and run the benchmark.
    void start() {
        LOG(INFO, "Clients establishing qpairs");
        for (size_t i = 0; i < servers.size(); ++i) {
            threadStates.emplace_back(clientTrySetupQueuePair(servers.at(i).c_str(),
                                                              PORT));
            threads.emplace_back(std::thread{&Benchmark::entry,
                                 this, i, &threadStates.back()});

        }
        LOG(INFO, "All Clients established qpairs");

        while (nReady != servers.size())
            std::this_thread::yield();

        go = true;

        for (auto& thread : threads)
            thread.join();

        for (size_t i = 0; i < servers.size(); ++i) {
            while (freeTxBuffers[i].size() < MAX_TX_QUEUE_DEPTH_PER_THREAD)
                reapTxBuffers();
        }
    }

    void entry(size_t threadNum, ThreadState* threadState) {
        LOG(DEBUG, "Running benchmark with %lu clients %lu chunksPerMessage "
                "%lu chunkSize %lu deltas %lu deltaSize",
                servers.size(), nChunks, chunkSize,
                nDeltas, deltaSize);

        pinTo(threadNum);
        PRNG prng{threadNum};
        threadState->chunks.resize(nDeltas + nChunks);
        uint32_t start = 0;

        bool preTouchChunks = false;
        bool runSimulateWorkload = false;

        std::unordered_map<int, uintptr_t> ramCloudHashTable;

        ramCloudHashTable.rehash(logSize/chunkSize);
	
        PRNG prng{threadNum};

        for (size_t i = 0; i < nDeltas; ++i) {
            start = prng.generate();
            start = start % (logSize - deltaSize);
            threadState->chunks[i].p = (void*)(logMemoryBase + start);
            threadState->chunks[i].len = deltaSize;

            if (preTouchChunks == true) {
                memset(threadState->chunks[i].p, nDeltas + deltaSize,
                    threadState->chunks[i].len);
            }
        }

        for (size_t i = 0; i < nChunks; ++i) {
            start = prng.generate();
            start = start % (logSize - chunkSize);
            threadState->chunks[i].p = (void*)(logMemoryBase + start);
            threadState->chunks[i].len = chunkSize;

            if (preTouchChunks == true) {
                memset(threadState->chunks[i].p, nChunks + chunkSize,
                    threadState->chunks[i].len);
            }

            if (runSimulateWorkload == true) {
                ramCloudHashTable[i] = logMemoryBase + start;
            }
        }
// Costly filling up of Zipfian vectors
#if defined ZIPFIAN_SETUP && ZIPFIAN_SETUP == 1 
	LOG(INFO, "Generating Zipfian addresses for thread:%lu",threadNum+1);
	uint32_t chunkOffsets = (logSize/chunkSize) - 1;
	uint32_t deltaOffsets = ((deltaSize==0)?0:(logSize/deltaSize) - 1);
	ZipfianGenerator chunksGenerator(chunkOffsets, THETA, threadNum);
	ZipfianGenerator deltasGenerator(deltaOffsets, THETA, threadNum);
	for (uint32_t i=0;i<MAX_ZIPFIAN_ADDRESSES;i++){
		zipfianChunkAddresses[threadNum].push_back(chunksGenerator.nextNumber());
		zipfianDeltaAddresses[threadNum].push_back(deltasGenerator.nextNumber());
	}
	LOG(INFO, "Generated Zipfian addresses for thread:%lu",threadNum+1);
	LOG(INFO, "Writing vector to files");
	std::stringstream outputfile;
	outputfile<<"vector_thread_"<<threadNum+1<<".txt";
        write_vector_to_file(&zipfianChunkAddresses[threadNum], outputfile.str().c_str());
#endif 
        // If this is a migration test, perform a few operations (reads and
        // writes) before proceeding.
        if (deltaSize == 0 && runSimulateWorkload == true) {
            simulateWorkload(threadState, ramCloudHashTable);
        }

        nReady++;
        while (!go);
        // warmup
        //run(threadState, warmupSeconds, threadNum);

        threadMetrics.reset();

        uint64_t cycles = 0;
        {
            CycleCounter<> counter{&cycles};
            run(threadState, seconds, threadNum);
        }

        threadMetrics.dump(!doZeroCopy, threadState->qp->getPeerName(),
                           cycles, nChunks, chunkSize, nDeltas, deltaSize,
                           seconds, warmupSeconds);

        LOG(ERROR, "Chunks tx zero-copy[%s]: %lu / %lu",
            threadState->qp->getPeerName(),
            threadMetrics.chunksTransmittedZeroCopy,
            threadMetrics.chunksTransmitted);

        if (doZeroCopy &&
            threadMetrics.chunksTransmittedZeroCopy !=
                threadMetrics.chunksTransmitted)
        {
            DIE("Not all chunks were zero copied in zero copy mode");
        }
    }

    void simulateWorkload(ThreadState* threadState,
        std::unordered_map<int, uintptr_t> ramCloudHashTable) {
        double theta = 0.5;
        int writePercent = 100;
        int numOperations = 100;
        ZipfianGenerator generator(nChunks, theta);
        srand(time(NULL));

        for (int i = 0; i < numOperations; i++) {
            uint64_t lookupRecord = generator.nextNumber();
            uintptr_t recordAddress = 0;

            if (rand() % 100 < 100 - writePercent) {
                // Perform a hash table lookup only.
                recordAddress = ramCloudHashTable[lookupRecord];
            } else {
                recordAddress = ramCloudHashTable[lookupRecord];
                memset((void*)recordAddress, i + recordAddress, chunkSize);
            }
        }
    }

    void run(ThreadState* threadState, double seconds, size_t threadNum) {
        LOG(INFO, "In run %lu", threadNum);
	const uint64_t cyclesToRun = Cycles::fromSeconds(seconds);
        //bool refreshChunks = false;
        uint32_t start = 0;
	PRNG prng{threadNum};
#if defined ZIPFIAN_SETUP && ZIPFIAN_SETUP == 1
	uint32_t zipfChunkOffset = 0;
	uint32_t zipfDeltaOffset = 0;
#endif
        const uint64_t startTsc = Cycles::rdtsc();
        while (true) {

#if defined ZIPFIAN_SETUP && ZIPFIAN_SETUP == 1
	       for (size_t i = 0; i < nDeltas; ++i) {
                  start = zipfianDeltaAddresses[threadNum][zipfDeltaOffset];
		  ++zipfDeltaOffset;
		  if (zipfDeltaOffset>=MAX_ZIPFIAN_ADDRESSES){
		  zipfDeltaOffset = 0;
		  }
                  threadState->chunks[i].p = (void*)(logMemoryBase + (start * deltaSize));
                  threadState->chunks[i].len = deltaSize;
                }
                for (size_t i = 0; i < nChunks; i++) {
		  start = zipfianChunkAddresses[threadNum][zipfChunkOffset];
		  ++zipfChunkOffset;
		  if (zipfChunkOffset>=MAX_ZIPFIAN_ADDRESSES){
		  zipfChunkOffset = 0;
		  }
	          threadState->chunks[i].p = (void*)(logMemoryBase + (start * chunkSize));
                  threadState->chunks[i].len = chunkSize;
                }
#else
                for (size_t i = 0; i < nDeltas; ++i) {
                    start = prng.generate();
                    start = start % (logSize - deltaSize);
                    threadState->chunks[i].p = (void*)(logMemoryBase + start);
                    threadState->chunks[i].len = deltaSize;
                }

                for (size_t i = 0; i < nChunks; ++i) {
                    start = prng.generate();
                    start = start % (logSize - chunkSize);
                    threadState->chunks[i].p = (void*)(logMemoryBase + start);
                    threadState->chunks[i].len = chunkSize;
                }
#endif
            //sendZeroCopy(&threadState->chunks[0], nChunks, nChunks * chunkSize,
            //             threadState->qp.get(), doZeroCopy, threadNum);
            if (doZeroCopy) {
                sendStrictZeroCopy(&threadState->chunks[0],
                                   nDeltas + nChunks,
                                   nDeltas * deltaSize + nChunks * chunkSize,
                                   threadState->qp.get(),
                                   threadNum);
            } else {
                sendStrictCopy(&threadState->chunks[0],
                               nDeltas + nChunks,
                               nDeltas * deltaSize + nChunks * chunkSize,
                               threadState->qp.get(),
                               threadNum);
            }
            if (Cycles::rdtsc() - startTsc > cyclesToRun)
                break;
        }
    }

  private:
    const std::vector<std::string> servers;

    const size_t nChunks;
    const size_t chunkSize;

    const size_t nDeltas;
    const size_t deltaSize;

    const bool doZeroCopy;

    const double seconds;
    const double warmupSeconds;

    std::deque<std::thread> threads;
    std::deque<ThreadState> threadStates;

    std::atomic<uint64_t> nReady;
    std::atomic<bool> go;
};

static const char USAGE[] =
R"(ibv-bench.

    Usage:
      ibv-bench server <hostname> [--hugePages] [--runZeroCopyOnly] [--runCopyOutOnly] [--runDeltasOnly]
      ibv-bench client <hostname>... [--hugePages] [--runZeroCopyOnly] [--runCopyOutOnly] [--runDeltasOnly] [--minChunkSize=SIZE] [--maxChunkSize=SIZE] [--minChunksPerMessage=CHUNKS] [--maxChunksPerMessage=CHUNKS] [--seconds=SECONDS] [--warmup=SECONDS]
      ibv-bench (-h | --help)

    Options:
      -h --help                     Show this screen
      --hugePages                   Use huge pages
      --runZeroCopyOnly             Don't run Copy Out mode
      --runCopyOutOnly              Don't run Zero Copy mode
      --runDeltasOnly               Only Run Delta Experiments
      --minChunkSize=SIZE           Smallest size of individual objects [default: 1]
      --maxChunkSize=SIZE           Largest size of individual objects [default: 1024]
      --minChunksPerMessage=CHUNKS  Min Number of objects to transmit per send [default: 1]
      --maxChunksPerMessage=CHUNKS  Max number of objects to transmit per send [default: 32]
      --seconds=SECONDS             Number of seconds to run per chunk count/size pair [default: 10]
      --warmup=SECONDS              Number of seconds to run per chunk count/size pair before starting measurment [default: 5]
)";

int main(int argc, const char** argv)
{
    Cycles::init();

    std::map<std::string, docopt::value> args
        = docopt::docopt(USAGE,
                         { argv + 1, argv + argc },
                         true,               // show help if requested
                         "ibv-bench 0.2");  // version string

    // Dump command line args for debugging.
    for (auto const& arg : args)
        std::cerr << arg.first <<  " " << arg.second << std::endl;

    const bool isServer = bool(args["server"]) && args["server"].asBool();
    const bool useHugePages = bool(args["--hugePages"]) &&
                              args["--hugePages"].asBool();
    bool onlyZeroCopy =  false;
    onlyZeroCopy = (args["--runZeroCopyOnly"]) &&
                    args["--runZeroCopyOnly"].asBool();
    bool onlyCopyOut = false;
    onlyCopyOut =  (args["--runCopyOutOnly"]) &&
                    args["--runCopyOutOnly"].asBool();
    bool onlyDeltas = false;
    onlyDeltas = (args["--runDeltasOnly"]) &&
                    args["--runDeltasOnly"].asBool();
    if (onlyDeltas && (onlyZeroCopy || onlyCopyOut)){
      LOG(ERROR, "When using --runDeltasOnly, can't use other restrictive modes");
    }
    if (onlyZeroCopy && onlyCopyOut){
        LOG(ERROR, "Can't use both --runZeroCopyOnly and --runCopyOutOnly");
        exit(1);
    }
    const size_t minChunkSize = args["--minChunkSize"].asLong();
    const size_t maxChunkSize = args["--maxChunkSize"].asLong();
    const size_t minChunksPerMessage = args["--minChunksPerMessage"].asLong();
    const size_t maxChunksPerMessage = args["--maxChunksPerMessage"].asLong();

    const double seconds = double(args["--seconds"].asLong());
    const double warmupSeconds = double(args["--warmup"].asLong());

    assert(minChunkSize > 0);
    assert(maxChunkSize <= 1024);
    assert(minChunksPerMessage >= 0);
    assert(maxChunksPerMessage <= 1024);
    assert(seconds > 0.);
    assert(warmupSeconds >= 0.);

    std::vector<std::string> hostNames = args["<hostname>"].asStringList();

    LOG(INFO, "Running as %s", isServer ? "server" : "client");
    for (const auto& hostName : hostNames)
        LOG(INFO, " > %s", hostName.c_str());
    LOG(INFO, "Number of client server connections: %lu", hostNames.size());

    setup(isServer ? hostNames.at(0).c_str() : nullptr,
        isServer ? 1 : hostNames.size());
    // Allocate a GB and register it with the HCA.
    LOG(INFO, "Registering log memory");
    void* base = nullptr;

    Tub<LargeBlockOfMemory<>> largeBlockOfMemory{};
    if (useHugePages) {
        largeBlockOfMemory.construct("/dev/hugetlbfs/ibv-bench-log", logSize);
        base = largeBlockOfMemory->get();
    } else {
        base = xmemalign(4096, logSize);
    }

    registerMemory(base, logSize);

    pinAllMemory();

    if (isServer) {
        LOG(INFO, "Running server event loop");
        while (true) {
            poll();
        }
    } else {
        LOG(INFO, "Running client benchmarks");

        ThreadMetrics::dumpHeader();
        if(!onlyDeltas)
        {
                for (size_t chunkSize = minChunkSize;
                    chunkSize <= maxChunkSize;
                    chunkSize *= 2)
                // const std::vector<size_t> sizes{128, 1024};
                // for (size_t chunkSize : sizes)
                {
                    for (size_t nChunks = minChunksPerMessage;
                         nChunks <= maxChunksPerMessage && nChunks <= 32;
                         ++nChunks)
                    {  
                        if(!onlyCopyOut) 
                        {
                            LOG(INFO, "Running Zero Copy on #chunks: %lu size: %lu",
                                    nChunks, chunkSize);
                            Benchmark bench{hostNames, nChunks, chunkSize, 0, 0,
                                            true /* 0-copy */, seconds, warmupSeconds};
                            bench.start();
                        }
                        if(!onlyZeroCopy)
                        {
                            LOG(INFO, "Running Copy-All on #chunks: %lu size: %lu",
                                    nChunks, chunkSize);
                            Benchmark bench{hostNames, nChunks, chunkSize, 0, 0,
                                            false /* no 0-copy */, seconds, warmupSeconds};
                            bench.start();
                        }
                    }
                    // Power of 2 number of chunks
                    // for (size_t nChunks = 64; nChunks <= maxChunksPerMessage; nChunks *=2) {
                    //     LOG(INFO, "Running Copy-All on #chunks: %lu size: %lu",
                    //             nChunks, chunkSize);
                    //     Benchmark bench{hostNames, nChunks, chunkSize, 0, 0,
                    //                     false /* doZeroCopy */, seconds, warmupSeconds};
                    //     bench.start();
                    // }
                }
        } else {

        // Delta record tests. For these we use the command line args for
        // number of chunks for the deltas instead, and we just included a 16
        // KB base page in each trasmission no matter what.  It's all zero-copy
        // too.
        for (size_t deltaSize = minChunkSize;
            deltaSize <= maxChunkSize;
            deltaSize *= 2)
                {
                    for (size_t nDeltas = minChunksPerMessage - 1; nDeltas <= (maxChunksPerMessage - 1); ++nDeltas)
                    {
                        {
                            LOG(INFO, "Running Deltas on #deltas: %lu size: %lu",
                                    nDeltas, deltaSize);
                            Benchmark bench{hostNames, 1, 16384, nDeltas, deltaSize,
                                            true/*always  0-copy*/ , seconds, warmupSeconds};
                            bench.start();
                        }
                    }
                }
    }
    }
    return 0;
}

