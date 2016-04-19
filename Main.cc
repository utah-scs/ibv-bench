#define _BSD_SOURCE 1
#include <cstdio>
#include <fcntl.h>
#include <cerrno>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <cinttypes>
#include <cassert>

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

#include "docopt.h"

#include "Tub.h"
#include "IpAddress.h"
#include "LargeBlockOfMemory.h"
#include "CycleCounter.h"
#include "SpinLock.h"

static const int PORT = 12240;

static const uint32_t MAX_INLINE_DATA = 400;
static const uint32_t MAX_SHARED_RX_QUEUE_DEPTH = 32;

// Since we always use at most 1 SGE per receive request, there is no need
// to set this parameter any higher. In fact, larger values for this
// parameter result in increased descriptor size, which means that the
// Infiniband controller needs to fetch more data from host memory,
// which results in a higher number of on-controller cache misses.
static const uint32_t MAX_SHARED_RX_SGE_COUNT = 1;
static const uint32_t MAX_TX_QUEUE_DEPTH = 16;

// With 64 KB seglets 1 MB is fractured into 16 or 17 pieces, plus we
// need an entry for the headers.
// 31 seems to be the limit on this. Not sure why, because the qp's are
// initialized with a max sge limit of 1 anyway.
uint32_t MAX_TX_SGE_COUNT = 26;
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
int*         clientSetupSocket; // UDP socket for outgoing setup requests
int*         clientPort;        // Port number associated with
RAMCloud::SpinLock     mutex("trasmitbufferlock"); //To synchronize getTransmitBuffer calls
uint64_t*    postSendCycles;     // Cycle counter for post send calls per client;
uint64_t*    getTrasmitCycles;   // Cycle counter for getting transmit buffers per client;

ibv_context* ctxt;           // device context of the HCA to use
ibv_pd* pd;

struct BufferDescriptor {
    char *          buffer;         // buf of ``bytes'' length
    uint32_t        bytes;          // length of buffer in bytes
    uint32_t        messageBytes;   // byte length of message in the buffer
    ibv_mr *        mr;             // memory region of the buffer

    BufferDescriptor(char *buffer, uint32_t bytes, ibv_mr *mr)
        : buffer(buffer), bytes(bytes), messageBytes(0), mr(mr) {}
    BufferDescriptor()
        : buffer(NULL), bytes(0), messageBytes(0), mr(NULL) {}
};

void* rxBase;
BufferDescriptor rxDescriptors[MAX_SHARED_RX_QUEUE_DEPTH * 2];

void* txBase;
BufferDescriptor txDescriptors[MAX_TX_QUEUE_DEPTH];

std::vector<BufferDescriptor*> freeTxBuffers{};

uint8_t numClients = 1;
std::vector<std::string> hostNames{};

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
    qpia.cap.max_send_sge = 32;         // max send scatter-gather elements
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

std::vector<QueuePair*> QueuePairs{};


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
              uint32_t bufferCount)
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
        new(&descriptors[i]) BufferDescriptor(buffer, bufferSize, mr);
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
    /*
    fd_set rfds;

    FD_ZERO(&rfds);
    FD_SET(serverSetupSocket, &rfds);

    timeval tv{};

    while (true) {
        tv.tv_sec = 1;
        int r = select(1, &rfds, NULL, NULL, &tv);
        if (r == -1) {
            DIE("Error on select");
        } else if (r > 0) {
            LOG(NOTICE, "Handling a socket event");
            handleFileEvent();
        } else {
            LOG(NOTICE, "select timed out");
        }
    }
    */
}

bool setup(bool isServer)
{
    for(int i=0; i < numClients;i++) {
        clientSetupSocket[i] = socket(PF_INET, SOCK_DGRAM, 0);
        if (clientSetupSocket[i] == -1) {
            LOG(ERROR, "failed to create client socket: %s", strerror(errno));
            exit(-1);
        }
        sockaddr_in socketAddress;
        socketAddress.sin_family = AF_INET;
        socketAddress.sin_addr.s_addr = htonl(INADDR_ANY);
        socketAddress.sin_port = 0;
        if (bind(clientSetupSocket[i],
                 (sockaddr * )(&socketAddress),
                 sizeof(socketAddress)) == -1) {
            close(clientSetupSocket[i]);
            LOG(WARNING, "couldn't bind port for clientSetupSocket[%d]: %s",
                i,strerror(errno));
            exit(-1);
        }

        if (!setNonBlocking(clientSetupSocket[i])) {
            close(clientSetupSocket[i]);
            exit(-1);
        }

        socklen_t socketAddressLength = sizeof(socketAddress);
        if (getsockname(clientSetupSocket[i],
                        (sockaddr * )(&socketAddress),
                        &socketAddressLength) != 0) {
            close(clientSetupSocket[i]);
            LOG(ERROR, "couldn't get port for clientSetupSocket: %s",
                strerror(errno));
            exit(-1);
        }
        clientPort[i] = ntohs(socketAddress.sin_port);
        LOG(INFO, "Port[%d]:%d",i,clientPort[i]);

    }
    // If this is a server, create a server setup socket and bind it.
    if (isServer) {
        sockaddr address;
        getIpAddress(hostNames[0].c_str(), PORT, &address);

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

        LOG(NOTICE, "InfRc listening on UDP: %s:%d", hostNames[0].c_str(), PORT);

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
                  uint32_t(MAX_SHARED_RX_QUEUE_DEPTH * 2));
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
                  bufferSize, uint32_t(MAX_TX_QUEUE_DEPTH));
    for (auto& bd : txDescriptors)
        freeTxBuffers.push_back(&bd);

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

        freeTxBuffers.push_back(bd);

        if (retArray[i].status != IBV_WC_SUCCESS) {
            LOG(ERROR, "Transmit failed for buffer %lu: %s",
                reinterpret_cast<uint64_t>(bd),
                wcStatusToString(retArray[i].status));
            ++txFailures;
        }
    }

    return n;
}

BufferDescriptor*
getTransmitBuffer(uint64_t tid)
{
    // if we've drained our free tx buffer pool, we must wait.
    CycleCounter<> trasmitCounter{&getTrasmitCycles[tid]};
    std::lock_guard<RAMCloud::SpinLock> lock(mutex);
    while (freeTxBuffers.empty()) {
        reapTxBuffers();

        if (freeTxBuffers.empty()) {
            // We are temporarily out of buffers. Time how long it takes
            // before a transmit buffer becomes available again (a long
            // time could indicate deadlock); in the normal case this code
            // is not invoked.
            uint64_t start = rdtsc();
            while (freeTxBuffers.empty())
                reapTxBuffers();
            uint64_t wait = rdtsc() - start;
            if (wait > 3lu * 5 * 1000 * 1000)  {
                LOG(WARNING, "Long delay waiting for transmit buffers "
                        "(%lu ticks); deadlock or target crashed?", wait);
            }
        }
    }

    BufferDescriptor* bd = freeTxBuffers.back();
    freeTxBuffers.pop_back();
    return bd;
}

struct Chunk {
    void* p;
    uint32_t len;
};

uint64_t chunksTransmitted = 0;
uint64_t chunksTransmittedZeroCopy = 0;

void
sendZeroCopy(Chunk* message, uint32_t chunkCount, uint32_t messageLen, QueuePair* qp, bool allowZeroCopy)
{
    auto it = std::find(QueuePairs.begin(), QueuePairs.end(), qp);
    auto tid = std::distance(QueuePairs.begin(), it);
    uint32_t lastChunkIndex = chunkCount - 1;
    ibv_sge isge[MAX_TX_SGE_COUNT];

    uint32_t chunksUsed = 0;
    uint32_t sgesUsed = 0;
    BufferDescriptor* bd = getTransmitBuffer(tid);
    bd->messageBytes = messageLen;

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
        bool inBounds = addr >= logMemoryBase &&
            (addr + chunk.len) <= (logMemoryBase + logMemoryBytes);
        bool stillRoom = (sgesUsed < MAX_TX_SGE_COUNT - 1 ||
                          ((chunksUsed == lastChunkIndex) &&
                           (unaddedStart == unaddedEnd)));
        if (allowZeroCopy && stillRoom && inBounds &&
            chunk.len > MIN_CHUNK_ZERO_COPY_LEN)
        {
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
            memcpy(unaddedEnd, chunk.p, chunk.len);
            unaddedEnd += chunk.len;
        }
        ++chunksUsed;
    }
    if (unaddedStart != unaddedEnd) {
        isge[sgesUsed] = {
            reinterpret_cast<uint64_t>(unaddedStart),
            uint32_t(unaddedEnd - unaddedStart),
            bd->mr->lkey
        };
        ++sgesUsed;
        unaddedStart = unaddedEnd;
    }

    ibv_send_wr txWorkRequest;

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

    chunksTransmitted += chunksUsed;
    chunksTransmittedZeroCopy += chunksZeroCopied;

    ibv_send_wr* badTxWorkRequest;
    
    CycleCounter<> postSendCtr{};
    if (ibv_post_send(qp->qp, &txWorkRequest, &badTxWorkRequest)) {
        DIE("ibv_post_send failed");
    }
    postSendCycles[tid]+=postSendCtr.stop();
}

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

// Returns 0 on success or ENOMEM if send queue is full.
int
rdma(ibv_wr_opcode opcode,
     QueuePair* qp, BufferDescriptor *bd, uint32_t bytes,
     uint64_t remoteVA, uint32_t rkey)
{
    assert(bytes <= bd->bytes);

    ibv_sge isge = {
        reinterpret_cast<uint64_t>(bd->buffer),
        bytes,
        bd->mr->lkey
    };
    ibv_send_wr txWorkRequest;

    memset(&txWorkRequest, 0, sizeof(txWorkRequest));
    txWorkRequest.wr_id = reinterpret_cast<uint64_t>(bd);// stash descriptor ptr

    txWorkRequest.next = NULL;
    txWorkRequest.sg_list = &isge;
    txWorkRequest.num_sge = 1;

    txWorkRequest.opcode = opcode;

    //txWorkRequest.send_flags = IBV_SEND_SIGNALED | IBV_SEND_INLINE;
    txWorkRequest.send_flags = IBV_SEND_SIGNALED;
    // This will deadlock, since we won't see CQ entries to reap buffers.
    //txWorkRequest.send_flags = 0;

    txWorkRequest.wr.rdma.remote_addr = remoteVA;
    txWorkRequest.wr.rdma.rkey = rkey;


    ibv_send_wr *bad_txWorkRequest;
    int r = ibv_post_send(qp->qp, &txWorkRequest, &bad_txWorkRequest);

    // ENOMEM is returned when send queue is full.
    if (r == ENOMEM)
        return r;

    if (r) {
        LOG(ERROR, "ibv_post_send failed errno %d %s", errno, strerror(errno));
        DIE("ibv_post_send failed for RDMA Read of 0x%lx with rkey 0x%x",
                remoteVA, rkey);
    }

    //LOG(ERROR, "Posted RDMA read of %u bytes with bd %lu (capacity %u)",
    //        bytes, reinterpret_cast<uint64_t>(bd), bd->bytes);

    return 0;
}

int
rdmaRead(QueuePair* qp, BufferDescriptor *bd, uint32_t bytes,
         uint64_t remoteVA, uint32_t rkey)
{
    return rdma(IBV_WR_RDMA_READ, qp, bd, bytes, remoteVA, rkey);
}

int
rdmaRead2(QueuePair* qp, BufferDescriptor* bd, uint32_t bytesPerVA,
          uint64_t* remoteVAs, uint32_t remoteVACount, uint32_t rkey)
{
    assert(bytesPerVA * remoteVACount <= bd->bytes);

    ibv_send_wr txWorkRequests[remoteVACount];
    ibv_sge isge[remoteVACount];

    for (uint32_t i = 0 ; i < remoteVACount; ++i) {
        LOG(INFO, "%d bytesPerVA %u remoteVA %lu %u", i, bytesPerVA, remoteVAs[i], rkey);
        isge[i] = {
            reinterpret_cast<uint64_t>(bd->buffer) + (bytesPerVA * i),
            bytesPerVA,
            bd->mr->lkey
        };
        ibv_send_wr& txWorkRequest = txWorkRequests[i];

        memset(&txWorkRequest, 0, sizeof(txWorkRequest));
        txWorkRequest.wr_id = reinterpret_cast<uint64_t>(bd);// stash descriptor ptr
        txWorkRequest.next = i == remoteVACount ? NULL : &txWorkRequests[i + 1];
        txWorkRequest.sg_list = &isge[i];
        txWorkRequest.num_sge = 1;
        txWorkRequest.opcode = IBV_WR_RDMA_READ;
        txWorkRequest.send_flags = IBV_SEND_SIGNALED;

        txWorkRequest.wr.rdma.remote_addr = remoteVAs[i];
        txWorkRequest.wr.rdma.rkey = rkey;
    }

    for (uint32_t i = 0 ; i < remoteVACount; ++i) {
        ibv_send_wr& wr = txWorkRequests[i];
        LOG(INFO,
            "wr[%d]:\n"
            "wr_id: %lu\n"
            "next: %p\n"
            "sg_list: %p\n"
            "num_sge: %u\n"
            "opcode: %d\n"
            "send_flags: %d\n"
            "remote_addr: %lu\n"
            "rkey: %u\n",
            i, wr.wr_id, wr.next, wr.sg_list, wr.num_sge, wr.opcode,
            wr.send_flags, wr.wr.rdma.remote_addr, wr.wr.rdma.rkey);

    }

    ibv_send_wr *bad_txWorkRequest;
    int r = ibv_post_send(qp->qp, &txWorkRequests[0], &bad_txWorkRequest);

    // ENOMEM is returned when send queue is full.
    if (r == ENOMEM)
        return r;

    if (r) {
        LOG(ERROR, "ibv_post_send failed errno %d %s", errno, strerror(errno));
        DIE("ibv_post_send failed for RDMA Read of 0x%lx with rkey 0x%x",
                remoteVAs[0], rkey);
    }

    //LOG(ERROR, "Posted RDMA read of %u bytes with bd %lu (capacity %u)",
    //        bytes, reinterpret_cast<uint64_t>(bd), bd->bytes);

    return 0;
}

int
rdmaWrite(QueuePair* qp, Chunk* message, uint32_t chunkCount,
         uint32_t messageLen, uint64_t remoteVA, uint32_t rkey)
{
    if (chunkCount > MAX_TX_SGE_COUNT)
        DIE("Tried to transmit too many chunks in a single message.");

    ibv_sge isge[chunkCount];

    for (uint32_t i = 0 ; i < chunkCount; ++i) {
        Chunk& chunk = message[i];

        const uintptr_t addr = reinterpret_cast<const uintptr_t>(chunk.p);
        bool inBounds = addr >= logMemoryBase &&
            (addr + chunk.len) <= (logMemoryBase + logMemoryBytes);
        if (!inBounds)
            DIE("Tried to transmit a chunk that wasn't in the log.");

        isge[i] = {
            addr,
            chunk.len,
            logMemoryRegion->lkey
        };
    }
    ibv_send_wr txWorkRequest;

    memset(&txWorkRequest, 0, sizeof(txWorkRequest));
    txWorkRequest.wr_id = 0;
    txWorkRequest.next = NULL;
    txWorkRequest.sg_list = isge;
    txWorkRequest.num_sge = chunkCount;
    txWorkRequest.opcode = IBV_WR_RDMA_WRITE;
    txWorkRequest.send_flags = IBV_SEND_SIGNALED;

    txWorkRequest.wr.rdma.remote_addr = remoteVA;
    txWorkRequest.wr.rdma.rkey = rkey;

    // We can get a substantial latency improvement (nearly 2usec less per RTT)
    // by inlining data with the WQE for small messages. The Verbs library
    // automatically takes care of copying from the SGEs to the WQE.
    //if (messageLen <= MAX_INLINE_DATA)
        //txWorkRequest.send_flags |= IBV_SEND_INLINE;

    chunksTransmitted += chunkCount;
    chunksTransmittedZeroCopy += chunkCount;

    ibv_send_wr* badTxWorkRequest;
    int r = ibv_post_send(qp->qp, &txWorkRequest, &badTxWorkRequest);
    if (r == ENOMEM)
        return r;

    if (r)
        DIE("ibv_post_send failed: %d %s", r, strerror(r));

    return 0;
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
                            QueuePairTuple *outgoingQpt, QueuePairTuple *incomingQpt, uint32_t index)
{
    bool haveSent = false;
    uint64_t startTime = rdtsc();
    while (1) {
        if (!haveSent) {
            ssize_t len = sendto(clientSetupSocket[index], outgoingQpt,
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
        ssize_t len = recvfrom(clientSetupSocket[index], incomingQpt,
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
                incomingQpt->getNonce(), clientPort[index]);
        }

        if (rdtsc() - startTime > 3lu * 50 * 1000 * 1000 * 1000)
            return false;
    }
}




void
clientTrySetupQueuePair(uint16_t port)
{
    for (uint16_t host=0;host <numClients;host++) {
        IpAddress address{hostNames[host].c_str(), static_cast<uint16_t>(port)};
        sockaddr_in *sin = reinterpret_cast<sockaddr_in *>(&address.address);

        // Create a new QueuePair and send its parameters to the server so it
        // can create its qp and reply with its parameters.
        QueuePair *qp = new QueuePair(IBV_QPT_RC,
                                      clientSrq,
                                      commonTxCq, clientRxCq,
                                      MAX_TX_QUEUE_DEPTH,
                                      MAX_SHARED_RX_QUEUE_DEPTH);
        uint32_t i;
        uint64_t nonce = rand();
        LOG(DEBUG, "starting to connect to %s via local port %d, nonce 0x%lx",
            inet_ntoa(sin->sin_addr), clientPort[host], nonce);

        for (i = 0; i < QP_EXCHANGE_MAX_TIMEOUTS; i++) {
            QueuePairTuple outgoingQpt(uintptr_t(logMemoryRegion->addr),
                                       logMemoryRegion->rkey,
                                       uint16_t(lid),
                                       qp->getLocalQpNumber(),
                                       qp->getInitialPsn(), nonce);
            QueuePairTuple incomingQpt;
            bool gotResponse;

            try {
                gotResponse = clientTryExchangeQueuePairs(sin, &outgoingQpt,
                                                          &incomingQpt,host);
            } catch (...) {
                delete qp;
                throw;
            }

            if (!gotResponse) {
                // To avoid log clutter, only print a log message for the
                // first retry.
                if (i == 0) {
                    LOG(WARNING, "timed out waiting for response; retrying");
                }
                continue;
            }
            LOG(DEBUG, "connected to %s via local port %d",
                inet_ntoa(sin->sin_addr), clientPort[host]);

            // plumb up our queue pair with the server's parameters.
            qp->plumb(&incomingQpt);
            LOG(DEBUG, "New queue pair nonce 0x%lx, remote log VA 0x%lx, "
                    "remote log rkey 0x%x",
                incomingQpt.getNonce(), incomingQpt.getLogVA(),
                incomingQpt.getRkey());
            remoteLogVA = incomingQpt.getLogVA();
            remoteLogRkey = incomingQpt.getRkey();
            QueuePairs.push_back(qp);
            break;
        }
        if(i==QP_EXCHANGE_MAX_TIMEOUTS) {
            LOG(WARNING, "failed to exchange with server within allotted "
                    "(sent request %u times, local port %d)",
                QP_EXCHANGE_MAX_TIMEOUTS,
                clientPort[host]);
            QueuePairs.pop_back();
            delete qp;
            DIE("failed to connect to host");
        }
    }

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
    if (freeTxBuffers.size() < 3) {
        reapTxBuffers();
        if (freeTxBuffers.size() >= 3) {
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

QueuePair* clientQP = nullptr;

enum Mode { MODE_SEND, MODE_WRITE, MODE_READ, MODE_ALL };

static const int messages = 10 * 1000 * 1000;
static const size_t logSize = 4lu * 1024 * 1024 * 1024;

Mode mode = MODE_ALL;
bool isServer = false;
bool useHugePages = false;
size_t chunkSize = 100;
size_t nChunks = 32;

uint64_t benchSend(bool doZeroCopy, QueuePair*qpair)
{
    Chunk chunks[nChunks];
    uint32_t start = 0;
    for (size_t i = 0; i < nChunks; ++i) {
        start = generateRandom();
        start = start % (logSize - chunkSize);
        chunks[i].p = (void*)(logMemoryBase + start);
        chunks[i].len = chunkSize;
    }

    CycleCounter<> counter{};

    for (int i = 0; i < messages ; ++i) {
        sendZeroCopy(chunks, nChunks, nChunks * chunkSize, qpair, doZeroCopy);
//        if ((i % 1000000) == 0) {
//            LOG(ERROR, "Chunks tx zero-copy: %lu / %lu",
//                    chunksTransmittedZeroCopy, chunksTransmitted);
//        }
    }
    LOG(ERROR, "Chunks tx zero-copy: %lu / %lu",
                    chunksTransmittedZeroCopy, chunksTransmitted);
    return counter.stop();
}

/*
uint64_t benchRDMAWrite()
{
    Chunk chunks[nChunks];
    uint32_t start = 0;
    for (size_t i = 0; i < nChunks; ++i) {
        start = generateRandom();
        start = start % (logSize - chunkSize);
        chunks[i].p = (void*)(logMemoryBase + start);
        chunks[i].len = chunkSize;
    }

    CycleCounter<> counter{};

    for (int i = 0; i < messages ; ++i) {
        while (rdmaWrite(clientQP, chunks, nChunks, nChunks * chunkSize,
                            remoteLogVA + start, remoteLogRkey) == ENOMEM)
        {
            reapTxBuffers();
        }
        if ((i % 100000) == 0) {
            LOG(ERROR, "Chunks tx zero-copy: %lu / %lu",
                    chunksTransmittedZeroCopy, chunksTransmitted);
        }
    }

    return counter.stop();
}

uint64_t benchRDMARead()
{
    CycleCounter<> counter{};

    for (int i = 0; i < messages; ++i) {
        BufferDescriptor* bd = getTransmitBuffer();

        //uint64_t start = 0;

        uint64_t remoteVAs[32];
        for (int i = 0; i < 32; ++i) {
            uint64_t start = generateRandom();
            start = start % (logSize - chunkSize);
            remoteVAs[i] = remoteLogVA + start;
        }

        while (rdmaRead2(clientQP, bd, chunkSize,
                        &remoteVAs[0], 32, remoteLogRkey) == ENOMEM)
        //while (rdmaRead(clientQP, bd, chunkSize,
        //                remoteLogVA + start, remoteLogRkey) == ENOMEM)
        {
        }
        if ((i % 100000) == 0) {
            LOG(ERROR, "Chunks rx zero-copy RDMA read: %u (%lu errors)", i + 1, txFailures);
        }
    }

    return counter.stop();
}
*/


void dumpStats(const char* server, int mode, uint64_t cycles, int chunksPerMessage, size_t currSize, uint64_t sendCycles, uint64_t trasmitCycles)
{
    long double seconds = Cycles::toSeconds(cycles);
    uint64_t totalnsecs = Cycles::toNanoseconds(cycles);
    uint64_t sendnsecs = Cycles::toNanoseconds(sendCycles);
    uint64_t gettxnsecs = Cycles::toNanoseconds(trasmitCycles);
    // Shows erratic numbers for chunksPerMessage >=256. printing everything so that we can calculate mbs outside
    // long double mbs =
    //         ((long double)(messages * chunksPerMessage * currSize) / (1u << 20)) / seconds;
    long double usPerMessage = seconds / messages * 1e6;
    printf(">%d %s %d %lu %d %d %Lf %lu %lu %lu %0.3Lf\n",mode, server, chunksPerMessage, currSize, messages, 1u<<20,
           seconds, totalnsecs, sendnsecs, gettxnsecs, usPerMessage);
    
    // LOG(INFO, "stats mode:%d server:%s chunksPerMessage:%d currSize:%lu messages:%d mfactor:%d seconds:%Lf total_nsecs:%lu send_nsecs:%lu gettx_nsecs:%lu",
    //     mode, server, chunksPerMessage, currSize, messages, 1u<<20, seconds, totalnsecs, sendnsecs, gettxnsecs);
}

void benchSendQP(bool mode, QueuePair* qpair,uint32_t index){
    uint64_t cycles = 0;
    postSendCycles[index] = 0;
    getTrasmitCycles[index] = 0;
    cycles = benchSend(mode,qpair);
    dumpStats(hostNames[index].c_str(), mode?0:1, cycles, nChunks, chunkSize, postSendCycles[index], getTrasmitCycles[index]);
}


void measure(QueuePair* qpair, const char* server) {
    /* Some junk to do synchronous sends, non-zero-copy
     * Probably need cleanup.
     *
    for (int i = 0; i < messages ; ++i) {
        BufferDescriptor* bd = getTransmitBuffer();
        assert(bd->buffer);
        assert(bd->bytes);
        assert(bd->mr);

        Header* header = reinterpret_cast<Header*>(bd->buffer);
        header->len = 6;

        bd->messageBytes = sizeof(*header) + 6;
        memcpy(bd->buffer + sizeof(*header), "hello", 6);

        LOG(INFO, "Client posting message");

        postSendAndWait(qp, bd, bd->messageBytes);
    }
    */
    Cycles::init();
    //printf(">server copied chunks chunksize mbs\n");
    printf(">copied server chunks chunksize messages mfactor seconds totalnsecs sendnsecs gettxnsecs usPerMessage\n");

    if (mode == MODE_SEND || mode == MODE_ALL) {
        size_t iternChunks;
        size_t iterChunkSize;
        MAX_TX_SGE_COUNT = 32;
        for (iternChunks = 1; iternChunks <= 32; ++iternChunks) {
            nChunks = iternChunks;
            for (iterChunkSize=1;iterChunkSize <=1024;iterChunkSize*=2){
                std::vector<std::thread *> clientThreads;
                for(uint32_t tid=0;tid<numClients;tid++){
                    clientThreads.push_back(NULL);
                }
                chunkSize = iterChunkSize;
                for (uint32_t tid=0;tid<numClients;tid++){
                    if(clientThreads[tid]==NULL) {
                        LOG(INFO,"Running Zero Copy on %s #chunks:%lu size:%lu",hostNames[tid].c_str(),nChunks,chunkSize);
                        postSendCycles[tid] = 0;
                        getTrasmitCycles[tid] = 0;
                        clientThreads[tid] = new std::thread(benchSendQP, true, QueuePairs[tid], tid);
                    }
                }
                for (uint32_t tid=0;tid<numClients;tid++){
                    if(clientThreads[tid]!=NULL){
                    clientThreads[tid]->join();
                        delete clientThreads[tid];
                        clientThreads[tid] = NULL;
                    }
                }
                // sleep(5);
                // reapTxBuffers();
                for (uint32_t tid=0;tid<numClients;tid++){
                    if(clientThreads[tid]==NULL) {
                        LOG(INFO,"Running Copy-All on %s #chunks:%lu size:%lu",hostNames[tid].c_str(),nChunks,chunkSize);
                        postSendCycles[tid] = 0;
                        getTrasmitCycles[tid] = 0;
                        clientThreads[tid] = new std::thread(benchSendQP, false, QueuePairs[tid], tid);
                    }

                }
                for (uint32_t tid=0;tid<numClients;tid++){
                    if(clientThreads[tid]!=NULL){
                        clientThreads[tid]->join();
                        delete clientThreads[tid];
                        clientThreads[tid] = NULL;
                    }
                }
            }
        }
        for (iternChunks = 64; iternChunks <= 1024; iternChunks*=2) {
            nChunks = iternChunks;
            for (iterChunkSize=1;iterChunkSize <=1024;iterChunkSize*=2){
                std::vector<std::thread*> clientThreads;
                for(uint32_t tid=0;tid<numClients;tid++){
                    clientThreads.push_back(NULL);
                }
                // sleep(5);
                // reapTxBuffers();
                chunkSize = iterChunkSize;
                for (uint32_t tid=0;tid<numClients;tid++){
                    if(clientThreads[tid]==NULL) {
                        LOG(INFO,"Running Copy-All on %s #chunks:%lu size:%lu",hostNames[tid].c_str(),nChunks,chunkSize);
                        postSendCycles[tid] = 0;
                        getTrasmitCycles[tid] = 0;
                        clientThreads[tid] = new std::thread(benchSendQP, false, QueuePairs[tid], tid);
                    }
                }
                for (uint32_t tid=0;tid<numClients;tid++){
                    if(clientThreads[tid]!=NULL){
                        clientThreads[tid]->join();
                        delete clientThreads[tid];
                        clientThreads[tid] = NULL;
                    }
                }
            }
        }
    }

    /*
    if (mode == MODE_WRITE || mode == MODE_ALL) {
        uint32_t sgLen = MAX_TX_SGE_COUNT = nChunks;
        LOG(INFO, "Running writes with sgLen %d", sgLen);
        cycles = benchRDMAWrite();
        dumpStats(MODE_WRITE, cycles, nChunks, sgLen);
    }

    sleep(5);
    reapTxBuffers();

    if (mode == MODE_READ || mode == MODE_ALL) {
        uint32_t sgLen = MAX_TX_SGE_COUNT = 1;
        LOG(INFO, "Running reads with sgLen %d", sgLen);
        // RDMA Read can only fetch 1 item per op.
        // Doesn't matter for RDMA logic below, but final stat dump multiplies
        // by nChunks, so this needs to be right to get correct stats out.
        cycles = benchRDMARead();
        dumpStats(MODE_READ, cycles, 1, 1);
    }
     */
}

static const char USAGE[] =
R"(ibv-bench.

    Usage:
      ibv-bench server <hostname> [--hugePages]
      ibv-bench client <hostname> [--hugePages] [--chunkSize=SIZE] [--chunksPerMessage=CHUNKS] [--sgLength=SGLEN] [--mode=MODE]
      ibv-bench (-h | --help)

    Options:
      -h --help                  Show this screen
      --hugePages                Use huge pages
      --chunkSize=SIZE           Size of individual objects [default: 100]
      --chunksPerMessage=CHUNKS  Number of objects to send per send/write, ignored for read [default: 32]
      --sgLength=SGLEN           Max S/G list length [default: 32]
      --mode=MODE                send, read, write, or all [default: all]
      --hostname                 Use servers separated by : for multiple connections (eg:- client node-0:node-1)
)";

int main(int argc, const char** argv)
{
    std::map<std::string, docopt::value> args
        = docopt::docopt(USAGE,
                         { argv + 1, argv + argc },
                         true,               // show help if requested
                         "ibv-bench 0.1");  // version string

    // Dump command line args for debugging.
    for (auto const& arg : args) {
        std::cerr << arg.first <<  " " << arg.second << std::endl;
    }

    isServer = bool(args["server"]) && args["server"].asBool();
    useHugePages = bool(args["--hugePages"]) && args["--hugePages"].asBool();
    chunkSize = args["--chunkSize"].asLong();
    nChunks = args["--chunksPerMessage"].asLong();

    const char* hostName = args["<hostname>"].asString().c_str();
    hostNames = split(hostName,':');
    numClients = hostNames.size();
    mode = MODE_ALL;

    if (args["--mode"].asString() == "send") {
        mode = MODE_SEND;
    } else if (args["--mode"].asString() == "write") {
        mode = MODE_WRITE;
    } else if (args["--mode"].asString() == "read") {
        mode = MODE_READ;
    }

    LOG(INFO, "Running as %s with %s",
            isServer ? "server" : "client", hostName);
    LOG(INFO, "number of connections:%d", numClients);
    for (uint32_t i=0;i<numClients;i++){
        LOG(INFO, "Server[%d]:%s",i,hostNames[i].c_str());
    }

    clientSetupSocket = new int[numClients];
    clientPort = new int[numClients];
    postSendCycles = new uint64_t[numClients];
    getTrasmitCycles = new uint64_t[numClients];
    setup(isServer);
    // Allocate a GB and register it with the HCA.
    LOG(INFO, "Registering log memory");
    void* base = nullptr;

    Tub<LargeBlockOfMemory<>> largeBlockOfMemory{};
    if (useHugePages) {
        largeBlockOfMemory.construct(logSize);
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
    }else {
            LOG(INFO, "Setting up queue pairs per client-server");
            clientTrySetupQueuePair(PORT);
            LOG(INFO, "All Clients established qpairs");
            measure(QueuePairs[0],hostNames[0].c_str());
            return 0;
    }

    return 0;
}

