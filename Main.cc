#define _BSD_SOURCE 1
#include <cstdio>
#include <fcntl.h>
#include <cerrno>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <cinttypes>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <infiniband/verbs.h>
#include <netdb.h>
#include <sys/socket.h>

#include <vector>

#include <Tub.h>

static const int PORT = 12240;

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
enum { MAX_TX_SGE_COUNT = 24 };
static const uint32_t QP_EXCHANGE_USEC_TIMEOUT = 50000;

#define LOG(level, fmt, ...)  fprintf(stderr, fmt "\n", ##__VA_ARGS__) 
#define DIE(fmt, ...)  \
    do { \
        fprintf(stderr, fmt "\n", ##__VA_ARGS__); \
        exit(-1); \
    } while (0)

#define ERROR 0
#define WARNING 1

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
int          lid;               // local id for this HCA and physical port
int          serverSetupSocket; // UDP socket for incoming setup requests;
                                // -1 means we're not a server
int          clientSetupSocket; // UDP socket for outgoing setup requests
int          clientPort;        // Port number associated with

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

ibv_context* ctxt;           // device context of the HCA to use
ibv_pd* pd;

void* rxBase;
BufferDescriptor rxDescriptors[MAX_SHARED_RX_QUEUE_DEPTH * 2];

void* txBase;
BufferDescriptor txDescriptors[MAX_TX_QUEUE_DEPTH];

std::vector<BufferDescriptor*> freeTxBuffers;

class DeviceList {
  public:
    DeviceList()
        : devices(ibv_get_device_list(NULL))
    {
        if (devices == NULL) {
            DIE("Could not open infiniband device list", errno);
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
        DIE("posix_memalign(%lu, %lu) failed", alignment);
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

void devListSetup(ibv_device*** const devices) {
    *devices = ibv_get_device_list(NULL);
    if (devices == NULL) {
        DIE("Could not open infiniband device list");
    }
}

void devListDestroy(ibv_device** const devices) {
    ibv_free_device_list(devices);
}

ibv_device*
devListLookup(ibv_device** devices, const char* name) {
    if (name == NULL)
        return devices[0];
    for (int i = 0; devices[i] != NULL; i++) {
        if (strcmp(devices[i]->name, name) == 0)
            return devices[i];
    }
    return NULL;
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
        DIE(, "failed to open infiniband device: %s",
                name == NULL ? "any" : name);
    }

    pd = ibv_alloc_pd(ctxt);
    if (pd == NULL) {
        DIE("failed to allocate infiniband protection domain", errno);
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
        IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_LOCAL_WRITE);
    if (mr == NULL) {
        DIE("failed to register buffer", errno);
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

bool setup(bool isServer, const char* hostName)
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
            (sockaddr*)(&socketAddress),
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
            (sockaddr*)(&socketAddress),
            &socketAddressLength) != 0) {
        close(clientSetupSocket);
        LOG(ERROR, "couldn't get port for clientSetupSocket: %s",
                strerror(errno));
        exit(-1);
    }
    clientPort = ntohs(socketAddress.sin_port);

    // If this is a server, create a server setup socket and bind it.
    if (isServer) {
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
        // XXX
        //serverConnectHandler.construct(serverSetupSocket, this);
    }

    if (!devSetup())
        DIE("Couldn't setup the Infiniband device");

    // Step 2:
    //  Set up the initial verbs necessities: open the device, allocate
    //  protection domain, create shared receive queue, register buffers.

    int ibPhysicalPort = 1;
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
    uint32_t i = 0;
    for (auto& bd : rxDescriptors) {
        if (i < MAX_SHARED_RX_QUEUE_DEPTH)
            postSrqReceiveAndKickTransmit(serverSrq, &bd);
        else
            postSrqReceiveAndKickTransmit(clientSrq, &bd);
        ++i;
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
}

int main(int argc, char* argv[])
{
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <0|1 isServer> <serverHostName>\n",
                argv[0]);
        exit(-1);
    }

    bool isServer = atoi(argv[1]) == 1;
    const char* hostName = argv[2];

    LOG(INFO, "Running as %s with %s",
            isServer ? "server" : "client", hostName);

    setup(isServer, hostName);
    return 0;
}

