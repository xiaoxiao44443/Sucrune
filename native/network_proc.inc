/* Only live Sucrune-owned sockets may enter the guest's proc tables. The
 * manager pins each workspace root for the lifetime of its broker sessions.
 * Never consult host /proc/net, which can contain unrelated applications. */
static pthread_mutex_t scope_lock = PTHREAD_MUTEX_INITIALIZER;
static struct sucrune_network_broker *scopes;

int sucrune_network_attach_workspace(struct sucrune_network_broker *network, int root) {
    struct stat st;
    if (fstat(root, &st) < 0) return -errno;
    network->root_device = (uint64_t)st.st_dev;
    network->root_inode = (uint64_t)st.st_ino;
    pthread_mutex_lock(&scope_lock);
    network->scope_next = scopes;
    scopes = network;
    network->scope_attached = 1;
    pthread_mutex_unlock(&scope_lock);
    return 0;
}

static void detach_workspace(struct sucrune_network_broker *network) {
    if (!network->scope_attached) return;
    pthread_mutex_lock(&scope_lock);
    struct sucrune_network_broker **link = &scopes;
    while (*link != network) link = &(*link)->scope_next;
    *link = network->scope_next;
    network->scope_attached = 0;
    network->visible_slots = 0;
    pthread_mutex_unlock(&scope_lock);
}

/* Publish after filling fd/domain/protocol; revoke before closing the fd.
 * Other slot fields are session-local and are never read by the observer. */
static void set_slot_visible(struct sucrune_network_broker *network,
        const struct sucrune_net_slot *slot, int visible) {
    if (!network->scope_attached || (slot->protocol != IPPROTO_TCP && slot->protocol != IPPROTO_UDP)) return;
    uint64_t bit = UINT64_C(1) << (unsigned int)(slot - network->slots);
    pthread_mutex_lock(&scope_lock);
    if (visible) network->visible_slots |= bit;
    else network->visible_slots &= ~bit;
    pthread_mutex_unlock(&scope_lock);
}

struct socket_row {
    uint32_t local[4], remote[4];
    unsigned int local_port, remote_port, state, tx, rx;
    uint64_t inode;
};

static unsigned int copy_endpoint(const struct sockaddr_storage *address, uint32_t words[4]) {
    if (address->ss_family == AF_INET) {
        const struct sockaddr_in *v4 = (const struct sockaddr_in *)address;
        memcpy(words, &v4->sin_addr, 4);
        return ntohs(v4->sin_port);
    }
    const struct sockaddr_in6 *v6 = (const struct sockaddr_in6 *)address;
    memcpy(words, &v6->sin6_addr, 16);
    return ntohs(v6->sin6_port);
}

static int read_socket_row(const struct sucrune_net_slot *slot, uint16_t dns_port, struct socket_row *row) {
    struct sockaddr_storage address = {0};
    socklen_t length = sizeof(address);
    if (getsockname(slot->fd, (struct sockaddr *)&address, &length) < 0 || address.ss_family != slot->domain) return 0;
    *row = (struct socket_row){0};
    row->local_port = copy_endpoint(&address, row->local);
    if (!row->local_port) return 0;
    length = sizeof(address);
    if (getpeername(slot->fd, (struct sockaddr *)&address, &length) == 0 && address.ss_family == slot->domain) {
        row->remote_port = copy_endpoint(&address, row->remote);
        /* Report the guest resolver, just as getpeername does. */
        if (slot->domain == AF_INET && dns_port && row->remote_port == dns_port &&
            row->remote[0] == htonl(INADDR_LOOPBACK)) {
            row->remote[0] = htonl(UINT32_C(0x7f000035));
            row->remote_port = 53;
        }
    }
    struct stat st;
    if (fstat(slot->fd, &st) < 0) return 0;
    row->inode = (uint64_t)st.st_ino;
    if (slot->protocol == IPPROTO_TCP) {
        struct tcp_info info = {0};
        length = sizeof(info);
        if (getsockopt(slot->fd, IPPROTO_TCP, TCP_INFO, &info, &length) < 0 || info.tcpi_state == 7) return 0;
        row->state = info.tcpi_state;
        if (row->state == 10) { /* TCP_LISTEN: backlog already queued for accept */
            row->rx = info.tcpi_unacked;
            return 1;
        }
    } else {
        row->state = row->remote_port ? 1U : 7U;
    }
    int queued = 0;
    if (ioctl(slot->fd, TIOCOUTQ, &queued) == 0 && queued > 0) row->tx = (unsigned int)queued;
    if (ioctl(slot->fd, FIONREAD, &queued) == 0 && queued > 0) row->rx = (unsigned int)queued;
    return 1;
}

static int compare_inode(const void *a, const void *b) {
    uint64_t left = ((const struct socket_row *)a)->inode;
    uint64_t right = ((const struct socket_row *)b)->inode;
    return left < right ? -1 : left > right;
}

static int write_table(FILE *stream, int family, int protocol, const struct sucrune_network_broker *reader,
        uint32_t guest_uid) {
    size_t count = 0, capacity = 0;
    struct socket_row *rows = NULL;
    int error = 0;
    pthread_mutex_lock(&scope_lock);
    for (const struct sucrune_network_broker *n = scopes; n && !error; n = n->scope_next) {
        if (n->root_device != reader->root_device || n->root_inode != reader->root_inode) continue;
        for (uint64_t mask = n->visible_slots; mask; mask &= mask - 1) {
            const struct sucrune_net_slot *slot = &n->slots[__builtin_ctzll(mask)];
            if (slot->domain != family || slot->protocol != protocol) continue;
            struct socket_row row;
            if (!read_socket_row(slot, n->hooks.dns_port, &row)) continue;
            if (count == capacity) {
                size_t next = capacity ? 2 * capacity : 16;
                struct socket_row *grown = reallocarray(rows, next, sizeof(*rows));
                if (!grown) { error = -ENOMEM; break; }
                rows = grown;
                capacity = next;
            }
            rows[count++] = row;
        }
    }
    pthread_mutex_unlock(&scope_lock);
    if (error) { free(rows); return error; }
    if (count > 1) qsort(rows, count, sizeof(*rows), compare_inode);
    fputs("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n", stream);
    size_t index = 0;
    int words = family == AF_INET ? 1 : 4;
    for (size_t i = 0; i < count; ++i) {
        const struct socket_row *row = &rows[i];
        if (i && row->inode == rows[i-1].inode) continue; /* same socket inherited through fork */
        fprintf(stream, "%4zu: ", index++);
        for (int j = 0; j < words; ++j) fprintf(stream, "%08X", row->local[j]);
        fprintf(stream, ":%04X ", row->local_port);
        for (int j = 0; j < words; ++j) fprintf(stream, "%08X", row->remote[j]);
        fprintf(stream, ":%04X %02X %08X:%08X 00:00000000 00000000 %u 0 %llu\n",
            row->remote_port, row->state, row->tx, row->rx, guest_uid, (unsigned long long)row->inode);
    }
    free(rows);
    return ferror(stream) ? -EIO : 0;
}

int sucrune_network_proc_open(struct sucrune_network_broker *network, int table, uint32_t guest_uid) {
    if (!network->scope_attached) return -ENODEV;
    if (table < SUCRUNE_SYS_TCP || table > SUCRUNE_SYS_UDP6) return -EINVAL;
    int family = table == SUCRUNE_SYS_TCP6 || table == SUCRUNE_SYS_UDP6 ? AF_INET6 : AF_INET;
    int protocol = table == SUCRUNE_SYS_TCP || table == SUCRUNE_SYS_TCP6 ? IPPROTO_TCP : IPPROTO_UDP;
    unsigned int flags = MFD_CLOEXEC | MFD_ALLOW_SEALING;
    int fd = (int)syscall(SYS_memfd_create, "sucrune-proc-net", flags | 0x0008U /* MFD_NOEXEC_SEAL */);
    if (fd < 0 && errno == EINVAL) fd = (int)syscall(SYS_memfd_create, "sucrune-proc-net", flags);
    if (fd < 0) return -errno;
    FILE *writer = fdopen(fd, "w");
    if (!writer) { int error = -errno; close(fd); return error; }
    int result = write_table(writer, family, protocol, network, guest_uid);
    if (!result && fflush(writer) < 0) result = -errno;
    if (!result && fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) < 0) result = -errno;
    if (!result) {
        char pinned[48];
        snprintf(pinned, sizeof(pinned), "/proc/self/fd/%d", fd);
        result = open(pinned, O_RDONLY | O_CLOEXEC);
        if (result < 0) result = -errno;
    }
    fclose(writer);
    return result;
}
