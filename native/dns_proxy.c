#include "dns_proxy.h"
#include <errno.h>
#include <limits.h>
#include <string.h>

static uint16_t dns_u16(const unsigned char *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}
/* A visited-offset bitmap is unnecessary: a bounded traversal rejects every
 * compression cycle, while expanded names retain DNS's 255-byte limit. */
static int dns_name(const unsigned char *data, size_t length, size_t *offset,
    unsigned char *key, size_t *key_length) {
    size_t position=*offset, end=0U, used=0U, traversed=0U;
    int jumped=0;
    for (;;) {
        if (position>=length || ++traversed>256U) return -EPROTO;
        unsigned int label=data[position++];
        if ((label&0xc0U)==0xc0U) {
            if (position>=length) return -EPROTO;
            size_t target=((size_t)(label&0x3fU)<<8)|data[position++];
            /* DNS compression refers to an earlier name occurrence, never a
             * header byte or a forward offset outside a truncated question. */
            if (target<12U || target>=position-2U) return -EPROTO;
            if (!jumped) end=position;
            jumped=1; position=target; continue;
        }
        if ((label&0xc0U)!=0U || used+1U+(size_t)label>255U ||
            (size_t)label>length-position) return -EPROTO;
        if (key!=NULL) key[used]=(unsigned char)label;
        used++;
        for (unsigned int i=0U;i<label;i++) {
            unsigned char c=data[position++];
            if (c>='A' && c<='Z') c=(unsigned char)(c+('a'-'A'));
            if (key!=NULL) key[used]=c;
            used++;
        }
        if (label==0U) break;
    }
    *offset=jumped ? end : position;
    if (key_length!=NULL) *key_length=used;
    return 0;
}
static int dns_question(const unsigned char *data, size_t length,
    struct sucrune_dns_question *question) {
    size_t offset=12U, used=0U;
    int result=dns_name(data,length,&offset,question->key,&used);
    if (result<0 || length-offset<4U) return -EPROTO;
    memcpy(question->key+used,data+offset,4U);
    question->key_length=used+4U; question->wire_end=offset+4U;
    question->id=dns_u16(data); question->udp_limit=512U;
    return 0;
}
int sucrune_dns_parse_query(const void *value, size_t length,
    struct sucrune_dns_question *question) {
    if (value==NULL || question==NULL || length<12U || length>SUCRUNE_DNS_QUERY_MAX) return -EINVAL;
    const unsigned char *data=value;
    if ((data[2]&0xf8U)!=0U || dns_u16(data+4)!=1U ||
        dns_u16(data+6)!=0U || dns_u16(data+8)!=0U) return -EPROTO;
    struct sucrune_dns_question parsed;
    memset(&parsed,0,sizeof(parsed));
    if (dns_question(data,length,&parsed)<0) return -EPROTO;
    size_t offset=parsed.wire_end;
    unsigned int count=dns_u16(data+10), opts=0U;
    for (unsigned int i=0U;i<count;i++) {
        if (dns_name(data,length,&offset,NULL,NULL)<0 || length-offset<10U) return -EPROTO;
        unsigned int type=dns_u16(data+offset), size=dns_u16(data+offset+8U);
        if (type==41U) {
            if (++opts>1U) return -EPROTO;
            unsigned int limit=dns_u16(data+offset+2U);
            parsed.udp_limit=(uint16_t)(limit<512U ? 512U : limit>65507U ? 65507U : limit);
        }
        offset+=10U;
        if ((size_t)size>length-offset) return -EPROTO;
        offset+=(size_t)size;
    }
    if (offset!=length) return -EPROTO;
    *question=parsed; return 0;
}
int sucrune_dns_system_answer_length(const void *value, size_t length,
    const struct sucrune_dns_question *question) {
    if (value==NULL || question==NULL || length<12U || length>SUCRUNE_DNS_ANSWER_MAX) return -EINVAL;
    const unsigned char *data=value;
    if ((data[2]&0xf8U)!=0x80U || dns_u16(data+4)!=1U || dns_u16(data)!=question->id) return -EPROTO;
    struct sucrune_dns_question parsed;
    if (dns_question(data,length,&parsed)<0 || parsed.key_length!=question->key_length ||
        memcmp(parsed.key,question->key,parsed.key_length)!=0) return -EPROTO;
    size_t offset=parsed.wire_end;
    unsigned int count=(unsigned int)dns_u16(data+6)+dns_u16(data+8)+dns_u16(data+10);
    for (unsigned int i=0U;i<count;i++) {
        if (dns_name(data,length,&offset,NULL,NULL)<0 || length-offset<10U) return -EPROTO;
        size_t size=dns_u16(data+offset+8U); offset+=10U;
        if (size>length-offset) return -EPROTO;
        offset+=size;
    }
    return (int)offset;
}
int sucrune_dns_validate_answer(const void *value, size_t length,
    const struct sucrune_dns_question *question) {
    int used=sucrune_dns_system_answer_length(value,length,question);
    return used<0 ? used : (size_t)used==length ? 0 : -EPROTO;
}

#if !defined(SUCRUNE_DNS_CODEC_ONLY)
#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
static void dns_put16(unsigned char *p, uint16_t n) {
    p[0]=(unsigned char)(n>>8); p[1]=(unsigned char)n;
}
#if defined(__ANDROID__)
#include <android/multinetwork.h>
#endif

enum dns_state { DNS_FREE, DNS_QUEUED, DNS_ACTIVE, DNS_DONE };
struct dns_client { uint64_t token; uint16_t port; int transport; };
struct dns_job {
    enum dns_state state;
    uint64_t token, tcp_generation;
    int tcp_index, cancel_reason, control_fd, collecting;
    int64_t deadline;
    struct sockaddr_in peer;
    struct sucrune_dns_question question;
    size_t query_length, answer_length;
    unsigned char query[SUCRUNE_DNS_QUERY_MAX], answer[SUCRUNE_DNS_ANSWER_MAX];
};
struct dns_connection {
    int fd, job;
    uint64_t token, generation;
    int64_t idle_deadline;
    size_t used, wanted, sent;
    unsigned char input[SUCRUNE_DNS_QUERY_MAX+2U];
};
struct sucrune_dns_proxy {
    pthread_mutex_t lock;
    pthread_cond_t changed;
    pthread_t io_thread, workers[SUCRUNE_DNS_WORKER_LIMIT];
    unsigned int worker_count, workers_exited;
    int io_started, io_exited, stopping, joined;
    int udp, tcp, wake[2];
    uint16_t port;
    struct sucrune_dns_config config;
    struct sucrune_dns_backend backend;
    int system_backend;
    struct sucrune_dns_stats stats;
    struct dns_client clients[SUCRUNE_DNS_CLIENT_LIMIT];
    struct dns_job jobs[SUCRUNE_DNS_QUERY_LIMIT];
    struct dns_connection connections[SUCRUNE_DNS_TCP_LIMIT];
};
static int64_t dns_now(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC,&value)!=0) return 0;
    return (int64_t)value.tv_sec*1000+(int64_t)value.tv_nsec/1000000;
}
static void dns_wake(struct sucrune_dns_proxy *proxy) {
    unsigned char byte=1U;
    ssize_t result=write(proxy->wake[1],&byte,1U); (void)result;
}
static int dns_default_submit(void *unused, uint64_t network,
    const unsigned char *query, size_t length) {
    (void)unused;
#if defined(__ANDROID__)
    return android_res_nsend(network,query,length,0U);
#else
    (void)network;(void)query;(void)length; return -ENOTSUP;
#endif
}
static int dns_default_collect(void *unused, int fd, int *rcode,
    unsigned char *answer, size_t length) {
    (void)unused;
#if defined(__ANDROID__)
    return android_res_nresult(fd,rcode,answer,length);
#else
    (void)rcode;(void)answer;(void)length;(void)close(fd); return -ENOTSUP;
#endif
}
static void dns_default_cancel(void *unused, int fd) {
    (void)unused;
#if defined(__ANDROID__)
    android_res_cancel(fd);
#else
    (void)close(fd);
#endif
}
/* Call only with lock held. Retained control alias avoids descriptor-number
 * reuse when collect closes the original. shutdown never consumes either FD. */
static void dns_cancel_job(struct sucrune_dns_proxy *proxy, struct dns_job *job, int reason) {
    if (job->state==DNS_FREE || job->cancel_reason!=0) return;
    job->cancel_reason=reason;
    if (reason==ETIMEDOUT) proxy->stats.timed_out++; else proxy->stats.cancelled++;
    if (job->control_fd>=0) (void)shutdown(job->control_fd,SHUT_RDWR);
}
static size_t dns_failure(struct dns_job *job, unsigned int rcode, int truncated,
    unsigned char flags2, unsigned char flags3) {
    size_t length=job->question.wire_end;
    memcpy(job->answer,job->query,length);
    job->answer[2]=(unsigned char)(0x80U|(flags2&0x05U)|(truncated ? 0x02U : 0U));
    job->answer[3]=(unsigned char)((flags3&0x90U)|(rcode&0x0fU));
    memset(job->answer+6,0,6U);
    return length;
}
static uint64_t dns_lookup_client(struct sucrune_dns_proxy *proxy, int transport, uint16_t port) {
    for (unsigned int i=0U;i<SUCRUNE_DNS_CLIENT_LIMIT;i++)
        if (proxy->clients[i].token!=0U && proxy->clients[i].transport==transport && proxy->clients[i].port==port)
            return proxy->clients[i].token;
    return 0U;
}
static int dns_token_live(struct sucrune_dns_proxy *proxy, uint64_t token) {
    for (unsigned int i=0U;i<SUCRUNE_DNS_CLIENT_LIMIT;i++) if (proxy->clients[i].token==token) return 1;
    return 0;
}
static void *dns_worker(void *argument) {
    struct sucrune_dns_proxy *proxy=argument;
    for (;;) {
        (void)pthread_mutex_lock(&proxy->lock);
        struct dns_job *job=NULL;
        while (!proxy->stopping && job==NULL) {
            for (unsigned int i=0U;i<SUCRUNE_DNS_QUERY_LIMIT;i++)
                if (proxy->jobs[i].state==DNS_QUEUED) {job=&proxy->jobs[i];break;}
            if (job==NULL) (void)pthread_cond_wait(&proxy->changed,&proxy->lock);
        }
        if (proxy->stopping) {(void)pthread_mutex_unlock(&proxy->lock);break;}
        job->state=DNS_ACTIVE;
        int cancelled=job->cancel_reason;
        (void)pthread_mutex_unlock(&proxy->lock);
        int result=cancelled!=0 ? -cancelled : proxy->backend.submit(proxy->backend.userdata,
            proxy->config.network_handle,job->query,job->query_length);
        int fd=result, control=-1;
        if (fd>=0) {
            int type=0; socklen_t size=sizeof(type);
            if (getsockopt(fd,SOL_SOCKET,SO_TYPE,&type,&size)!=0) result=-errno;
            else if (size!=sizeof(type) || type!=SOCK_STREAM) result=-EPROTO;
            else if ((control=fcntl(fd,F_DUPFD_CLOEXEC,0))<0) result=-errno;
            (void)pthread_mutex_lock(&proxy->lock);
            job->control_fd=control;
            if (proxy->stopping || job->cancel_reason!=0 || dns_now()>=job->deadline) {
                if (job->cancel_reason==0) dns_cancel_job(proxy,job,proxy->stopping ? ECANCELED : ETIMEDOUT);
                result=-job->cancel_reason;
            }
            (void)pthread_mutex_unlock(&proxy->lock);
            if (result>=0) {
                for (;;) {
                    (void)pthread_mutex_lock(&proxy->lock);
                    cancelled=job->cancel_reason;
                    (void)pthread_mutex_unlock(&proxy->lock);
                    int64_t left=job->deadline-dns_now();
                    if (cancelled!=0 || left<=0) {result=cancelled!=0 ? -cancelled : -ETIMEDOUT;break;}
                    struct pollfd wait={fd,POLLIN,0};
                    int ready=poll(&wait,1U,(int)(left>50 ? 50 : left));
                    if (ready<0 && errno==EINTR) continue;
                    if (ready<0) {result=-errno;break;}
                    if (ready==0) continue;
                    /* A pending cancellation can wake poll through shutdown.
                     * Commit to exactly one consuming callback under lock. */
                    (void)pthread_mutex_lock(&proxy->lock);
                    if (job->cancel_reason==0 && dns_now()>=job->deadline) dns_cancel_job(proxy,job,ETIMEDOUT);
                    cancelled=job->cancel_reason;
                    if (cancelled==0) job->collecting=1;
                    (void)pthread_mutex_unlock(&proxy->lock);
                    if (cancelled!=0) {result=-cancelled;break;}
                    /* Keep collection bounded even when only a partial netd
                     * stream is readable. IO owner also shutdowns at deadline. */
                    struct timeval timeout={(time_t)(left/1000),(suseconds_t)((left%1000)*1000)};
                    if (setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout))!=0) {result=-errno;break;}
                    int rcode=0;
                    result=proxy->backend.collect(proxy->backend.userdata,fd,&rcode,job->answer,sizeof(job->answer));
                    fd=-1; /* collect consumed it even on failure. */
                    if (result>=0) {
                        /* A real Android resolver can return a complete DNS
                         * message plus uncounted nonzero tail bytes. Exclude
                         * those bytes; retain checks on query ID, question,
                         * compression and every section's count and bounds. */
                        int used=sucrune_dns_system_answer_length(job->answer,(size_t)result,&job->question);
                        if (used<0 || (!proxy->system_backend && used!=result)) result=-EPROTO;
                        else result=used;
                    }
                    break;
                }
            }
            if (fd>=0) proxy->backend.cancel(proxy->backend.userdata,fd);
        }
        (void)pthread_mutex_lock(&proxy->lock);
        if (control>=0) (void)close(control);
        job->control_fd=-1;
        if (result==-ETIMEDOUT && job->cancel_reason==0) dns_cancel_job(proxy,job,ETIMEDOUT);
        if (proxy->stopping || job->cancel_reason==ECANCELED || !dns_token_live(proxy,job->token)) job->state=DNS_FREE;
        else {
            if (result<0 || job->cancel_reason!=0) {
                if (job->cancel_reason==0) proxy->stats.backend_errors++;
                job->answer_length=dns_failure(job,2U,0,job->query[2],0x80U);
            } else {
                job->answer_length=(size_t)result;
                if (job->tcp_index<0 && job->answer_length>job->question.udp_limit) {
                    unsigned char a=job->answer[2],b=job->answer[3];
                    job->answer_length=dns_failure(job,b&0x0fU,1,a,b);
                }
            }
            job->state=DNS_DONE;
        }
        (void)pthread_mutex_unlock(&proxy->lock);
        dns_wake(proxy);
    }
    (void)pthread_mutex_lock(&proxy->lock);proxy->workers_exited++;
    (void)pthread_cond_broadcast(&proxy->changed);(void)pthread_mutex_unlock(&proxy->lock);
    return NULL;
}
/* IO owner only; caller holds lock. */
static void dns_close_connection(struct sucrune_dns_proxy *proxy, unsigned int index) {
    struct dns_connection *connection=&proxy->connections[index];
    if (connection->job>=0) {
        struct dns_job *job=&proxy->jobs[(unsigned int)connection->job];
        if (job->tcp_index==(int)index && job->tcp_generation==connection->generation && job->token==connection->token) {
            if (job->state==DNS_ACTIVE) dns_cancel_job(proxy,job,ECANCELED);
            else job->state=DNS_FREE;
        }
    }
    if (connection->fd>=0) (void)close(connection->fd);
    connection->fd=-1;connection->job=-1;connection->token=0U;
    connection->used=0U;connection->wanted=2U;connection->sent=0U;
}
static int dns_admit(struct sucrune_dns_proxy *proxy, uint64_t token,
    const unsigned char *query, size_t length, const struct sockaddr_in *peer, int tcp_index) {
    struct sucrune_dns_question question;
    if (sucrune_dns_parse_query(query,length,&question)<0) {proxy->stats.malformed++;return -EPROTO;}
    for (unsigned int i=0U;i<SUCRUNE_DNS_QUERY_LIMIT;i++) {
        struct dns_job *job=&proxy->jobs[i];
        if (job->state!=DNS_FREE) continue;
        job->token=token;job->question=question;job->query_length=length;
        job->tcp_index=tcp_index;job->tcp_generation=tcp_index<0 ? 0U : proxy->connections[(unsigned int)tcp_index].generation;
        job->cancel_reason=0;job->control_fd=-1;job->collecting=0;job->answer_length=0U;
        job->deadline=dns_now()+(int64_t)proxy->config.query_timeout_ms;
        if (peer!=NULL) job->peer=*peer;
        memcpy(job->query,query,length);job->state=DNS_QUEUED;proxy->stats.admitted++;
        (void)pthread_cond_signal(&proxy->changed);return (int)i;
    }
    proxy->stats.capacity_rejected++;return -EAGAIN;
}
static void dns_receive_udp(struct sucrune_dns_proxy *proxy) {
    for (unsigned int turn=0U;turn<16U;turn++) {
        unsigned char query[SUCRUNE_DNS_QUERY_MAX];
        struct sockaddr_in peer;memset(&peer,0,sizeof(peer));socklen_t size=sizeof(peer);
        ssize_t received=recvfrom(proxy->udp,query,sizeof(query),MSG_DONTWAIT|MSG_TRUNC,(struct sockaddr *)&peer,&size);
        if (received<0) return;
        if ((size_t)received>sizeof(query)) {proxy->stats.malformed++;continue;}
        uint64_t token=size==sizeof(peer) && peer.sin_family==AF_INET && peer.sin_addr.s_addr==htonl(INADDR_LOOPBACK)
            ? dns_lookup_client(proxy,SUCRUNE_DNS_UDP,peer.sin_port) : 0U;
        if (token==0U) {proxy->stats.unregistered++;continue;}
        (void)dns_admit(proxy,token,query,(size_t)received,&peer,-1);
    }
}
static void dns_accept_tcp(struct sucrune_dns_proxy *proxy) {
    for (unsigned int turn=0U;turn<8U;turn++) {
        struct sockaddr_in peer;memset(&peer,0,sizeof(peer));socklen_t size=sizeof(peer);
        int fd=accept4(proxy->tcp,(struct sockaddr *)&peer,&size,SOCK_CLOEXEC|SOCK_NONBLOCK);
        if (fd<0) return;
        uint64_t token=size==sizeof(peer) && peer.sin_family==AF_INET && peer.sin_addr.s_addr==htonl(INADDR_LOOPBACK)
            ? dns_lookup_client(proxy,SUCRUNE_DNS_TCP,peer.sin_port) : 0U;
        if (token==0U) {proxy->stats.unregistered++;(void)close(fd);continue;}
        unsigned int i;
        for (i=0U;i<SUCRUNE_DNS_TCP_LIMIT;i++) if (proxy->connections[i].fd<0) break;
        if (i==SUCRUNE_DNS_TCP_LIMIT) {proxy->stats.capacity_rejected++;(void)close(fd);continue;}
        struct dns_connection *connection=&proxy->connections[i];
        if (connection->generation==UINT64_MAX) {(void)close(fd);proxy->stats.capacity_rejected++;continue;}
        connection->generation++;connection->fd=fd;connection->job=-1;connection->token=token;
        connection->used=0U;connection->wanted=2U;connection->sent=0U;
        connection->idle_deadline=dns_now()+(int64_t)proxy->config.query_timeout_ms;
    }
}
static void dns_tcp_read(struct sucrune_dns_proxy *proxy, unsigned int index) {
    struct dns_connection *connection=&proxy->connections[index];
    for (unsigned int turn=0U;turn<2U;turn++) {
        ssize_t received=recv(connection->fd,connection->input+connection->used,connection->wanted-connection->used,MSG_DONTWAIT);
        if (received<0) {if (errno!=EAGAIN && errno!=EWOULDBLOCK && errno!=EINTR) dns_close_connection(proxy,index);return;}
        if (received==0) {dns_close_connection(proxy,index);return;}
        connection->used+=(size_t)received;
        if (connection->used<connection->wanted) return;
        if (connection->wanted==2U) {
            size_t length=dns_u16(connection->input);
            if (length<12U || length>SUCRUNE_DNS_QUERY_MAX) {proxy->stats.malformed++;dns_close_connection(proxy,index);return;}
            connection->wanted=length+2U;continue;
        }
        int job=dns_admit(proxy,connection->token,connection->input+2U,connection->wanted-2U,NULL,(int)index);
        if (job<0) {dns_close_connection(proxy,index);return;}
        connection->job=job;return;
    }
}
static void dns_tcp_write(struct sucrune_dns_proxy *proxy, unsigned int index) {
    struct dns_connection *connection=&proxy->connections[index];
    if (connection->job<0) return;
    struct dns_job *job=&proxy->jobs[(unsigned int)connection->job];
    if (job->state!=DNS_DONE || job->tcp_generation!=connection->generation) return;
    unsigned char prefix[2];dns_put16(prefix,(uint16_t)job->answer_length);
    struct iovec buffers[2];size_t n=0U;
    if (connection->sent<2U) buffers[n++]=(struct iovec){prefix+connection->sent,2U-connection->sent};
    size_t body=connection->sent>2U ? connection->sent-2U : 0U;
    if (body<job->answer_length) buffers[n++]=(struct iovec){job->answer+body,job->answer_length-body};
    struct msghdr message;memset(&message,0,sizeof(message));message.msg_iov=buffers;message.msg_iovlen=n;
    ssize_t sent=sendmsg(connection->fd,&message,MSG_DONTWAIT|MSG_NOSIGNAL);
    if (sent<0) {if (errno!=EAGAIN && errno!=EWOULDBLOCK && errno!=EINTR) dns_close_connection(proxy,index);return;}
    connection->sent+=(size_t)sent;
    if (connection->sent==job->answer_length+2U) {
        proxy->stats.answered++;job->state=DNS_FREE;connection->job=-1;
        connection->used=0U;connection->wanted=2U;connection->sent=0U;
        connection->idle_deadline=dns_now()+(int64_t)proxy->config.query_timeout_ms;
    }
}
static void *dns_io(void *argument) {
    struct sucrune_dns_proxy *proxy=argument;
    for (;;) {
        struct pollfd descriptors[3U+SUCRUNE_DNS_TCP_LIMIT];
        (void)pthread_mutex_lock(&proxy->lock);
        if (proxy->stopping) {(void)pthread_mutex_unlock(&proxy->lock);break;}
        int64_t now=dns_now();
        descriptors[0]=(struct pollfd){proxy->wake[0],POLLIN,0};
        descriptors[1]=(struct pollfd){proxy->udp,POLLIN,0};descriptors[2]=(struct pollfd){proxy->tcp,POLLIN,0};
        for (unsigned int i=0U;i<SUCRUNE_DNS_QUERY_LIMIT;i++) {
            struct dns_job *job=&proxy->jobs[i];
            if (job->state!=DNS_FREE && !dns_token_live(proxy,job->token)) dns_cancel_job(proxy,job,ECANCELED);
            if (job->state!=DNS_FREE && now>=job->deadline) dns_cancel_job(proxy,job,ETIMEDOUT);
            if (job->state==DNS_DONE && job->tcp_index<0) {
                /* Revocation wins even if a deadline already recorded another
                 * reason. The old port may now belong to a new generation. */
                if (job->cancel_reason==ECANCELED || !dns_token_live(proxy,job->token)) {job->state=DNS_FREE;continue;}
                ssize_t sent=sendto(proxy->udp,job->answer,job->answer_length,MSG_DONTWAIT|MSG_NOSIGNAL,
                    (struct sockaddr *)&job->peer,sizeof(job->peer));
                if (sent==(ssize_t)job->answer_length) {proxy->stats.answered++;job->state=DNS_FREE;}
                else if (sent>=0 || (errno!=EAGAIN && errno!=EWOULDBLOCK && errno!=EINTR) || now>=job->deadline) job->state=DNS_FREE;
            }
        }
        for (unsigned int i=0U;i<SUCRUNE_DNS_TCP_LIMIT;i++) {
            struct dns_connection *connection=&proxy->connections[i];
            if (connection->fd>=0 && (!dns_token_live(proxy,connection->token) ||
                (connection->job<0 && now>=connection->idle_deadline) ||
                (connection->job>=0 && proxy->jobs[(unsigned int)connection->job].state==DNS_DONE &&
                 now>=proxy->jobs[(unsigned int)connection->job].deadline+100))) dns_close_connection(proxy,i);
            short events=connection->job<0 ? POLLIN :
                proxy->jobs[(unsigned int)connection->job].state==DNS_DONE ? POLLOUT : 0;
            descriptors[3U+i]=(struct pollfd){connection->fd,events,0};
        }
        (void)pthread_mutex_unlock(&proxy->lock);
        int result=poll(descriptors,3U+SUCRUNE_DNS_TCP_LIMIT,25);
        if (result<0 && errno!=EINTR) {sucrune_dns_proxy_request_stop(proxy);continue;}
        (void)pthread_mutex_lock(&proxy->lock);
        if (descriptors[0].revents!=0) {unsigned char buffer[64];while (read(proxy->wake[0],buffer,sizeof(buffer))>0) {}}
        if (!proxy->stopping) {
            if ((descriptors[1].revents&POLLIN)!=0) dns_receive_udp(proxy);
            if ((descriptors[2].revents&POLLIN)!=0) dns_accept_tcp(proxy);
            for (unsigned int i=0U;i<SUCRUNE_DNS_TCP_LIMIT;i++) {
                if (proxy->connections[i].fd<0) continue;
                short events=descriptors[3U+i].revents;
                if ((events&(POLLERR|POLLNVAL))!=0) {dns_close_connection(proxy,i);continue;}
                if ((events&POLLIN)!=0 && proxy->connections[i].job<0) dns_tcp_read(proxy,i);
                if (proxy->connections[i].fd>=0 && (events&POLLOUT)!=0) dns_tcp_write(proxy,i);
                if (proxy->connections[i].fd>=0 && (events&POLLHUP)!=0) dns_close_connection(proxy,i);
            }
        }
        (void)pthread_mutex_unlock(&proxy->lock);
    }
    (void)pthread_mutex_lock(&proxy->lock);
    if (proxy->udp>=0) {(void)close(proxy->udp);proxy->udp=-1;}
    if (proxy->tcp>=0) {(void)close(proxy->tcp);proxy->tcp=-1;}
    for (unsigned int i=0U;i<SUCRUNE_DNS_TCP_LIMIT;i++) dns_close_connection(proxy,i);
    for (unsigned int i=0U;i<SUCRUNE_DNS_QUERY_LIMIT;i++) {
        dns_cancel_job(proxy,&proxy->jobs[i],ECANCELED);
        if (proxy->jobs[i].state!=DNS_ACTIVE) proxy->jobs[i].state=DNS_FREE;
    }
    proxy->stats.listeners_closed=1;proxy->io_exited=1;
    (void)pthread_cond_broadcast(&proxy->changed);(void)pthread_mutex_unlock(&proxy->lock);
    return NULL;
}
int sucrune_dns_proxy_start(const struct sucrune_dns_config *config,
    const struct sucrune_dns_backend *backend, struct sucrune_dns_proxy **output) {
    if (output==NULL) return -EINVAL;
    *output=NULL;
    if (config==NULL || config->query_timeout_ms==0U || config->query_timeout_ms>30000U ||
        (backend!=NULL && (backend->submit==NULL || backend->collect==NULL || backend->cancel==NULL))) return -EINVAL;
#if !defined(__ANDROID__)
    if (backend==NULL) return -ENOTSUP;
#endif
    struct sucrune_dns_proxy *proxy=calloc(1U,sizeof(*proxy));
    if (proxy==NULL) return -ENOMEM;
    proxy->udp=-1;proxy->tcp=-1;proxy->wake[0]=-1;proxy->wake[1]=-1;proxy->config=*config;
    proxy->backend=backend!=NULL ? *backend : (struct sucrune_dns_backend){NULL,dns_default_submit,dns_default_collect,dns_default_cancel};
    proxy->system_backend=backend==NULL;
    for (unsigned int i=0U;i<SUCRUNE_DNS_TCP_LIMIT;i++) {proxy->connections[i].fd=-1;proxy->connections[i].job=-1;}
    for (unsigned int i=0U;i<SUCRUNE_DNS_QUERY_LIMIT;i++) proxy->jobs[i].control_fd=-1;
    int error=pthread_mutex_init(&proxy->lock,NULL);
    if (error!=0) {free(proxy);return -error;}
    pthread_condattr_t attributes;
    error=pthread_condattr_init(&attributes);
    if (error!=0) {(void)pthread_mutex_destroy(&proxy->lock);free(proxy);return -error;}
    error=pthread_condattr_setclock(&attributes,CLOCK_MONOTONIC);
    if (error==0) error=pthread_cond_init(&proxy->changed,&attributes);
    (void)pthread_condattr_destroy(&attributes);
    if (error!=0) {(void)pthread_mutex_destroy(&proxy->lock);free(proxy);return -error;}
    proxy->tcp=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,IPPROTO_TCP);
    proxy->udp=socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK,IPPROTO_UDP);
    if (proxy->tcp<0 || proxy->udp<0 || pipe2(proxy->wake,O_CLOEXEC|O_NONBLOCK)!=0) {error=errno;goto failed;}
    struct sockaddr_in address;memset(&address,0,sizeof(address));address.sin_family=AF_INET;address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if (bind(proxy->tcp,(struct sockaddr *)&address,sizeof(address))!=0) {error=errno;goto failed;}
    socklen_t length=sizeof(address);
    if (getsockname(proxy->tcp,(struct sockaddr *)&address,&length)!=0 ||
        bind(proxy->udp,(struct sockaddr *)&address,sizeof(address))!=0 || listen(proxy->tcp,8)!=0) {error=errno;goto failed;}
    proxy->port=ntohs(address.sin_port);
    for (unsigned int i=0U;i<SUCRUNE_DNS_WORKER_LIMIT;i++) {
        error=pthread_create(&proxy->workers[i],NULL,dns_worker,proxy);
        if (error!=0) goto failed;
        proxy->worker_count++;
    }
    error=pthread_create(&proxy->io_thread,NULL,dns_io,proxy);
    if (error!=0) goto failed;
    proxy->io_started=1;*output=proxy;return 0;
failed:
    (void)pthread_mutex_lock(&proxy->lock);proxy->stopping=1;(void)pthread_cond_broadcast(&proxy->changed);(void)pthread_mutex_unlock(&proxy->lock);
    for (unsigned int i=0U;i<proxy->worker_count;i++) (void)pthread_join(proxy->workers[i],NULL);
    if (proxy->udp>=0) (void)close(proxy->udp);
    if (proxy->tcp>=0) (void)close(proxy->tcp);
    for (unsigned int i=0U;i<2U;i++) if (proxy->wake[i]>=0) (void)close(proxy->wake[i]);
    (void)pthread_cond_destroy(&proxy->changed);(void)pthread_mutex_destroy(&proxy->lock);free(proxy);return -error;
}
int sucrune_dns_proxy_endpoint(struct sucrune_dns_proxy *proxy, uint16_t *port) {
    if (proxy==NULL || port==NULL) return -EINVAL;
    (void)pthread_mutex_lock(&proxy->lock);int result=proxy->stopping ? -ESHUTDOWN : 0;
    if (result==0) *port=proxy->port;
    (void)pthread_mutex_unlock(&proxy->lock);return result;
}
int sucrune_dns_proxy_allow_client(struct sucrune_dns_proxy *proxy, int transport, int fd, uint64_t token) {
    if (proxy==NULL || fd<0 || token==0U || (transport!=SUCRUNE_DNS_TCP && transport!=SUCRUNE_DNS_UDP)) return -EINVAL;
    int type=0;socklen_t size=sizeof(type);
    if (getsockopt(fd,SOL_SOCKET,SO_TYPE,&type,&size)!=0) return -errno;
    if (type!=(transport==SUCRUNE_DNS_TCP ? SOCK_STREAM : SOCK_DGRAM)) return -EPROTOTYPE;
    struct sockaddr_in address;memset(&address,0,sizeof(address));size=sizeof(address);
    if (getsockname(fd,(struct sockaddr *)&address,&size)!=0) return -errno;
    if (size!=sizeof(address) || address.sin_family!=AF_INET || address.sin_port==0U ||
        (address.sin_addr.s_addr!=htonl(INADDR_LOOPBACK) && address.sin_addr.s_addr!=htonl(INADDR_ANY))) return -EINVAL;
    (void)pthread_mutex_lock(&proxy->lock);
    int result=proxy->stopping ? -ESHUTDOWN : -EMFILE;
    if (!proxy->stopping) {
        unsigned int free_index=SUCRUNE_DNS_CLIENT_LIMIT;
        for (unsigned int i=0U;i<SUCRUNE_DNS_CLIENT_LIMIT;i++) {
            struct dns_client *client=&proxy->clients[i];
            if (client->token==token || (client->token!=0U && client->transport==transport && client->port==address.sin_port)) {result=-EEXIST;free_index=SUCRUNE_DNS_CLIENT_LIMIT;break;}
            if (client->token==0U) free_index=i;
        }
        if (free_index<SUCRUNE_DNS_CLIENT_LIMIT) {proxy->clients[free_index]=(struct dns_client){token,address.sin_port,transport};result=0;}
    }
    (void)pthread_mutex_unlock(&proxy->lock);return result;
}
int sucrune_dns_proxy_remove_client(struct sucrune_dns_proxy *proxy, uint64_t token) {
    if (proxy==NULL || token==0U) return -EINVAL;
    (void)pthread_mutex_lock(&proxy->lock);int result=-ENOENT;
    for (unsigned int i=0U;i<SUCRUNE_DNS_CLIENT_LIMIT;i++) if (proxy->clients[i].token==token) {proxy->clients[i].token=0U;result=0;break;}
    for (unsigned int i=0U;i<SUCRUNE_DNS_QUERY_LIMIT;i++) if (proxy->jobs[i].token==token) dns_cancel_job(proxy,&proxy->jobs[i],ECANCELED);
    (void)pthread_mutex_unlock(&proxy->lock);dns_wake(proxy);return result;
}
void sucrune_dns_proxy_request_stop(struct sucrune_dns_proxy *proxy) {
    if (proxy==NULL) return;
    (void)pthread_mutex_lock(&proxy->lock);proxy->stopping=1;
    for (unsigned int i=0U;i<SUCRUNE_DNS_QUERY_LIMIT;i++) dns_cancel_job(proxy,&proxy->jobs[i],ECANCELED);
    (void)pthread_cond_broadcast(&proxy->changed);(void)pthread_mutex_unlock(&proxy->lock);dns_wake(proxy);
}
int sucrune_dns_proxy_join(struct sucrune_dns_proxy *proxy, int timeout_ms, struct sucrune_dns_stats *stats) {
    if (proxy==NULL || timeout_ms<0) return -EINVAL;
    int64_t deadline=dns_now()+(int64_t)timeout_ms;
    struct timespec limit={(time_t)(deadline/1000),(long)((deadline%1000)*1000000)};
    (void)pthread_mutex_lock(&proxy->lock);int result=0;
    if (!proxy->stopping) result=-EBUSY;
    while (result==0 && (!proxy->io_exited || proxy->workers_exited!=proxy->worker_count)) {
        int error=pthread_cond_timedwait(&proxy->changed,&proxy->lock,&limit);
        if (error!=0) result=-error;
    }
    (void)pthread_mutex_unlock(&proxy->lock);
    if (result==0 && !proxy->joined) {
        int error=pthread_join(proxy->io_thread,NULL);
        if (error!=0) result=-error;
        for (unsigned int i=0U;i<proxy->worker_count;i++) {error=pthread_join(proxy->workers[i],NULL);if (error!=0) result=-error;}
        if (result==0) proxy->joined=1;
    }
    if (stats!=NULL) {
        (void)pthread_mutex_lock(&proxy->lock);*stats=proxy->stats;stats->pending=0U;
        for (unsigned int i=0U;i<SUCRUNE_DNS_QUERY_LIMIT;i++) if (proxy->jobs[i].state!=DNS_FREE) stats->pending++;
        stats->workers_started=proxy->worker_count;stats->workers_exited=proxy->workers_exited;stats->joined=proxy->joined;
        (void)pthread_mutex_unlock(&proxy->lock);
    }
    return result;
}
int sucrune_dns_proxy_destroy(struct sucrune_dns_proxy *proxy) {
    if (proxy==NULL) return -EINVAL;
    if (!proxy->joined) return -EBUSY;
    (void)close(proxy->wake[0]);(void)close(proxy->wake[1]);
    (void)pthread_cond_destroy(&proxy->changed);(void)pthread_mutex_destroy(&proxy->lock);free(proxy);return 0;
}
#endif
