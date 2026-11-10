#include "project_scope.h"
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(expr) do { if(!(expr)) { \
    fprintf(stderr,"project scope line %d: %s (errno %d)\n",__LINE__,#expr,errno); \
    exit(1); \
} } while(0)

static pid_t start_member(int bus,int *captured) {
    int ready[2];
    CHECK(pipe(ready)==0);
    pid_t pid=fork();
    CHECK(pid>=0);
    if(pid==0) {
        CHECK(setpgid(0,0)==0);
        /* Like the real raw fork bootstrap, drop all FDs owned by the root
         * or by unrelated members before registering a fresh lease. */
        for(int fd=3;fd<256;fd++) if(fd!=bus && fd!=ready[1]) close(fd);
        /* Replicate nohup's ignored disposition and a guest with an INT
         * handler. Receipt of INT acknowledges processing the earlier HUP. */
        sucrune_scope_disposition(SIGHUP,1,0);
        sucrune_scope_disposition(SIGINT,2,0);
        int lease=sucrune_scope_join(bus);
        CHECK(lease>=3 && sucrune_scope_watch(lease)==0);
        CHECK(write(ready[1],"1",1)==1);
        for(;;) {
            usleep(1000);
            if(sucrune_scope_pending()&(1U<<(SIGINT-1))) {
                CHECK(write(ready[1],"i",1)==1);
            }
        }
    }
    close(ready[1]);
    char byte;
    CHECK(read(ready[0],&byte,1)==1);
    if(captured) *captured=ready[0]; else close(ready[0]);
    return pid;
}
static void revoked_on_owner_exit(void) {
    CHECK(prctl(PR_SET_CHILD_SUBREAPER,1,0,0,0)==0);
    int report[2];
    CHECK(pipe(report)==0);
    pid_t owner=fork();
    CHECK(owner>=0);
    if(!owner) {
        close(report[0]);
        int bus=sucrune_scope_start();
        CHECK(bus>=0);
        pid_t member=start_member(bus,NULL);
        CHECK(write(report[1],&member,sizeof(member))==sizeof(member));
        _exit(0);
    }
    close(report[1]);
    pid_t member;
    CHECK(read(report[0],&member,sizeof(member))==sizeof(member));
    close(report[0]);
    int status;
    CHECK(waitpid(owner,&status,0)==owner && WIFEXITED(status) && !WEXITSTATUS(status));
    CHECK(waitpid(member,&status,0)==member && WIFSIGNALED(status) && WTERMSIG(status)==SIGKILL);
}
int main(void) {
    alarm(10);
    revoked_on_owner_exit();
    int first=sucrune_scope_start(),second=sucrune_scope_start();
    CHECK(first>=3 && second>=3);
    int captured;
    pid_t ours=start_member(first,&captured),other=start_member(second,NULL);
    int32_t pids[SUCRUNE_SCOPE_LIMIT];
    CHECK(sucrune_scope_pids(first,pids,SUCRUNE_SCOPE_LIMIT)==1 && pids[0]==ours);
    /* The service owner is not registered; even trusted client requests
     * cannot target the control process, init, or other workspace groups. */
    CHECK(sucrune_scope_proc(first,getpid(),1)==-ESRCH);
    CHECK(sucrune_scope_signal(first,getpid(),SIGKILL)==-ESRCH);
    CHECK(sucrune_scope_signal(first,1,0)==-ESRCH);
    CHECK(sucrune_scope_signal(first,-1,SIGKILL)==-ESRCH);
    CHECK(sucrune_scope_signal(first,-other,SIGKILL)==-ESRCH);
    CHECK(sucrune_scope_signal(first,other,0)==-ESRCH);
    CHECK(sucrune_scope_proc(first,other,0)==-ESRCH);
    int stat=sucrune_scope_proc(first,ours,1);
    CHECK(stat>=0);
    char line[128];
    CHECK(read(stat,line,sizeof(line))>0);
    close(stat);
    int status;
    CHECK(sucrune_scope_signal(first,ours,SIGSTOP)==-EOPNOTSUPP);
    CHECK(sucrune_scope_signal(first,-ours,SIGHUP)==0);
    CHECK(sucrune_scope_signal(first,ours,SIGINT)==0);
    char marker;
    CHECK(read(captured,&marker,1)==1 && marker=='i');
    close(captured);
    CHECK(sucrune_scope_signal(first,ours,SIGTERM)==0);
    CHECK(waitpid(ours,&status,0)==ours && WIFSIGNALED(status) && WTERMSIG(status)==SIGTERM);
    CHECK(sucrune_scope_pids(first,pids,SUCRUNE_SCOPE_LIMIT)==0);
    CHECK(sucrune_scope_signal(second,other,0)==0);
    CHECK(sucrune_scope_signal(second,other,SIGKILL)==0);
    CHECK(waitpid(other,&status,0)==other && WIFSIGNALED(status) && WTERMSIG(status)==SIGKILL);
    puts("project process scope: isolation, signals and owner revocation passed");
    return 0;
}
