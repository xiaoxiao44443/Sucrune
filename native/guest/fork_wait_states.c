/* Linux ARM64 guest fixture. The pipe keeps each state stable until its actual
 * parent has checked the kernel wait status. No host signal helper is used. */
static long call(long number,long a,long b,long c,long d) {
    register long x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c,x3 __asm__("x3")=d;
    register long x4 __asm__("x4")=0,x8 __asm__("x8")=number;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x8) : "memory","cc");
    return x0;
}
static _Noreturn void finish(long code) { (void)call(94,code,0,0,0); __builtin_trap(); }
_Noreturn void _start(void) {
    enum { HOLE=0x5754, WNOHANG=1, WUNTRACED=2, WCONTINUED=8, SIGCONT=18, SIGSTOP=19 };
    long any_child=0xffffffffL; /* glibc can zero-extend (pid_t)-1 in x0. */
    int pipefd[2],status=HOLE; char token=0;
    if(call(59,(long)pipefd,0,0,0)!=0) finish(21);
    long child=call(220,17,0,0,0);
    if(child<0) finish(22);
    if(child==0) {
        if(call(57,pipefd[1],0,0,0)!=0) finish(23);
        if(call(63,pipefd[0],(long)&token,1,0)!=1 || token!='S') finish(24);
        long self=call(172,0,0,0,0);
        if(self<=0 || call(129,self,SIGSTOP,0,0)!=0) finish(25);
        if(call(63,pipefd[0],(long)&token,1,0)!=1 || token!='E') finish(26);
        finish(41);
    }
    if(call(57,pipefd[0],0,0,0)!=0) finish(27);
    if(call(260,any_child,(long)&status,WNOHANG|WUNTRACED|WCONTINUED,0)!=0 || status!=HOLE) finish(28);
    if(call(260,1,(long)&status,WNOHANG,0)!=-10 || call(260,0,(long)&status,WNOHANG,0)!=-95) finish(29);
    if(call(64,pipefd[1],(long)"S",1,0)!=1) finish(30);
    if(call(260,any_child,(long)&status,WUNTRACED,0)!=child || status!=((SIGSTOP<<8)|0x7f)) finish(31);
    status=HOLE;
    if(call(260,child,(long)&status,WNOHANG,0)!=0 || status!=HOLE) finish(32);
    if(call(260,child,(long)&status,WNOHANG|WUNTRACED,0)!=0 || status!=HOLE) finish(33);
    if(call(129,child,SIGCONT,0,0)!=0) finish(34);
    if(call(260,child,(long)&status,WCONTINUED,0)!=child || status!=0xffff) finish(35);
    status=HOLE;
    if(call(260,child,(long)&status,WNOHANG|WCONTINUED,0)!=0 || status!=HOLE) finish(36);
    if(call(64,pipefd[1],(long)"E",1,0)!=1 || call(57,pipefd[1],0,0,0)!=0) finish(37);
    if(call(260,any_child,(long)&status,0,0)!=child || status!=(41<<8)) finish(38);
    if(call(260,child,(long)&status,WNOHANG|WCONTINUED|WUNTRACED,0)!=-10) finish(39);
    const char result[]="fork-stop-continue-wait-ok\n";
    if(call(64,1,(long)result,sizeof(result)-1,0)!=sizeof(result)-1) finish(40);
    finish(0);
}
