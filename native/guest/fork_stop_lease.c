/* A fresh instrumented project owns this path. The child keeps the inherited
 * locked OFD and stdout open in a different kernel session until cancellation. */
static long call(long n,long a,long b,long c,long d) {
    register long x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c,x3 __asm__("x3")=d;
    register long x4 __asm__("x4")=0,x8 __asm__("x8")=n;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x8) : "memory","cc");
    return x0;
}
static _Noreturn void finish(long code) { (void)call(94,code,0,0,0); __builtin_trap(); }
static void write_text(const char *text,long size) {
    if(call(64,1,(long)text,size,0)!=size) finish(85);
}
static _Noreturn void hold(void) { for(;;) __asm__ volatile("yield"); }
__asm__(".text\n.global _start\n.type _start,%function\n_start:\nmov x0,sp\nb run_fixture");
_Noreturn void run_fixture(const long *initial_stack) {
    long fd=call(56,-100,(long)"/fork-cancel.lease",0102,0600); /* O_CREAT|O_RDWR */
    if(fd<0 || call(32,fd,6,0,0)!=0) finish(81); /* LOCK_EX|LOCK_NB */
    if(initial_stack[0]==2) {
        if(call(57,fd,0,0,0)!=0) finish(82);
        write_text("LEASE_REACQUIRED\n",17); finish(0);
    }
    long child=call(220,17,0,0,0);
    if(child<0) finish(83);
    if(child!=0) {
        if(call(57,fd,0,0,0)!=0) finish(84);
        write_text("PARENT_CLOSED_LEASE\n",20); hold();
    }
    long pid=call(172,0,0,0,0);
    if(pid<=0 || call(157,0,0,0,0)!=pid || call(156,0,0,0,0)!=pid) finish(86);
    char line[32]="SESSION_LEASE_PID=";
    char reverse[16];
    int n=0, end=18;
    do {reverse[n++]=(char)('0'+pid%10);pid/=10;} while(pid>0);
    while(n>0) line[end++]=reverse[--n];
    line[end++]='\n'; write_text(line,end); hold();
}
