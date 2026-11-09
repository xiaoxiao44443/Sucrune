package com.sucrune.probe.tests

import org.json.JSONObject

/** Run the registered DSH tool with an in-memory Agent and its real PTY.
 * Diagnostics describe only this offline fixture's phase, error class and measurements. */
internal fun checkDshPersistentBash(captureInitOutput: Boolean = false, toolbox: Boolean = false,
                                    writeFixture: (String, String) -> Unit,
                                    execute: (List<String>) -> JSONObject): String {
    checkDshFileTools(execute)
    val diagnostic = """
        import fs from 'node:fs';
        export function emit(tag, ...values) {
          console.log('SUC_DIAG ' + [tag,...values].join(' '));
        }
        const errors = ['ENOENT','EACCES','EPERM','EINVAL','ENOSYS','ENOTDIR','EIO','EMFILE',
          'ERR_MODULE_NOT_FOUND','MODULE_NOT_FOUND','ERR_DLOPEN_FAILED','ERR_ASSERTION','SEND_ACTIVE',
          'NO_BACKEND','OWNER_NOT_LIVE','FOREIGN_SESSION','TimeoutError','TypeError','RangeError'];
        const messages = [
          'Cannot inspect processes: /proc directory is unreadable',
          'PTY shell exited during startup','PTY shell did not reach readiness before startup timeout',
          'persistent bash shell did not accept initialization','cannot resolve foreground process group',
          'PTY cleanup failed','PTY session has exited','PTY session is closing',
          'did not reach quiescence','Failed to load native binding','requires an owning agent session',
          'Cannot read properties of','is not a function','Bash tool result mismatch',
          'no active service','is not available','is not registered','Failed to load',
          'posix_spawn','forkpty','no-realm','tool-bash-persistent disposed'];
        export function error(phase, e) {
          const pending = [e], seen = new Set();
          for (let i=0; i<pending.length && seen.size<8; i++) {
            const v = pending[i];
            if (!v || seen.has(v)) continue;
            seen.add(v);
            const code = errors.findIndex(x => x===v.code || x===v.name)+1;
            const reason = messages.findIndex(x => String(v.message || '').includes(x))+1;
            const errno = Number.isInteger(v.errno) && Math.abs(v.errno)<=4096 ? v.errno : 0;
            const sys = ['open','openat','read','scandir','stat','lstat','readlink','realpath','spawn','kill'].indexOf(v.syscall)+1;
            emit('error',phase,code,reason,errno,sys);
            pending.push(v.cause,v.spawnError,v.cleanupError,...(Array.isArray(v.errors)?v.errors.slice(0,8):[]));
          }
        }
        function fields(pid) {
          const s=fs.readFileSync('/proc/'+pid+'/stat','utf8');
          return s.slice(s.lastIndexOf(') ')+2).trim().split(/\s+/);
        }
        export function sample(phase, list) {
          let mask=0, children=0, childFlags=0;
          try { if (fs.statSync('/proc').isDirectory()) mask|=1; } catch {}
          try {
            const me=fields(process.pid); mask|=2;
            if (+me[2]>0) mask|=4; if (+me[3]>0) mask|=8;
          } catch {}
          try {
            const rows=fs.readdirSync('/proc'); mask|=16;
            if (rows.includes(String(process.pid))) mask|=32;
            for (const x of rows.filter(v=>/^\d+$/.test(v)).slice(0,65)) try {
              const f=fields(x); if (+f[1]!==process.pid) continue;
              children++;
              if (+f[2]===+x) childFlags|=1;
              if (+f[3]===+x) childFlags|=2;
              if (+f[4]!==0) childFlags|=4;
              if (+f[5]===+x) childFlags|=8;
            } catch {}
          } catch {}
          return [phase,mask,children,childFlags,list().length];
        }
        export function output(phase, text, expected) {
          if (typeof text!=='string') {emit('result',phase,0,0,-1);return;}
          const lines=text.split(/\r?\n/);
          const status=/^\[Command finished with exit code (\d{1,3})\]$/.exec(lines.at(-1));
          let mask=1;
          if (text===expected) mask|=2;
          if (text.includes('[Command timed out or OOM]')) mask|=4;
          if (text.includes('persistent bash shell was reset')) mask|=8;
          if (text.includes('[shell exited:') || text.includes('[shell killed by signal:')) mask|=16;
          if (text.includes('__DSH_PERSISTENT_BASH_')) mask|=32;
          if (lines[0]===expected.split('\n')[0]) mask|=64;
          emit('result',phase,mask,Math.min(text.length,65536),status?+status[1]:-1);
        }
    """.trimIndent()
    val observers = """
        export function attach(registry, provider, emit) {
          const undo=[]; let foreground=0, writes=0, raw=0, bytes=0, tail='', sent=0, lastfg=-1;
          const home='/workspace/terminal-check', allowed=['HOME','PATH','SHELL','PWD','LANG','LC_ALL',
            'LD_LIBRARY_PATH','SUCRUNE_MEMORY_POLICY','SUCRUNE_NETWORK_POLICY'];
          let collect=process.argv[2]==='capture-init' && process.cwd()===home && process.env.HOME===home &&
            (process.env.SUCRUNE_NETWORK_POLICY||'none')==='none' && Object.keys(process.env).every(k=>allowed.includes(k));
          let init=Buffer.alloc(0);
          const numeric=x=>Number.isInteger(x)&&Math.abs(x)<=65536?x:-1;
          const elapsed=t=>Math.min(65536,Math.max(0,Date.now()-t));
          const sig=s=>[null,'SIGHUP','SIGINT','SIGQUIT','SIGKILL','SIGTERM','SIGPIPE','SIGABRT','SIGSEGV','SIGBUS','SIGILL'].indexOf(s);
          const kind=t=>t==='stty -echo; set +H'||t==='stty -echo; set +H\r'?1:
            typeof t==='string'&&t.includes('__DSH_PERSISTENT_BASH_START_')?2:t===''?3:0;
          const flags=s=>{
            let n=0; for(const [i,mark] of ['dsh> ','\x1b]133;D;','stty -echo','stty:',
              'command not found','Inappropriate ioctl','Permission denied','Operation not permitted',
              'No such file','cannot set terminal process group','no job control','Segmentation fault',
              'error while loading shared libraries','Trace/breakpoint trap'].entries()) if(s.includes(mark)) n|=1<<i;
            return n;
          };
          function safe(f) { try { f(); } catch {} }
          function watch(p,done) { p.then(v=>safe(()=>done(v)),()=>{}); }
          function wrap(obj,key,before,after) {
            const prior=obj[key], own=Object.getOwnPropertyDescriptor(obj,key);
            function tap(...args) {
              const t=Date.now(); if(before)safe(()=>before(args));
              const result=Reflect.apply(prior,this,args);
              if(after)safe(()=>after(args,result,t));
              return result;
            }
            Object.defineProperty(obj,key,{configurable:true,writable:true,value:tap});
            undo.push(()=>{if(obj[key]===tap){if(own)Object.defineProperty(obj,key,own);else delete obj[key];}});
          }
          wrap(provider,'spawnTerminal',a=>emit('spawn',0,a[0]?.argv?.[0]==='/bin/bash'?1:0),
            (_,p,t)=>watch(p,h=>{
              emit('spawn',1,elapsed(t));
              watch(h.done,v=>{
                emit('exit',numeric(v.exitCode),sig(v.signal),raw,bytes,sent);
                if(collect && v.exitCode===159 && !v.signal && sent>0 && init.length>0 && bytes===init.length)
                  console.log('SUC_INIT '+init.toString('hex'));
                init.fill(0);init=Buffer.alloc(0);collect=false;
              });
              wrap(h.output,'write',([chunk])=>{
                if(typeof chunk!=='string'&&!Buffer.isBuffer(chunk))return;
                if(collect){const b=Buffer.from(chunk);if(init.length+b.length<=256)init=Buffer.concat([init,b]);else collect=false;}
                const s=tail+chunk.toString('utf8'); tail=s.slice(-64);
                raw|=flags(s); bytes=Math.min(65536,bytes+chunk.length);
              });
              wrap(h,'inspectForeground',null,(_,p)=>watch(p,f=>{
                foreground=Math.min(65536,foreground+1);
                const v=f===undefined?0:1+(f.processGroupId===h.pid?1:0)+(f.inputWaiting===true?4:0);
                if(v!==lastfg&&foreground<=20){emit('fg',foreground,v);lastfg=v;}
              }));
              wrap(h,'write',([s])=>{writes++;const k=kind(s);if(k===1)sent=1;else collect=false;
                if(writes<=6)emit('write',k,Math.min(65536,s.length));},
                ([s],p)=>{if(kind(s)===1)watch(p,()=>{sent=2;emit('write',4,0);});});
            }));
          wrap(registry,'spawn',()=>emit('spawn',2,0),(_,p,t)=>watch(p,s=>emit('ready',elapsed(t),flags(s.motd||''),raw,bytes)));
          wrap(registry,'startSend',a=>emit('send',kind(a[2]?.text),a[2]?.submit===true?1:0),
            (a,op,t)=>watch(op.done,v=>emit('sent',kind(a[2]?.text),
              ['stdin_read','inferred_idle','timeout','session_exit'].indexOf(v.waitReason)+1,
              v.sessionStatus.kind==='exited'?1:0,numeric(v.sessionStatus.exitCode),sig(v.sessionStatus.signal),
              elapsed(t),foreground,writes,raw,flags(v.viewport||''),bytes)));
          return ()=>{for(const restore of undo.reverse()) safe(restore);};
        }
    """.trimIndent()
    val script = """
        import assert from 'node:assert/strict';
        import fs from 'node:fs';
        import path from 'node:path';
        import { randomBytes } from 'node:crypto';
        import { createRequire } from 'node:module';
        import * as d from './bash-diagnostics.mjs';
        const resolve=createRequire('/opt/dsh/package.json').resolve;
        const load=name=>import(resolve('@deepseek-ai/'+name));
        let ctx,handle,tmp,timer,detach,phase=0,failed=false;
        function step(n){ phase=n; d.emit('stage',n); }
        process.on('uncaughtExceptionMonitor',e=>d.error(phase,e));
        try {
          step(1);
          const { Context }=await load('cordis');
          ctx=new Context();
          const cwd=process.cwd(), config={
            'fs-local':{cwd}, 'working-directory':{defaultDirectory:cwd},
            'sandbox-policy':{mode:'danger-full-access',workspaceRoot:cwd},
            'tool-bash-persistent':{timeoutMs:35000}
          };
          const plugins=['session','session-projection','system-prompt','llm','tools','agent',
            'agent-loop','fs-local','working-directory','sandbox-policy','subprocess-local',
            'terminal','terminal-bash','tool-bash-persistent'];
          for (const [i,name] of plugins.entries()) {
            step(10+i);
            const m=await load('dsh-'+name);
            await ctx.plugin(m.default || m,config[name] || {});
          }
          step(30);
          const {attach}=await import('./bash-observers.mjs');
          detach=attach((await load('dsh-terminal')).TerminalSessionService.prototype,
            (await load('dsh-subprocess-local')).LocalSubprocessRuntime.prototype,d.emit);
          assert.deepEqual(ctx.llm.listProviders(),[]);
          assert.equal(ctx.get('sessionPersistence'),undefined);
          handle=await ctx.agents.create({sessionId:'bash-fixture',meta:{cwd}});
          step(31);
          const owner=handle.agent,tool=ctx.tools.get('bash',owner);
          assert.equal(tool?.name,'bash'); assert.ok(ctx.terminals.listBackends().includes('shell'));
          const list=()=>ctx.terminals.list(owner);
          const call=command=>tool.execute({command},{agent:owner,signal:AbortSignal.timeout(42000)});
          const nonce=randomBytes(12).toString('hex');
          tmp=fs.mkdtempSync(path.join(cwd,'dsh-bash-'));
          const dir=path.basename(tmp);
          let previous='', emitted=0;
          function observe() {
            try {
              const row=d.sample(phase,list), signature=row.join(',');
              if (previous!==signature && emitted<20) { d.emit('proc',...row); previous=signature; emitted++; }
            } catch(e) { d.error(phase,e); }
          }
          step(40); observe(); timer=setInterval(observe,1500); timer.unref();
          const first=await call('cd '+dir+' && keep='+nonce+' && printf "%s\\n" "${'$'}BASHPID"');
          step(41); observe();
          const [pty]=list();
          const expected=pty?.pid+'\n[Command finished with exit code 0]';
          d.output(phase,first,expected);
          assert.ok(pty && Number.isSafeInteger(pty.pid) && pty.pid>0);
          assert.equal(first,expected,'Bash tool result mismatch');
          step(42);
          const second=await call('printf "%s\\n" "${'$'}keep" > proof && printf "%s:%s\\n" "${'$'}BASHPID" "${'$'}keep" && (exit 7)');
          step(43); observe();
          const wanted=pty.pid+':'+nonce+'\n[Command finished with exit code 7]';
          d.output(phase,second,wanted); assert.equal(second,wanted,'Bash tool result mismatch');
          step(44);
          const live=list(); assert.equal(live.length,1); assert.equal(live[0].sessionId,pty.sessionId);
          assert.equal(live[0].pid,pty.pid);
          assert.equal(fs.readFileSync(path.join(tmp,'proof'),'utf8'),nonce+'\n');
          if (process.argv[3]==='toolbox') {
            const tools=await call("git --version && curl --version > curl-version && rg -q '^curl ' curl-version && python3 -B -c 'import json; print(json.dumps([2,3]))' | jq 'add' > total && cat total");
            if (!/^git version [0-9.]+\r?\n5\r?\n\[Command finished with exit code 0\]$/.test(tools)) {
              // This offline fixture has an empty provider list and fixed, public inputs.
              if(process.argv[2]==='capture-init') console.log('SUC_TOOLBOX '+Buffer.from(String(tools)).subarray(0,600).toString('hex'));
              assert.fail('Bash tool result mismatch');
            }
            assert.equal(fs.readFileSync(path.join(tmp,'total'),'utf8'),'5\n');
          }
          step(45); await handle.dispose(); handle=undefined; assert.equal(ctx.terminals.hasOwnerActivity(owner),false);
        } catch(e) { d.error(phase,e); failed=true; }
        finally {
          clearInterval(timer);
          for (const [n,fn] of [[50,()=>handle?.dispose()],[51,()=>ctx?.fiber.dispose()],
              [52,()=>{if(tmp)try{fs.unlinkSync(path.join(tmp,'proof'));}catch(e){if(e.code!=='ENOENT')throw e;}}],
              [53,()=>{if(tmp){for(const name of ['total','curl-version']) fs.rmSync(path.join(tmp,name),{force:true}); fs.rmdirSync(tmp);}}],
              [54,()=>{if(tmp)assert.equal(fs.lstatSync(tmp,{throwIfNoEntry:false}),undefined);}]]) {
            step(n); try{await fn();}catch(e){d.error(n,e);failed=true;}
          }
        }
        detach?.();
        if(failed) process.exitCode=1; else step(60);
    """.trimIndent()
    writeFixture("bash-diagnostics.mjs", diagnostic)
    writeFixture("bash-observers.mjs", observers)
    writeFixture("bash-workflow.mjs", script)
    val result = execute(listOf("/workspace/terminal-check/bash-workflow.mjs",
        if (captureInitOutput) "capture-init" else "none", if (toolbox) "toolbox" else "none"))
    val counts = mapOf("stage" to 1, "proc" to 5, "error" to 5, "result" to 4,
        "spawn" to 2, "ready" to 4, "fg" to 2, "write" to 2, "exit" to 5, "send" to 2, "sent" to 11)
    val observations = result.optString("stdout").lineSequence().filter { it.startsWith("SUC_DIAG ") }
        .map { it.removePrefix("SUC_DIAG ").split(' ') }.filter { row ->
            counts[row.first()] == row.size - 1 && row.drop(1).all { it.toIntOrNull() in -4096..65536 }
        }.take(100).toList()
    val stages = observations.filter { it.first() == "stage" }.map { it[1].toInt() }
    val expected = listOf(1) + (10..23) + listOf(30, 31, 40, 41, 42, 43, 44, 45, 50, 51, 52, 53, 54, 60)
    val state = result.optString("state").takeIf { it in setOf("exited", "failed", "cancelled", "timed_out", "lost") } ?: "other"
    val exit = result.optInt("exit_code", -1)
    val syscall = result.optJSONObject("result")?.optJSONObject("native")?.optInt("last_unsupported_syscall", -1) ?: -1
    check(state == "exited" && exit == 0 && stages == expected && observations.none { it.first() == "error" }) {
        val detail = observations.joinToString(";") { it.joinToString(",") }
        val init = if (captureInitOutput) result.optString("stdout").lineSequence().filter { it.startsWith("SUC_INIT ") }
            .map { it.removePrefix("SUC_INIT ") }.singleOrNull()?.takeIf { it.length in 2..512 &&
                it.length % 2 == 0 && it.all { c -> c in '0'..'9' || c in 'a'..'f' } } else null
        val toolOutput = if (toolbox && captureInitOutput) result.optString("stdout").lineSequence()
            .firstOrNull { it.matches(Regex("SUC_TOOLBOX [0-9a-f]{2,1200}")) }?.substringAfter(' ') else null
        "Original DSH Bash state=$state exit=$exit syscall=$syscall $detail" + (init?.let { " offline_init_hex=$it" } ?: "") +
            (toolOutput?.let { " offline_tool_hex=$it" } ?: "")
    }
    return "Original DSH write/read and persistent Bash verified on the same PTY" +
        if (toolbox) ". Git, curl, rg, Python, jq and cat produced a verified project file." else "."
}
