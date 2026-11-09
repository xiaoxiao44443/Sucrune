package com.sucrune.probe.tests

import org.json.JSONObject

/** execute launches the original Linux ARM64 Node with JIT and checks real
 * runner/isolated identity, exit 0, and all four cleanup barriers. */
internal fun nodeProcWorkflowCases(execute: (List<String>) -> JSONObject): List<Pair<String, () -> String>> =
    listOf("linux_node_owned_proc_stat" to {
        val script = """
            'use strict';
            const fs = require('node:fs');
            const {spawn} = require('node:child_process');
            const assert = require('node:assert/strict');
            function record(path) {
              const line = fs.readFileSync(path, 'utf8');
              const m = /^(\d+) \(([^]*)\) (\S) (.+)\n$/.exec(line);
              assert.ok(m, 'invalid proc stat');
              const fields = m[4].split(' ');
              assert.ok(fields.length >= 48);
              assert.match(fields[18], /^[1-9]\d*$/);
              for (const n of [26,27,28,29,30,35,45,46,47,48,49,50,51]) assert.equal(fields[n-4], '0');
              return {pid:Number(m[1]), ppid:Number(fields[0]), pgrp:Number(fields[1]),
                sid:Number(fields[2]), started:fields[18]};
            }
            function pids() {
              return fs.readdirSync('/proc', {withFileTypes:true}).filter(e => /^[0-9]+$/.test(e.name))
                .map(e => {assert.ok(e.isDirectory());return Number(e.name)}).sort((a,b)=>a-b);
            }
            async function run() {
              const self = record('/proc/self/stat');
              let rootMode = -1, rootErrno = 0, listCount = -1, listErrno = 0;
              try { rootMode = fs.statSync('/proc').mode } catch (e) { rootErrno = Number(e.errno) || -1 }
              try { listCount = pids().length } catch (e) { listErrno = Number(e.errno) || -1 }
              console.log(JSON.stringify({proc_snapshot:true,pid:self.pid,ppid:self.ppid,pgrp:self.pgrp,
                sid:self.sid,root_mode:rootMode,root_errno:rootErrno,list_count:listCount,list_errno:listErrno}));
              assert.equal(self.pid, process.pid);
              assert.deepEqual(record('/proc/'+self.pid+'/stat'),self);
              // Kernel session/group IDs can be zero in the caller's PID namespace.
              assert.ok(Number.isSafeInteger(self.pgrp) && self.pgrp>=0, 'invalid proc pgrp '+self.pgrp);
              assert.ok(Number.isSafeInteger(self.sid) && self.sid>=0, 'invalid proc sid '+self.sid);
              assert.equal(rootErrno,0,'stat /proc errno '+rootErrno);
              assert.equal(rootMode & 0o170000,0o040000,'stat /proc mode '+rootMode);
              assert.equal(listErrno,0,'readdir /proc errno '+listErrno);
              assert.deepEqual(pids(), [self.pid]);
              for (const path of ['/proc/1/stat','/proc/self/mem','/proc/self/fd/0','/proc/self/task','/proc/uptime'])
                assert.throws(() => fs.readFileSync(path), {code:'ENOENT'});
              assert.throws(() => fs.openSync('/proc/self/stat','w'), {code:'EROFS'});
              const child = spawn('/usr/bin/node', ['-e', "process.stdin.resume();process.stdout.write('READY\\n')"],
                {stdio:['pipe','pipe','inherit']});
              const done = new Promise((ok,fail)=>{child.once('error',fail);child.once('close',(code,signal)=>ok({code,signal}))});
              const childPid = child.pid;
              try {
                let ready='';
                for await (const chunk of child.stdout) {
                  ready+=chunk.toString(); if(ready.includes('\n')) break;
                }
                assert.equal(ready,'READY\n');
                const view = record('/proc/'+childPid+'/stat');
                assert.equal(view.pid,childPid);
                assert.equal(view.ppid,self.pid);
                assert.ok(BigInt(view.started)>=BigInt(self.started));
                assert.deepEqual(pids(), [self.pid,childPid].sort((a,b)=>a-b));
              } finally { child.stdin.end() }
              assert.deepEqual(await done,{code:0,signal:null});
              assert.deepEqual(pids(), [self.pid]);
              assert.throws(()=>record('/proc/'+childPid+'/stat'),{code:'ENOENT'});
              console.log(JSON.stringify({pid:self.pid,child:childPid,owned_stat:true,reaped:true}));
            }
            run().catch(e=>{console.error(String(e));process.exitCode=1});
        """.trimIndent()
        val record = execute(listOf("-e", script))
        val output = record.getString("stdout").trim().lines()
        check(output.size == 2 && JSONObject(output.first()).getBoolean("proc_snapshot"))
        val evidence = JSONObject(output.last())
        val native = record.getJSONObject("result").getJSONObject("native")
        check(evidence.getInt("pid") == native.getInt("runner_pid") &&
            evidence.getInt("child") > 0 && evidence.getInt("child") != evidence.getInt("pid") &&
            evidence.getBoolean("owned_stat") && evidence.getBoolean("reaped"))
        "Original Node read real self/child stat, enumerated owned PIDs, rejected writes/foreign paths and lost access after wait"
    }, "linux_node_owned_child_kill_wait" to {
        val script = """
            'use strict';
            const assert = require('node:assert/strict');
            const {spawn} = require('node:child_process');
            async function run() {
              const child = spawn('/usr/bin/node', ['-e',"process.stdin.resume(); console.log('READY')"],
                {stdio:['pipe','pipe','inherit']});
              const done = new Promise((ok,fail)=>{
                child.once('error',fail); child.once('close',(code,signal)=>ok({code,signal}));
              });
              const pid = child.pid;
              try {
                let ready = '';
                for await (const chunk of child.stdout) {ready +=chunk; if(ready.includes('\n')) break}
                assert.equal(ready, 'READY\n');
                assert.equal(process.kill(pid,0),true);
                // Probe only signal zero for unowned PIDs and groups.
                assert.throws(()=>process.kill(1,0),{code:'ESRCH'});
                assert.throws(()=>process.kill(-pid,0),e=>e.code==='ENOTSUP'||e.code==='EOPNOTSUPP');
                assert.throws(()=>process.kill(pid,'SIGWINCH'),e=>e.code==='ENOTSUP'||e.code==='EOPNOTSUPP');
                assert.equal(process.kill(pid,'SIGKILL'),true);
              } finally {child.stdin.end()}
              assert.deepEqual(await done,{code:null,signal:'SIGKILL'});
              assert.throws(()=>process.kill(pid,0),{code:'ESRCH'});
              console.log('OWNED_CHILD_SIGKILL_WAIT');
            }
            run().catch(e=>{console.error(String(e));process.exitCode=1});
        """.trimIndent()
        val record = execute(listOf("-e", script))
        check(record.getString("stdout") == "OWNED_CHILD_SIGKILL_WAIT\n" && record.getString("stderr").isEmpty())
        "Original Node checked its direct child, rejected unowned/group probes, sent SIGKILL and received the real wait signal"
    })
