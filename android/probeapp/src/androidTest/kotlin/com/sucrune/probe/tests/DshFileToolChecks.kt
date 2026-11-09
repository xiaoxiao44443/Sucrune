package com.sucrune.probe.tests

import org.json.JSONObject

/** Exercise the original model-facing file tools in a credential-free, in-memory
 * Agent. In particular a successful write must pass the package's path chmod,
 * file fchmod, write, fsync, rename and sibling staging-directory cleanup. */
internal fun checkDshFileTools(execute: (List<String>) -> JSONObject) {
    val script = """
        import assert from 'node:assert/strict';
        import fs from 'node:fs';
        import path from 'node:path';
        import {randomBytes} from 'node:crypto';
        import {createRequire} from 'node:module';
        const resolve=createRequire('/opt/dsh/package.json').resolve;
        const load=n=>import(resolve('@deepseek-ai/'+n));
        const {Context}=await load('cordis'), ctx=new Context();
        let handle,cwd,file,phase=0,failed=false;
        function stage(n){phase=n;console.log('SUC_FS stage '+n);}
        function report(e){
          failed=true;
          const codes=['FS_PERMISSION_DENIED','FS_IO_ERROR','FS_NOT_FOUND','FS_NOT_OBSERVED','FS_STALE_VERSION',
            'ENOENT','EEXIST','ENOSYS','EPERM','EACCES','EINVAL','ENOTEMPTY','ERR_ASSERTION'];
          const ops=['chmod','fchmod','open','mkdir','fsync','write','rename','link','unlink','rmdir','scandir'];
          for(let i=0;e && i<5;i++,e=e.cause) {
            const num=Number.isInteger(e.errno)&&Math.abs(e.errno)<=4096?e.errno:0;
            console.log('SUC_FS error '+[phase,codes.indexOf(e.code)+1,ops.indexOf(e.syscall)+1,num].join(' '));
          }
        }
        try{
          stage(1);cwd=fs.mkdtempSync(path.join(process.cwd(),'dsh-file-'));file=path.join(cwd,'proof');
          const configs={'fs-local':{cwd},'working-directory':{defaultDirectory:cwd},
            'sandbox-policy':{mode:'danger-full-access',workspaceRoot:cwd},
            'tool-fs':{read:true,write:true,edit:true,readImage:false}};
          for(const n of ['session','session-projection','system-prompt','llm','tools','agent','agent-loop',
              'fs-local','working-directory','sandbox-policy','tool-fs']){
            const m=await load('dsh-'+n);await ctx.plugin(m.default||m,configs[n]||{});
          }
          stage(2);assert.deepEqual(ctx.llm.listProviders(),[]);assert.equal(ctx.get('sessionPersistence'),undefined);
          handle=await ctx.agents.create({sessionId:'fs-proof',meta:{cwd}});
          const agent=handle.agent,run={agent,signal:AbortSignal.timeout(45000)};
          const write=ctx.tools.get('write',agent),read=ctx.tools.get('read',agent);
          const token=randomBytes(12).toString('hex');
          for(const [i,operation,mode] of [[0,'create',0o600],[1,'update',0o640]]){
            stage(i?5:3);
            const body=token+'-'+i,args={file_path:i?'./proof':file,content:body+'\n'};
            const w=await write.execute(args,run);
            assert.equal(w.path,file);assert.equal(w.operation,operation);
            const text=write.output.render(args,w)[0].text;
            assert.ok(text.includes('<path>'+file+'</path>')&&text.split('\n').includes(i?'Updated file':'Created file'));
            assert.deepEqual(fs.readdirSync(cwd),['proof']);assert.equal(fs.statSync(file).mode&0o777,mode);
            assert.equal(fs.readFileSync(file,'utf8'),body+'\n');
            stage(i?6:4);
            const q={file_path:'./proof'},r=await read.execute(q,run);
            assert.equal(r.path,file);assert.equal(r.lines[0].text,body);
            assert.ok(read.output.render(q,r)[0].text.split('\n').includes('1: '+body));
            if(!i){const fd=fs.openSync(file,'r+');try{fs.fchmodSync(fd,0o640);}finally{fs.closeSync(fd);}}
          }
        }catch(e){report(e);}finally{
          for(const [n,fn] of [[7,()=>handle?.dispose()],[8,()=>ctx.fiber.dispose()],
            [9,()=>{if(file)try{fs.unlinkSync(file);}catch(e){if(e.code!=='ENOENT')throw e;}}],
            [10,()=>{if(cwd)fs.rmdirSync(cwd);}]]){stage(n);try{await fn();}catch(e){report(e);}}
        }
        if(failed)process.exitCode=1;else stage(11);
    """.trimIndent()
    val result = execute(listOf("--input-type=module", "-e", script))
    val observations = result.optString("stdout").lineSequence().filter { it.startsWith("SUC_FS ") }
        .map { it.removePrefix("SUC_FS ").split(' ') }.filter { row ->
            ((row.first() == "stage" && row.size == 2) || (row.first() == "error" && row.size == 5)) &&
                row.drop(1).all { it.toIntOrNull() in -4096..4096 }
        }.take(40).toList()
    check(result.optString("state") == "exited" && result.optInt("exit_code", -1) == 0 &&
        observations == (1..11).map { listOf("stage", it.toString()) }) {
        "Original DSH file tools failed " + observations.joinToString(";") { it.joinToString(",") }
    }
}
