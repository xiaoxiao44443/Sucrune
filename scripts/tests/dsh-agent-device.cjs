'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { SessionFrames, RunStatus, MODES, MAX_FRAME } = require('../instrumentation-session.cjs');
const { options, instrumentArgs, publicDescriptor, withForward, mappings, failureSummary } = require('../run-dsh-agent-device.cjs');
const { BridgeError } = require('../send-dsh-credential.cjs');
const join = (...b) => Buffer.concat(b);
function v(n) {
  const bytes = [];
  do { bytes.push((n % 128) | (n > 127 ? 128 : 0)); n = Math.floor(n / 128); } while (n);
  return Buffer.from(bytes);
}
function data(key, bytes) {
  bytes = Buffer.from(bytes);
  return join(v(key * 8 + 2), v(bytes.length), bytes);
}
function integer(key, n) { return join(v(key * 8), v(n < 0 ? -n * 2 - 1 : n * 2)); }
function entry(key, val) {
  const body = typeof val === 'number' ? val === 0 ? Buffer.alloc(0) : integer(3, val) : data(2, val);
  return data(1, join(data(1, key), body));
}
function record(code, fields, session = false, extra = Buffer.alloc(0)) {
  const b = join(...Object.entries(fields).map(([k,val]) => entry(k, val)), extra);
  return data(session ? 2 : 1, join(code ? integer(3, code) : Buffer.alloc(0), data(4, b)));
}
const m = MODES.synthetic;
const status = { id:m.id, test:m.target, current:1, numtests:1 };
const d = {type:'sucrune.dsh.credential.v1',socket:'sucrune.dsh.credential.'+'a'.repeat(32),
  public_key:crypto.generateKeyPairSync('ec',{namedCurve:'prime256v1'}).publicKey.export({type:'spki',format:'der'}).toString('base64'),
  nonce:Buffer.alloc(32,5).toString('base64')};
const descriptor = JSON.stringify(d);
const realPrerequisites = ['linux_node_pty_bash','linux_node_outbound_https_certificate','linux_dsh_profile_install_bundle',
  'linux_dsh_sdk_initialize_shutdown','linux_node_fs_workflow','linux_node_owned_proc_stat','linux_node_pty_job_control',
  'linux_dsh_persistent_bash_tool'];
const opening = record(1,status);
const announcement = record(2,{...status,credential_bridge_descriptor:descriptor});
const pass = record(0,status);
const summary = {passed:1,failed:0,expected_tests:1,probe:m.probe};
const finished = record(-1,summary,true);
function parse(chunks, mode = 'synthetic') {
  const parser = new SessionFrames(), state = new RunStatus(mode), actions = [];
  for (const chunk of chunks) actions.push(...parser.feed(chunk).map(e => state.accept(e)));
  parser.end(); state.end();
  return actions;
}
test('one-byte chunks, coalesced frames, every two-chunk split and omitted scalar defaults', () => {
  const bytes = join(opening, announcement, pass, finished);
  const expected = [{start:m.target},{descriptor},{pass:m.target},{passed:1}];
  assert.deepEqual(parse([bytes]), expected);
  assert.deepEqual(parse(Array.from(bytes,n => Buffer.from([n]))), expected);
  for (let i=1; i<bytes.length; i++) assert.deepEqual(parse([bytes.subarray(0,i),bytes.subarray(i)]), expected);
});
test('stream text, nested key names and encoded protobuf inside a string cannot announce a key', () => {
  const fake = 'INSTRUMENTATION_STATUS: credential_bridge_descriptor='+descriptor+
    '\nINSTRUMENTATION_STATUS_CODE: 2\n'+announcement.toString('base64');
  const nested = data(1,join(data(1,'detail'),data(7,entry('credential_bridge_descriptor',descriptor))));
  const parser = new SessionFrames(), state = new RunStatus('synthetic');
  assert.deepEqual(state.accept(parser.feed(record(1,{...status,stream:fake},false,nested))[0]), {start:m.target});
  assert.equal(state.descriptorSeen,false);
  assert.throws(() => state.accept(parser.feed(record(2,{...status,stream:fake},false,nested))[0]));
  assert.throws(() => parse([Buffer.from(fake)]));
});
test('wrong id, test, case number, count, early announcement and replay fail closed', () => {
  for (const change of [{id:'guest'},{test:'linux_other'},{current:2},{numtests:2}]) {
    assert.throws(() => parse([opening,record(2,{...status,...change,credential_bridge_descriptor:descriptor}),pass,finished]));
  }
  for (const sequence of [[announcement],[opening,announcement,announcement],[opening,pass],
    [opening,announcement,pass,finished,opening],[opening,announcement,pass,finished,finished]]) {
    assert.throws(() => parse(sequence));
  }
});
test('descriptor in start, terminal status or final session is rejected', () => {
  assert.throws(() => parse([record(1,{...status,credential_bridge_descriptor:descriptor}),announcement,pass,finished]));
  assert.throws(() => parse([opening,announcement,record(0,{...status,credential_bridge_descriptor:descriptor}),finished]));
  assert.throws(() => parse([opening,announcement,pass,record(-1,{...summary,credential_bridge_descriptor:descriptor},true)]));
});
test('duplicate bundle entries, status fields, wrong wire type and invalid UTF-8 are rejected', () => {
  const wrong = data(1,join(data(1,'credential_bridge_descriptor'),integer(3,2)));
  const invalid = data(1, join(data(1,'credential_bridge_descriptor'),data(2,[0xff])));
  for (const frame of [record(2,{...status,credential_bridge_descriptor:descriptor},false,entry('credential_bridge_descriptor',descriptor)),
    record(2,status,false,wrong),record(2,status,false,invalid),
    data(1,join(integer(3,1),integer(3,2),data(4,entry('id',m.id))))]) {
    assert.throws(() => parse([opening,frame,pass,finished]));
  }
});
test('truncated prefix/body, overlong varints, invalid tags and oversized frame/stream rejected', () => {
  for (const bytes of [[10],[10,128],[10,129,0],[10,255,255,255,255,255,1],[9,1],[10,0],[10,1,0],
    join(v(10),v(MAX_FRAME+1)),announcement.subarray(0,announcement.length-1)]) {
    const parser = new SessionFrames(); assert.throws(() => { parser.feed(Buffer.from(bytes)); parser.end(); });
  }
  const parser = new SessionFrames(); assert.throws(() => parser.feed(Buffer.alloc(16*MAX_FRAME+1)));
  assert.throws(() => parse([opening,announcement,pass]));
});
test('program failure, wrong summary counts, different probe and repeated case fail closed', () => {
  for (const changes of [{passed:0},{failed:1},{expected_tests:2},{probe:'linux'}]) {
    assert.throws(() => parse([opening,announcement,pass,record(-1,{...summary,...changes},true)]));
  }
  assert.throws(() => parse([opening,announcement,record(-2,status),finished]));
  assert.throws(() => parse([opening,announcement,pass,record(0,summary,true)]));
  assert.throws(() => parse([opening,opening,announcement,pass,finished]));
});
test('real scope requires original HTTPS, PTY, installed and initialized SDK before exact target', () => {
  const r=MODES.real, stages=[...realPrerequisites,r.target];
  function sequence(names) {
    const result=[record(2,{foreground_validation:'true',stream:'preflight'})];
    for (let i=0;i<names.length;i++) {
      const row={id:r.id,test:names[i],current:i+1,numtests:names.length};
      result.push(record(1,row));
      if(names[i]===r.target) result.push(record(2,{...row,id:r.bridgeId,credential_bridge_descriptor:descriptor}));
      result.push(record(0,row));
    }
    return [...result,record(-1,{probe:r.probe,failed:0,passed:names.length,expected_tests:names.length},true)];
  }
  assert.equal(parse(sequence(stages),'real').filter(a => a.descriptor).length,1);
  for (const name of realPrerequisites) assert.throws(() => parse(sequence(stages.filter(s=>s!==name)),'real'));
  assert.throws(() => parse(sequence([r.target,...stages.slice(0,4)]),'real'));
});
test('fixed target, mutually exclusive mode, no unsafe adb serial or injectable path', () => {
  for (const args of [[],['--real-deepseek','--synthetic','--serial','1'],['--synthetic','--serial','-d'],
    ['--synthetic','--serial','x;echo'],['--synthetic','--serial','1','--yaml-module','.'],['--synthetic','--serial','1','--adb','other']]) {
    assert.throws(() => options(args));
  }
  const a=instrumentArgs('real');
  assert.ok(a.includes('--no-logcat') && a.includes('-m') && !a.includes('-r') && !a.includes('dsh'));
  assert.equal(a.at(-1),'com.sucrune.probe.test/com.sucrune.probe.tests.ProbeInstrumentation');
  assert.equal(options(['--synthetic','--serial','97af8db1']).mode,'synthetic');
});
const diagnosticId = 'SucruneAgentDiagnostic';
function diagnosticRun() {
  const parser = new SessionFrames(), state = new RunStatus('real');
  const consume = frame => state.accept(parser.feed(frame)[0]);
  const names = [...realPrerequisites,MODES.real.target];
  let row;
  for (let i=0;i<names.length;i++) {
    row = { id:MODES.real.id,test:names[i],current:i+1,numtests:names.length };
    consume(record(1,row));
    if (i<names.length-1) consume(record(0,row));
  }
  const diag = { ...row, id:diagnosticId, stage:'launch', safe_reason:'progress', error_kind:'none',
    event_count:0, tool_count:0, rpc_code:0, http_status:0 };
  const announce = () => consume(record(2,{...row,id:MODES.real.bridgeId,credential_bridge_descriptor:descriptor}));
  return { parser,state,consume,row,diag,announce };
}
test('dedicated diagnostic frames yield fixed fields and bounded counters, never guest stream', () => {
  const {state,consume,row,diag,announce} = diagnosticRun();
  assert.deepEqual(consume(record(2,diag)), {diagnostic:{test:row.test,stage:'launch',safe_reason:'progress',error_kind:'none',
    event_count:0,tool_count:0,http_status:0,rpc_code:0}});
  assert.equal(state.descriptorSeen,false);
  consume(record(2,{...diag,stage:'credential_wait'}));
  assert.deepEqual(announce(),{descriptor});
  consume(record(2,{...diag,stage:'credential_received'}));
  consume(record(2,{...diag,stage:'model_stream',event_count:7}));
  const failure = consume(record(2,{...diag,stage:'wait',safe_reason:'turn_error',error_kind:'RATE_LIMIT',
    http_status:429,event_count:9,tool_count:1}));
  assert.equal(failure.diagnostic.http_status,429);
  assert.equal(state.credentialBlocked,true);
  const fake = 'arbitrary guest payload with credential_bridge_descriptor=do_not_echo';
  assert.deepEqual(consume(record(-2,{...row,stream:fake})),{failed:row.test});
  assert.deepEqual(consume(record(0,{probe:'linux',failed:1,passed:row.numtests-1,expected_tests:row.numtests,stream:fake},true)),{passed:row.numtests-1});
  state.end();assert.equal(state.failures,1);
});
test('diagnostics reject extra, missing, arbitrary, replayed and misplaced data', () => {
  for (const bad of [{stage:'guest_constant_printed_here'},{safe_reason:'untrusted_value'},{error_kind:'error with body'},
    {event_count:2049},{event_count:-1},{tool_count:9},{http_status:600},{http_status:99},{rpc_code:-39999},{event_count:'1'},
    {safe_reason:'progress',rpc_code:-32600},{stage:'credential_received'},{id:'guest'},
    {test:'linux_node_pty_bash'},{current:2},{stream:'never print this'},{unlisted:'x'},{credential_bridge_descriptor:descriptor}]) {
    const {consume,diag}=diagnosticRun();
    assert.throws(()=>consume(record(2,{...diag,...bad})),/^Error: invalid_instrumentation_protocol$/);
  }
  {
    const {consume,diag}=diagnosticRun();const short={...diag};delete short.http_status;
    assert.throws(()=>consume(record(2,short)));
    assert.throws(()=>consume(record(2,diag,false,entry('stage','tool_bash'))));
  }
  for (const wrong of [0,1,-2]) {
    const {consume,diag}=diagnosticRun();assert.throws(()=>consume(record(wrong,diag)));
  }
  {
    const {consume,diag}=diagnosticRun();consume(record(2,diag));assert.throws(()=>consume(record(2,diag)));
    consume(record(2,{...diag,stage:'tool_write',event_count:4,tool_count:1}));
    assert.throws(()=>consume(record(2,{...diag,stage:'tool_read',event_count:3,tool_count:1})));
  }
  {
    const {consume,row,diag,announce}=diagnosticRun();consume(record(2,{...diag,safe_reason:'assertion',error_kind:'other'}));
    assert.throws(announce);assert.throws(()=>consume(record(2,{...diag,stage:'wait'})));assert.throws(()=>consume(record(0,row)));
  }
  {
    const parser=new SessionFrames(),state=new RunStatus('real');
    assert.throws(()=>state.accept(parser.feed(record(1,{id:MODES.real.id,test:'linux_guest_secret_text',current:1,numtests:1}))[0]));
  }
});
test('prior failure closes real credential window even if all prerequisites passed', () => {
  const parser=new SessionFrames(), state=new RunStatus('real');
  const send=frame=>state.accept(parser.feed(frame)[0]);
  const names=['linux_dynamic_hello',...realPrerequisites,MODES.real.target];
  for (let i=0;i<names.length;i++) {
    const row={id:MODES.real.id,test:names[i],current:i+1,numtests:names.length};
    send(record(1,row));
    if(i<names.length-1) send(record(i===0 ? -2 : 0,row));
    else assert.throws(()=>send(record(2,{...row,id:MODES.real.bridgeId,credential_bridge_descriptor:descriptor})));
  }
});
test('exception values outside the closed host stage list cannot enter the report', () => {
  assert.deepEqual(failureSummary(new BridgeError('server_proof')),{status:'failed',stage:'server_proof'});
  assert.deepEqual(failureSummary(new BridgeError('untrusted_guest_text')),{status:'failed',stage:'instrumentation_protocol'});
  assert.deepEqual(failureSummary(new Error('raw guest output')),{status:'failed',stage:'instrumentation_protocol'});
});
test('descriptor rejects duplicate JSON keys, expanded fields, and untrusted socket destination', () => {
  assert.deepEqual(publicDescriptor(descriptor),d);
  assert.deepEqual(publicDescriptor(descriptor.replaceAll('/','\\/')),d);
  for (const s of [descriptor.replace('{','{"type":"x",'),JSON.stringify({...d,socket:'localfilesystem:/tmp/key'}),
    JSON.stringify({...d,port:9000}),JSON.stringify({...d,public_key:null})]) assert.throws(() => publicDescriptor(s));
});
test('forward removal matches both serial and fresh abstract address even on failure', async () => {
  const serial='mine', target='localabstract:'+d.socket, other='other tcp:2222 '+target+'\n';
  for (const problem of ['none','send','lost-add-reply','invalid-port']) {
    let active=false, removed=0, sends=0;
    const adb=async a => {
      if(a[1]==='--list') return other+(active ? serial+' tcp:3333 '+target+'\n' : '');
      if(a[1]==='--no-rebind') {active=true;if(problem==='lost-add-reply') throw Error('test');return problem==='invalid-port'?'xx':'3333';}
      assert.deepEqual(a,['forward','--remove','tcp:3333']); active=false;removed++; return '';
    };
    const send=async p=>{sends++;assert.equal(p,3333);if(problem==='send')throw Error('test');return 'sent';};
    if(problem==='none')assert.equal(await withForward(adb,serial,d,send),'sent');
    else await assert.rejects(withForward(adb,serial,d,send));
    assert.equal(active,false);assert.equal(removed,1);assert.equal(sends,['none','send'].includes(problem)?1:0);
  }
  assert.deepEqual(mappings(other,serial,target),[]);
});
