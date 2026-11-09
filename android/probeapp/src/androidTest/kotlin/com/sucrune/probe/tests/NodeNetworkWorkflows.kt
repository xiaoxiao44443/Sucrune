package com.sucrune.probe.tests

import android.os.SystemClock
import com.sucrune.probe.RuntimeClient
import org.json.JSONObject
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket

/** Original Linux Node owns both client and server. The Android socket below
 * only verifies the cancelled listener has actually released its port. */
internal fun nodeNetworkWorkflowCases(
    client: RuntimeClient, environmentId: String,
    execute: (List<String>, Boolean) -> JSONObject,
    start: (List<String>, Long) -> String,
    stopAndReuse: (String) -> JSONObject
): List<Pair<String, () -> String>> {
    fun script(name: String, source: String): List<String> {
        client.makeDirectory(environmentId, "/network-workflows")
        val path = "/network-workflows/$name.cjs"
        client.writeFile(environmentId, path, source.trimIndent().toByteArray(Charsets.UTF_8))
        return listOf(path)
    }
    fun exact(record: JSONObject, expected: String) {
        check(!record.getBoolean("truncated") && record.getString("stdout") == expected &&
            record.getString("stderr").isEmpty()) { record.toString() }
        val native = record.getJSONObject("result").getJSONObject("native")
        if (native.getString("cleanup_mode") == "joined") check(native.getInt("network_resources_live") == 0)
    }
    return listOf(
        "linux_node_network_default_denied" to {
            val record = execute(script("denied", """
                'use strict';
                const net = require('node:net');
                const client = net.createConnection({host:'127.0.0.1',port:9});
                client.on('connect',()=>{ throw Error('unexpected permission'); });
                client.on('error',error=>{
                  if(error.code !== 'EACCES') throw error;
                  console.log('NETWORK_DENIED EACCES');
                });
            """), false)
            exact(record, "NETWORK_DENIED EACCES\n")
            "An ordinary Linux execution cannot create an IP socket without an explicit manager network policy"
        },
        "linux_node_network_tcp_stream" to {
            val record = execute(script("tcp", """
                'use strict';
                const assert = require('node:assert/strict');
                const net = require('node:net');
                const fs = require('node:fs');
                const crypto = require('node:crypto');
                const payload = Buffer.alloc(393221);
                for(let i=0;i<payload.length;i++) payload[i]=(i*17+31)&255;
                const digest = crypto.createHash('sha256').update(payload).digest('hex');
                let received = 0;
                const hash = crypto.createHash('sha256');
                const server = net.createServer({allowHalfOpen:true},socket=>{
                  socket.on('error',error=>{ throw error; });
                  socket.setNoDelay(true); socket.setKeepAlive(true,1000);
                  socket.on('data',bytes=>{ received+=bytes.length; hash.update(bytes); });
                  socket.on('end',()=>{
                    assert.equal(received,payload.length); assert.equal(hash.digest('hex'),digest);
                    socket.end('TCP_REPLY '+received+' '+digest+'\n');
                  });
                });
                server.on('error',error=>{ throw error; });
                server.listen(0,'127.0.0.1',()=>{
                  const client=net.createConnection({host:'127.0.0.1',port:server.address().port});
                  let reply='';
                  client.on('error',error=>{ throw error; });
                  client.on('connect',()=>{ client.setNoDelay(true); client.end(payload); });
                  client.setEncoding('utf8'); client.on('data',bytes=>{ reply+=bytes; });
                  client.on('end',()=>{
                    assert.equal(reply,'TCP_REPLY '+payload.length+' '+digest+'\n');
                    fs.writeFileSync('/network-workflows/tcp-result.txt',reply);
                    server.close(()=>console.log('TCP_STREAM_OK '+received));
                  });
                });
            """), true)
            exact(record, "TCP_STREAM_OK 393221\n")
            val artifact = client.readFile(environmentId, "/network-workflows/tcp-result.txt").toString(Charsets.UTF_8)
            check(artifact.matches(Regex("TCP_REPLY 393221 [a-f0-9]{64}\\n"))) { artifact }
            "Original Linux Node accepted and connected TCP through SCM_RIGHTS, streamed 393221 verified bytes, half-closed and produced a project artifact"
        },
        "linux_node_network_http_keepalive" to {
            val record = execute(script("http", """
                'use strict';
                const assert=require('node:assert/strict');
                const http=require('node:http');
                const crypto=require('node:crypto');
                const payload=Buffer.from('Sucrune中文🙂'.repeat(10000));
                let connections=0, requests=0;
                const server=http.createServer((request,response)=>{
                  const parts=[]; request.on('data',part=>parts.push(part));
                  request.on('end',()=>{
                    const body=Buffer.concat(parts); requests++;
                    assert.equal(request.method,'POST'); assert.equal(request.url,'/agent-fixture');
                    assert.deepEqual(body,payload);
                    response.writeHead(200,{'content-type':'application/json; charset=utf-8'});
                    response.end(JSON.stringify({request:requests,bytes:body.length,sha:crypto.createHash('sha256').update(body).digest('hex')}));
                  });
                });
                server.on('connection',()=>{connections++;}); server.on('error',error=>{throw error;});
                server.listen(0,'127.0.0.1',async()=>{
                  const agent=new http.Agent({keepAlive:true,maxSockets:1});
                  try {
                    for(let i=1;i<=2;i++) await new Promise((resolve,reject)=>{
                      const request=http.request({hostname:'127.0.0.1',port:server.address().port,path:'/agent-fixture',method:'POST',agent,
                        headers:{'content-length':payload.length}},response=>{
                        let text=''; response.setEncoding('utf8'); response.on('data',data=>{text+=data;});
                        response.on('end',()=>{try{
                          assert.equal(response.statusCode,200);
                          assert.deepEqual(JSON.parse(text),{request:i,bytes:payload.length,sha:crypto.createHash('sha256').update(payload).digest('hex')});
                          resolve();
                        }catch(error){reject(error);}});
                      });
                      request.on('error',reject); request.end(payload);
                    });
                    assert.equal(connections,1); assert.equal(requests,2);
                    agent.destroy(); server.close(()=>console.log('HTTP_KEEPALIVE_OK 2 1'));
                  } catch(error) {agent.destroy(); server.close(); throw error;}
                });
            """), true)
            exact(record, "HTTP_KEEPALIVE_OK 2 1\n")
            "Two real HTTP POST requests reused one TCP connection and verified the UTF-8 body and JSON responses"
        },
        "linux_node_network_refused" to {
            val record = execute(script("refused", """
                'use strict';
                const net=require('node:net');
                const server=net.createServer();
                server.on('error',error=>{throw error;});
                server.listen(0,'127.0.0.1',()=>{
                  const port=server.address().port;
                  server.close(()=>{
                    const socket=net.createConnection({host:'127.0.0.1',port});
                    socket.on('connect',()=>{throw Error('released listener unexpectedly accepted');});
                    socket.on('error',error=>{
                      if(error.code!=='ECONNREFUSED') throw error;
                      console.log('NETWORK_REFUSED ECONNREFUSED');
                    });
                  });
                });
            """), true)
            exact(record, "NETWORK_REFUSED ECONNREFUSED\n")
            "A released listener refused a later connection; real nonblocking completion preserved ECONNREFUSED"
        },
        "linux_node_network_cancel_listener" to {
            val id = start(script("cancel-listener", """
                'use strict';
                const net=require('node:net');
                const server=net.createServer();
                server.on('error',error=>{throw error;});
                server.listen(0,'127.0.0.1',()=>console.log('LISTENER_READY '+server.address().port));
            """), 30_000)
            var port = 0
            val deadline = SystemClock.elapsedRealtime() + 10_000
            while (port == 0) {
                val live = client.getExecution(id)
                check(live.getString("state") == "running") { live.toString() }
                val match = Regex("^LISTENER_READY ([0-9]+)\\n$").matchEntire(live.getString("stdout"))
                if (match != null) port = match.groupValues[1].toInt()
                else {
                    check(SystemClock.elapsedRealtime() < deadline) { "No live listener: $live" }
                    SystemClock.sleep(25)
                }
            }
            check(port in 1..65535)
            check(client.cancel(id))
            val record = stopAndReuse(id)
            check(record.getString("state") == "cancelled") { record.toString() }
            ServerSocket().use { checkSocket ->
                checkSocket.reuseAddress = true
                checkSocket.bind(InetSocketAddress(InetAddress.getByName("127.0.0.1"), port))
            }
            "Cancelling a live Linux listener completed all four barriers, allowed project reuse, and released its manager-held port"
        }
    )
}
