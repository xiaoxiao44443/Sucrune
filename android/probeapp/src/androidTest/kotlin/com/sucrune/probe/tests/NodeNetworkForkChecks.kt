package com.sucrune.probe.tests

import org.json.JSONObject

/** Run the original Node and /bin/bash in one project. The supplied runner
 * applies the network policy to this execution and checks its cleanup barriers. */
internal fun nodeNetworkForkCase(
    runNode: (source: String, extraEnv: List<String>) -> JSONObject
): Pair<String, () -> String> = "linux_node_spawn_bash_with_connected_tcp" to {
    val source = """
        'use strict';
        const assert = require('node:assert/strict');
        const net = require('node:net');
        const {once} = require('node:events');
        const {spawn} = require('node:child_process');
        let stage = 'listen';
        const watchdog = setTimeout(() => {
          process.stderr.write('TCP fork timeout at ' + stage + '\n');
          process.exit(70);
        }, 25000).unref();
        async function run() {
          const server = net.createServer({allowHalfOpen: true});
          server.listen(0, '127.0.0.1');
          await once(server, 'listening');
          const accepted = once(server, 'connection');
          const socket = net.connect(server.address().port, '127.0.0.1');
          await once(socket, 'connect');
          const [peer] = await accepted;
          const serverClosed = once(server, 'close');
          server.close();
          await new Promise(resolve => setImmediate(resolve));
          assert.equal(server.listening, false);
          assert.equal(socket.readyState, 'open');
          assert.equal(peer.readyState, 'open');
          let received = '';
          peer.setEncoding('utf8');
          peer.on('data', value => { received += value; });
          const peerEnded = once(peer, 'end');
          stage = 'spawn';
          const child = spawn('/bin/bash', ['--noprofile', '--norc', '-c',
            'printf "child-on-inherited-socket\n" >&3'], {
            cwd: '/', env: {LC_ALL: 'C', PATH: '/bin:/usr/bin'},
            stdio: ['pipe', 'pipe', 'pipe', socket]
          });
          const childClosed = once(child, 'close');
          let stdout = '', stderr = '';
          child.stdout.setEncoding('utf8').on('data', value => { stdout += value; });
          child.stderr.setEncoding('utf8').on('data', value => { stderr += value; });
          child.stdin.end();
          await once(child, 'spawn');
          assert.ok(child.pid > 0 && child.pid !== process.pid);
          stage = 'child-exit';
          assert.deepEqual(await childClosed, [0, null]);
          assert.equal(stdout, '');
          assert.equal(stderr, '');
          stage = 'parent-write';
          socket.end('parent-on-original-socket\n');
          await peerEnded;
          assert.equal(received, 'child-on-inherited-socket\nparent-on-original-socket\n');
          peer.end();
          await serverClosed;
          clearTimeout(watchdog);
          console.log('CHILD_AND_PARENT_TCP_OK');
        }
        run().catch(error => {
          process.stderr.write('TCP fork failed at ' + stage + ': ' + error.message + '\n');
          process.exit(71);
        });
    """.trimIndent()
    val record = runNode(source, listOf("SUCRUNE_NETWORK_POLICY=loopback"))
    val native = record.getJSONObject("result").getJSONObject("native")
    check(!record.getBoolean("truncated") && record.getString("stdout") == "CHILD_AND_PARENT_TCP_OK\n" &&
        record.getString("stderr").isEmpty() && native.getInt("exit_code") == 0 && native.getBoolean("runner_waited")) {
        record.toString()
    }
    "Original Bash wrote to a TCP descriptor inherited across guest fork and exec. Node wrote to the same connection after Bash exited."
}
