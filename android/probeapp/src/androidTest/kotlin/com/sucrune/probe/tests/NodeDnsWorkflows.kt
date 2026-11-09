package com.sucrune.probe.tests

import com.sucrune.probe.RuntimeClient
import org.json.JSONObject

/** The caller supplies an outbound execution and verifies its four cleanup barriers. */
internal fun nodeDnsWorkflowCases(
    client: RuntimeClient,
    envId: String,
    execute: (List<String>) -> JSONObject
): List<Pair<String, () -> String>> {
    fun run(name: String, body: String, options: List<String> = emptyList()): JSONObject {
        client.makeDirectory(envId, "/dns-workflows")
        val path = "/dns-workflows/$name.cjs"
        val source = """
            'use strict';
            const assert = require('node:assert/strict');
            assert.equal(process.platform, 'linux');
            assert.equal(process.arch, 'arm64');
            assert.equal(process.version, 'v24.22.2');
            const timeout = setTimeout(() => { console.error('DNS workflow deadline'); process.exit(1); }, 25000);
            (async () => {
                $body
            })().then(result => {
                clearTimeout(timeout);
                console.log(JSON.stringify(result));
            }, error => {
                console.error(error.stack || String(error));
                process.exitCode = 1;
                timeout.unref();
            });
        """.trimIndent()
        client.writeFile(envId, path, source.toByteArray(Charsets.UTF_8))
        val record = execute(options + path)
        check(record.getString("state") == "exited" && record.getInt("exit_code") == 0 &&
            !record.getBoolean("truncated") && record.getString("stderr").isEmpty()) { record.toString() }
        val native = record.getJSONObject("result").getJSONObject("native")
        check(native.getString("kind") == "linux") { native.toString() }
        if (native.getString("cleanup_mode") == "joined") {
            check(native.getInt("network_resources_live") == 0) { native.toString() }
        }
        return JSONObject(record.getString("stdout").trim())
    }

    return listOf(
        "linux_node_glibc_dns_lookup" to {
            val result = run("lookup", """
                const dns = require('node:dns/promises');
                const net = require('node:net');
                const host = 'example.com';
                const all = await dns.lookup(host, {all:true});
                assert.ok(all.length > 0);
                for (const item of all) {
                    assert.ok(item.family === 4 || item.family === 6);
                    assert.equal(net.isIP(item.address), item.family);
                }
                const v4 = await dns.lookup(host, {family:4});
                assert.equal(v4.family, 4);
                assert.equal(net.isIP(v4.address), 4);
                // Exercise net's own default hints and lookup callback. Stop at
                // the lookup event so this assertion measures name resolution.
                const observedFamily = await new Promise((resolve, reject) => {
                    const socket = net.createConnection({host, port:443});
                    let resolvedFamily = 0;
                    socket.once('error', reject);
                    socket.once('lookup', (error, address, family, hostname) => {
                        try {
                            if (error) throw error;
                            assert.equal(hostname, host);
                            assert.ok(family === 4 || family === 6);
                            assert.equal(net.isIP(address), family);
                            resolvedFamily = family;
                        } catch (failure) { reject(failure); }
                        finally { socket.destroy(); }
                    });
                    socket.once('close', () => {
                        if (resolvedFamily) resolve(resolvedFamily);
                        else reject(Error('Socket closed before a successful default lookup'));
                    });
                });
                return {answers: all.length, family4:v4.family, defaultFamily:observedFamily};
            """.trimIndent())
            check(result.getInt("answers") > 0 && result.getInt("family4") == 4 &&
                result.getInt("defaultFamily") in setOf(4, 6)) { result.toString() }
            "Guest getaddrinfo returned ${result.getInt("answers")} addresses for example.com. Node's default net lookup selected IPv${result.getInt("defaultFamily")}."
        },
        "linux_node_cares_dns_records" to {
            val result = run("resolve", """
                const dns = require('node:dns/promises');
                const net = require('node:net');
                const [v4, v6] = await Promise.all([
                    dns.resolve4('example.com.'), dns.resolve6('example.com.')
                ]);
                assert.ok(v4.length > 0 && v6.length > 0);
                assert.ok(v4.every(addr => net.isIP(addr) === 4));
                assert.ok(v6.every(addr => net.isIP(addr) === 6));
                const negative = await dns.resolve4('sucrune-absent.invalid.').then(
                    () => { throw Error('Unexpected positive answer for .invalid'); },
                    error => {
                        assert.ok(['ENOTFOUND','ENODATA'].includes(error.code), String(error));
                        return error.code;
                    }
                );
                return {a:v4.length, aaaa:v6.length, negative};
            """.trimIndent())
            check(result.getInt("a") > 0 && result.getInt("aaaa") > 0 &&
                result.getString("negative") in setOf("ENOTFOUND", "ENODATA")) { result.toString() }
            "c-ares returned ${result.getInt("a")} A and ${result.getInt("aaaa")} AAAA records. The .invalid query returned ${result.getString("negative")}."
        },
        "linux_node_outbound_https_certificate" to {
            val result = run("https", """
                const https = require('node:https');
                const tls = require('node:tls');
                const host = 'api.deepseek.com';
                assert.ok(tls.rootCertificates.length > 0);
                return await new Promise((resolve, reject) => {
                    const request = https.get({
                        hostname:host, servername:host, port:443, path:'/', agent:false,
                        rejectUnauthorized:true, signal:AbortSignal.timeout(20000)
                    }, response => {
                        response.once('error', reject);
                        try {
                            const socket = response.socket;
                            assert.equal(socket.encrypted, true);
                            assert.equal(socket.authorized, true, String(socket.authorizationError));
                            const cert = socket.getPeerCertificate();
                            assert.ok(typeof cert.fingerprint256 === 'string' && cert.fingerprint256.length > 0);
                            assert.equal(tls.checkServerIdentity(host, cert), undefined);
                            assert.equal(tls.checkServerIdentity('sucrune-mismatch.invalid', cert).code, 'ERR_TLS_CERT_ALTNAME_INVALID');
                            const status = response.statusCode;
                            assert.ok(Number.isInteger(status) && status >= 100 && status <= 599);
                            const version = socket.getProtocol();
                            assert.ok(typeof version === 'string' && version.startsWith('TLS'));
                            response.once('end', () => resolve({authorized:true, host, status, version}));
                            let bytes = 0;
                            response.on('data', chunk => {
                                bytes += chunk.length;
                                if (bytes > 1048576) response.destroy(Error('Public response exceeds validation limit'));
                            });
                            response.resume();
                        } catch (error) {
                            response.destroy();
                            reject(error);
                        }
                    });
                    request.once('error', reject);
                });
            """.trimIndent(), listOf("--use-bundled-ca"))
            check(result.getBoolean("authorized") && result.getString("host") == "api.deepseek.com" &&
                result.getInt("status") in 100..599 && result.getString("version").startsWith("TLS")) { result.toString() }
            "Public GET / on api.deepseek.com returned HTTP ${result.getInt("status")} over ${result.getString("version")}. Node validated the certificate chain and hostname."
        },
        "linux_node_udp_multiple_datagrams" to {
            val result = run("udp", """
                const dgram = require('node:dgram');
                const sender = dgram.createSocket('udp4');
                const receiver = dgram.createSocket('udp4');
                const packets = [Buffer.alloc(0), Buffer.from('Sucrune中文🙂'), Buffer.from([0,255,65,0])];
                const expected = packets.map(bytes => bytes.toString('hex')).sort();
                let sentBound = false, receivedBound = false;
                try {
                    await new Promise((resolve, reject) => {
                        const incoming = [], echoed = [];
                        sender.on('error', reject);
                        receiver.on('error', reject);
                        receiver.on('message', (bytes, peer) => {
                            try {
                                assert.equal(peer.address, '127.0.0.1');
                                assert.equal(peer.port, sender.address().port);
                                incoming.push(bytes.toString('hex'));
                                receiver.send(bytes, peer.port, peer.address, error => { if (error) reject(error); });
                            } catch (error) { reject(error); }
                        });
                        sender.on('message', (bytes, peer) => {
                            try {
                                assert.equal(peer.address, '127.0.0.1');
                                assert.equal(peer.port, receiver.address().port);
                                echoed.push(bytes.toString('hex'));
                                if (echoed.length === packets.length) {
                                    assert.deepEqual(echoed.sort(), expected);
                                    assert.deepEqual(incoming.sort(), expected);
                                    resolve();
                                }
                            } catch (error) { reject(error); }
                        });
                        receiver.bind(0, '127.0.0.1', () => {
                            receivedBound = true;
                            sender.bind(0, '127.0.0.1', () => {
                                sentBound = true;
                                for (const bytes of packets) sender.send(bytes, receiver.address().port, '127.0.0.1',
                                    error => { if (error) reject(error); });
                            });
                        });
                    });
                } finally {
                    if (sentBound) sender.close();
                    if (receivedBound) receiver.close();
                }
                return {echoed:packets.length, empty:true};
            """.trimIndent())
            check(result.getInt("echoed") == 3 && result.getBoolean("empty")) { result.toString() }
            "Original Node exchanged three datagrams in both directions, including a zero-length datagram, and verified the sender address and port."
        }
    )
}
