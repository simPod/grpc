<?php
/*
 * Copyright 2026 gRPC authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

class TlsVerificationTest extends \PHPUnit\Framework\TestCase
{
    private $server;
    private $channel;

    public function tearDown(): void
    {
        if ($this->channel !== null) {
            $this->channel->close();
        }
        unset($this->server);
    }

    private function createChannel($server_certificate, $credentials, $hostname)
    {
        $server_credentials = Grpc\ServerCredentials::createSsl(
            null,
            file_get_contents(__DIR__.'/../data/'.$server_certificate.'.key'),
            file_get_contents(__DIR__.'/../data/'.$server_certificate.'.pem')
        );
        $this->server = new Grpc\Server();
        $port = $this->server->addSecureHttp2Port('127.0.0.1:0', $server_credentials);
        $this->assertGreaterThan(0, $port);
        $this->server->start();
        $this->channel = new Grpc\Channel('127.0.0.1:'.$port, [
            'credentials' => $credentials,
            'force_new' => true,
            'grpc.ssl_target_name_override' => $hostname,
        ]);
    }

    public function testDefaultRejectsUntrustedCertificate()
    {
        $this->createChannel('tls_skip_verify', Grpc\ChannelCredentials::createSsl(
            file_get_contents(__DIR__.'/../data/ca.pem')
        ), 'untrusted.example.com');
        $this->assertVerificationFails();
    }

    public function testDefaultRejectsWrongHostname()
    {
        $this->createChannel('server1', Grpc\ChannelCredentials::createSsl(
            file_get_contents(__DIR__.'/../data/ca.pem')
        ), 'wrong.example.com');
        $this->assertVerificationFails();
    }

    private function assertVerificationFails()
    {
        $call = new Grpc\Call($this->channel, '/test/method',
            Grpc\Timeval::now()->add(new Grpc\Timeval(5000000)));
        $event = $call->startBatch([
            Grpc\OP_SEND_INITIAL_METADATA => [],
            Grpc\OP_SEND_CLOSE_FROM_CLIENT => true,
            Grpc\OP_RECV_STATUS_ON_CLIENT => true,
        ]);
        $this->assertSame(Grpc\STATUS_UNAVAILABLE, $event->status->code);
    }

    public function testSkipVerificationRetainsTls()
    {
        $arguments = PHP_VERSION_ID >= 80000
            ? ['skip_verify' => true]
            : [null, null, null, true];
        $this->createChannel('tls_skip_verify',
            call_user_func_array(['Grpc\ChannelCredentials', 'createSsl'], $arguments),
            'wrong.example.com');
        $this->assertRequestCompletes();
    }

    public function testSkipVerificationWithCompositeCredentials()
    {
        $credentials = Grpc\ChannelCredentials::createSsl(
            file_get_contents(__DIR__.'/../data/ca.pem'),
            file_get_contents(__DIR__.'/../data/server1.key'),
            file_get_contents(__DIR__.'/../data/server1.pem'),
            true
        );
        $call_credentials = Grpc\CallCredentials::createFromPlugin(function () {
            return ['authorization' => ['test-token']];
        });
        $composite = Grpc\ChannelCredentials::createComposite($credentials, $call_credentials);
        $this->createChannel('tls_skip_verify', $composite, 'wrong.example.com');
        // The channel must retain native credentials after PHP wrappers are freed.
        unset($credentials, $call_credentials, $composite);
        $this->assertRequestCompletes(['authorization' => ['test-token']]);
    }

    private function assertRequestCompletes($expected_metadata = [])
    {
        // Also exercise per-call host checking, independently of the TLS target.
        $call = new Grpc\Call($this->channel, '/test/method',
            Grpc\Timeval::now()->add(new Grpc\Timeval(5000000)), 'wrong-call.example.com');
        $event = $call->startBatch([
            Grpc\OP_SEND_INITIAL_METADATA => [],
            Grpc\OP_SEND_CLOSE_FROM_CLIENT => true,
        ]);
        $this->assertTrue($event->send_metadata);

        $request = $this->server->requestCall();
        foreach ($expected_metadata as $key => $values) {
            $this->assertSame($values, $request->metadata[$key]);
        }
        $request->call->startBatch([
            Grpc\OP_SEND_INITIAL_METADATA => ['tls-response' => ['received']],
            Grpc\OP_SEND_STATUS_FROM_SERVER => [
                'metadata' => [],
                'code' => Grpc\STATUS_OK,
                'details' => '',
            ],
        ]);
        $event = $call->startBatch([
            Grpc\OP_RECV_INITIAL_METADATA => true,
            Grpc\OP_RECV_STATUS_ON_CLIENT => true,
        ]);
        $this->assertSame(Grpc\STATUS_OK, $event->status->code);
        $this->assertSame(['received'], $event->metadata['tls-response']);
    }
}
