const http = require('http');
const request = require('request');
const net = require('net');
const url = require('url');
const WebSocket = require('ws');
const crypto = require("crypto");
const HttpsProxyAgent = require('https-proxy-agent');


const WSHeaderType    = "dev-req-type";
const WSHeaderTcpHost = "dev-tcp-host";
const WsConnectionTypeTcp = "TCP";
const WsConnectionTypeHttp = "HTTP";
const WsConnectionTypeHTTPCallback = "HTTP_CALLBACK";

const logger = require('electron-log');

const caStr = '-----BEGIN CERTIFICATE-----\n' +
    'MIICQDCCAeWgAwIBAgIQZ10HUuF4FfLZMiPKd1NLojAKBggqhkjOPQQDAjBqMQsw\n' +
    'CQYDVQQGEwJDTjEQMA4GA1UECBMHQmVpamluZzEQMA4GA1UEBxMHQmVpamluZzER\n' +
    'MA8GA1UEChMIaGVsaXVtb3MxETAPBgNVBAsTCGhlbGl1bW9zMREwDwYDVQQDEwho\n' +
    'ZWxpdW1vczAeFw0yMzA4MjgxMDE1MDBaFw00MzA4MjMxMDE1MDBaMGoxCzAJBgNV\n' +
    'BAYTAkNOMRAwDgYDVQQIEwdCZWlqaW5nMRAwDgYDVQQHEwdCZWlqaW5nMREwDwYD\n' +
    'VQQKEwhoZWxpdW1vczERMA8GA1UECxMIaGVsaXVtb3MxETAPBgNVBAMTCGhlbGl1\n' +
    'bW9zMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE3fjGc4MqN6E02b9Wd7ZTV6je\n' +
    'vsRXOpUOK5WaI1ls/TVJMu3dszJC1ibQ7dkg/4+mOt9x+v99/Td7kShO2xYlG6Nt\n' +
    'MGswDgYDVR0PAQH/BAQDAgGmMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcD\n' +
    'ATAPBgNVHRMBAf8EBTADAQH/MCkGA1UdDgQiBCBCIIS6gbzeQXmXVQHoOJvvXfst\n' +
    'MKCFy3m1gFNfF1PdXjAKBggqhkjOPQQDAgNJADBGAiEAsvREvvd1rYxcNF8YpR44\n' +
    'fTgOLTBHbN41BOTXlsFi0qkCIQCVJ9r4AtiMmwhMogkuGWcORG65EMcKLczIyveo\n' +
    'DUMPzQ==\n' +
    '-----END CERTIFICATE-----';

const headerMap = {
    "accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "accept-language":           "zh-CN,zh;q=0.9",
    "cache-control":             "max-age=0",
    "sec-ch-ua":                 "\"Not A(Brand\";v=\"99\", \"Google Chrome\";v=\"121\", \"Chromium\";v=\"121\"",
    "sec-ch-ua-mobile":          "?0",
    "sec-ch-ua-platform":        "\"macOS\"",
    "sec-fetch-dest":            "document",
    "sec-fetch-mode":            "navigate",
    "sec-fetch-site":            "none",
    "sec-fetch-user":            "?1",
    "upgrade-insecure-requests": "1",
    "cookie":                    'cookie: OAuth_Token_Request_State=f32971c3-4524-46d8-8392-3a33cd990ac8; kc-access=eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJUX3JUOXl1cFBycDJ3THlGd1Q2ZnJXQjFGR2loUU1CRmNzaWIyYnhLeUkwIn0.eyJleHAiOjE3MTI5MjEwMzQsImlhdCI6MTcxMTYyNTAzNCwiYXV0aF90aW1lIjoxNzExNjI1MDM0LCJqdGkiOiJkOTA2YzMwNC05NGNjLTQ5NDUtOTBiOS1jMzA3NjUyNWI0ZGQiLCJpc3MiOiJodHRwczovL2tleWNsb2FrLnVzZXIuc3lzdGVtLnNlcnZpY2Uub3JnMy9yZWFsbXMvb3JnMyIsImF1ZCI6WyJkZXNrdG9wLWdhdGVrZWVwZXIiLCJhY2NvdW50Il0sInN1YiI6IjE0MTVmOWVhLTc3YzAtNDJhZC05MTljLTQ3NzJkY2QyZjMwMSIsInR5cCI6IkJlYXJlciIsImF6cCI6ImRlc2t0b3AtZ2F0ZWtlZXBlciIsInNlc3Npb25fc3RhdGUiOiIyMGVlNzU0My0zNGMwLTQ1MTUtYTVhZi0xYmYyNWZiYmUxYjkiLCJhY3IiOiIxIiwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbImRlZmF1bHQtcm9sZXMtb3JnMyIsIm9mZmxpbmVfYWNjZXNzIiwiYWRtaW4iLCJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoib3BlbmlkIGF1IHByb2ZpbGUgZW1haWwiLCJzaWQiOiIyMGVlNzU0My0zNGMwLTQ1MTUtYTVhZi0xYmYyNWZiYmUxYjkiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsIm5hbWUiOiJhZG1pbiIsInByZWZlcnJlZF91c2VybmFtZSI6ImFkbWluIiwiZ2l2ZW5fbmFtZSI6ImFkbWluIiwiZmFtaWx5X25hbWUiOiIifQ.W0-EmxY3S5UzBGX6FlA2avjY8Tc_v-338L4NGulxOtpphgjWR6ajh7aFPRwUkNiOo27d40MLtxCmdJhJ2amuRwgmnbA0f2aOpEqRsGl3SDGsR_U03eMhkZBXKMAuKZWFGR8apnEgcJ6BXuBODPaDvlQvbtN5KKrncvU1EPEe8EwOvdtFfcKqAfDGcjTcGeIZUA96ZzeF5snCvtH6eRF7x20CkP-TYMAKl4nAaZYzQ39QxoaYrFdwotKTrEraqCjp1A0fJVniYQ07o5KfvTDwumVgKRaCPCxT3RhRAkbewmVArD3-9h1drfCTkf9W8uCvMw9AYffoxsfyB62_dTfOoA; kc-state=f/pRlWbj4SuiWXdEPH63NVZTGfAHKz8CCwivSwedFIOFvd56TODa1enDwRDGCaT8yx5DpaOkKWEzPaXMfOvMFiKfryCDbLgTHdPWbNmmRg7fT3udygwPeIR2bmS/b+Lq5RnfRXdN4u/MSScGV/DNT8Q7kdUHoyjVmXa79akRnnHlQvC2C9QnSYhFYcVbBW5n99/LR1u7NXljf6SrRaQ2dwdxMtJw4MvwQjIjr/rw3wDL2/pZa7dnvYTaZ2YEiGn2jxDwXWWciCalyE4aDQ5VbJPKu07AZz+6fwS9bvtpggV2qVbi+3K3dhC3Pg8a05TDZr2TgPruGvpJw0noCb1hEEk3FCjgMWrmAEGltSafOQv7uAozXBmQi7e6MmnIxwzI2rfbTTQPvbyp0O7uM/6ea7DP0CXaq5k4tRAv8Lx7v9TX+a20hO0USYjFDdzBJIAsCF7i7feObk982sjNoon826YVz441lr+ek7VFjTeA1SVSIacFtsK8g1vztiKXcxtPfQEiaUlsPljy4qmye0Qpz4ElgfxIEedj299pgn5CIDNPBh4Z9bOA3SogTbmWPOYkmwSAISD8YQj6GNtRM20tzkujs+mSY4+M0FLc3tG46jslW+OCk3PhF6D+TfG4My/bBvjJEO0fTmEpVDyrgfBOiVCPsqVf9TghsyDXXLGjYAME94p7wqrPCp+A8jK4Nvl5GnGdoA53KY/aO+gzoFQH2RIGnyeCO7TmttBFEAIlo8LA81WlJrW1UKc; NEXT_LOCALE=zh'}


const wssHost = 'wss://busybox.local.app.org3'

module.exports = {
    runClient,
};

async function runClient(proxy_port) {
    const agent = new HttpsProxyAgent.HttpsProxyAgent({
        hostname: 'localhost',
        port: proxy_port,
    });

    //Http client
    let headerMapHttp = { ...headerMap };
    headerMapHttp[WSHeaderType] = WsConnectionTypeHttp;
    const wsHttp = new WebSocket(wssHost, { agent: agent, headers: headerMapHttp, ca: caStr });

    wsHttp.onopen = () => {
        logger.info(`http proxy websocket onopen`);
    }

    wsHttp.onerror = (error) => {
        logger.error(`http proxy websocket error: ${error.message}`);
    }

    const responses = {};

    const server = http.createServer((req, res) => {
        const { hostname, port, path } = url.parse(req.url);
        const requestId = crypto.randomUUID();
        responses[requestId] = res;

        let httpData = {"id":"", "host":"", "method":"", "url":"", "body":"", "header":"", "code":""};
        httpData.id = requestId;
        httpData.host = "127.0.0.1:17880";
        httpData.method = req.method;
        httpData.url = req.url;
        httpData.code = 0;
        httpData.header = {};

        for (let key in req.headers) {
            if (key !== "host") {
                httpData.header[key] = [req.headers[key]]
            }
        }

        let body = '';
        req.on('data', chunk => {
            body += chunk.toString();
        });

        req.on('end', () => {
            httpData.body = Buffer.from(body, "utf-8").toString('base64');
            wsHttp.send(Buffer.from(JSON.stringify(httpData)))
        });

        wsHttp.onmessage = (e) => {
            const response = JSON.parse(e.data.toString())
            responses[response.id].writeHeader(response.code, response.header)
            responses[response.id].end(Buffer.from(response.body, 'base64').toString('utf8'));
            delete responses[response.id];
        }

        wsHttp.onclose = () => {
            logger.info(`http proxy websocket close`);
        }

    });
    server.listen(17880, () => {
        logger.info(`http proxy server is listening on port 17880`);
    })


    //TCP client
    let headerMapTcp = { ...headerMap };
    headerMapTcp[WSHeaderType] = WsConnectionTypeTcp;
    headerMapTcp[WSHeaderTcpHost] = "postgres:5432";

    const tcpServer = net.createServer((clientSocket) => {
        const wsTcp = new WebSocket(wssHost, { agent: agent, headers: headerMapTcp, ca: caStr });

        wsTcp.onopen = () => {
            logger.info(`tcp proxy websocket onopen`);
            clientSocket.on('data', (data) => {
                wsTcp.send(Buffer.from(data))
            });
        }
        wsTcp.onerror = (error) => {
            logger.error(`tcp proxy websocket error: ${error.message}`);
        }

        wsTcp.onclose = () => {
            logger.info(`tcp proxy websocket close`);
        }

        wsTcp.onmessage = (e) => {
            clientSocket.write(e.data);
        }

        clientSocket.on('end', () => {
            wsTcp.close();
        });
        clientSocket.on('error', (err) => {
            logger.error(`tcp client socket error: ${err.message}`);
        });
    });

    tcpServer.on('listening', () => {
        const {address, port}  = tcpServer.address();
        logger.info(`tcp proxy server is running at: ${address} port ${port}`);
    });
    tcpServer.on('close', () => {
        logger.info(`tcp proxy server close`);
    });
    tcpServer.on('error', (err) => {
        logger.error(`tcp proxy server error: ${err.message}`);
    });
    tcpServer.listen(5432, () => {
        logger.info(`tcp proxy server bound`);
    });




    //Http callback
    let headerMapCallBack = { ...headerMap };
    headerMapCallBack[WSHeaderType] = WsConnectionTypeHTTPCallback;

    const wsHttpCallBack = new WebSocket(wssHost, { agent: agent, headers: headerMapCallBack, ca: caStr });

    wsHttpCallBack.onopen = () => {
        logger.info(`http callback proxy websocket onopen`);
    }

    wsHttpCallBack.onerror = (error) => {
        logger.error(`http callback proxy websocket error: ${error.message}`);
    }

    wsHttpCallBack.onclose = () => {
        logger.info(`http callback proxy websocket close`);
    }

    wsHttpCallBack.onmessage = (e) => {
        const wsMsg = JSON.parse(e.data.toString())
        let options = {
            method: wsMsg.method,
            url: "http://"+wsMsg.host+wsMsg.url,
            headers: wsMsg.headers,
            body: Buffer.from(wsMsg.body, 'base64').toString('utf8')
        };

        request(options, function (error, res) {
            if (error) {
                logger.error(`http callback request error: ${error.message}, url: ${options.url}`);
                let httpData = {"id":"", "host":"", "method":"", "url":"", "body":"", "header":"", "code":""};
                httpData.id = wsMsg.id;
                httpData.body = Buffer.from(error, "utf-8").toString('base64');
                httpData.code = 500;
                wsHttpCallBack.send(Buffer.from(JSON.stringify(httpData)))
            } else {
                let httpData = {"id":"", "host":"", "method":"", "url":"", "body":"", "header":"", "code":""};
                httpData.id = wsMsg.id;
                httpData.body = Buffer.from(res.body, "utf-8").toString('base64');
                httpData.code = res.statusCode;
                httpData.header = {};
                for (let key in res.headers) {
                    if (key !== "host") {
                        httpData.header[key] = [res.headers[key]]
                    }
                }
                wsHttpCallBack.send(Buffer.from(JSON.stringify(httpData)));
            }
        })
    }
}
