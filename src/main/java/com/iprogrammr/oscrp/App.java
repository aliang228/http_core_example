package com.iprogrammr.oscrp;

import org.apache.http.*;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.DefaultBHttpClientConnection;
import org.apache.http.impl.nio.reactor.DefaultConnectingIOReactor;
import org.apache.http.impl.nio.reactor.IOReactorConfig;
import org.apache.http.impl.pool.BasicConnPool;
import org.apache.http.impl.pool.BasicPoolEntry;
import org.apache.http.message.BasicHttpRequest;
import org.apache.http.message.BasicHttpResponse;
import org.apache.http.nio.reactor.IOReactor;
import org.apache.http.nio.reactor.IOReactorException;
import org.apache.http.protocol.*;
import org.apache.http.ssl.SSLContexts;

import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

/**
 * Hello world!
 *
 */
public class App
{
    public static void main( String[] args )
    {
//        printHttpRequest();
//        printHttpResponse();
        try {
            testEntity();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void printHttpRequest() {
        HttpRequest request = new BasicHttpRequest("GET", "/", HttpVersion.HTTP_1_1);
        System.out.println(request.getRequestLine().getMethod());
        System.out.println(request.getRequestLine().getUri());
        System.out.println(request.getProtocolVersion());
        System.out.println(request.getRequestLine().toString());
    }

    private static void printHttpResponse() {
        HttpResponse response = new BasicHttpResponse(HttpVersion.HTTP_1_1, HttpStatus.SC_OK, "OK");
        System.out.println(response.getStatusLine().getProtocolVersion());
        System.out.println(response.getStatusLine().getReasonPhrase());
        System.out.println(response.getStatusLine().getStatusCode());
        System.out.println(response.getStatusLine().toString());
    }

    private static void testEntity() throws IOException {
        StringEntity entity = new StringEntity("message", Consts.UTF_8);
        System.out.println(entity.getContentType());
        System.out.println(entity.getContentLength());
        System.out.println(entity.getContentEncoding());
        System.out.println(entity.getContent().toString());
    }

    private static void testHttpProcessor(){
        HttpProcessor processor = HttpProcessorBuilder.create().add(new ResponseDate())
                .add(new ResponseServer("My Response Server 1.1"))
                .add(new ResponseContent())
                .add(new ResponseConnControl())
                .build();
        HttpService service = new HttpService(processor, null);
    }

    private static void testRequestHandler(){

        HttpRequestHandler handler = new HttpRequestHandler() {
            public void handle(HttpRequest request, HttpResponse response, HttpContext context) throws HttpException, IOException {
                response.setStatusCode(HttpStatus.SC_OK);
                response.setEntity(new StringEntity("some text", ContentType.TEXT_PLAIN));
            }
        };

        UriHttpRequestHandlerMapper handlerMapper = new UriHttpRequestHandlerMapper();
        handlerMapper.register("/service/*", handler);
        HttpProcessor processor = HttpProcessorBuilder.create().add(new ResponseDate())
                .add(new ResponseServer("My Response Server 1.1"))
                .add(new ResponseContent())
                .add(new ResponseConnControl())
                .build();
        HttpService httpService = new HttpService(processor, handlerMapper);
    }

    private static void testConnectionPool() throws ExecutionException, InterruptedException {
        HttpHost target = new HttpHost("localhost");
        BasicConnPool connpool = new BasicConnPool();
        connpool.setMaxTotal(200);
        connpool.setDefaultMaxPerRoute(10);
        connpool.setMaxPerRoute(target, 20);
        Future<BasicPoolEntry> future = connpool.lease(target, null);
        BasicPoolEntry poolEntry = future.get();
        HttpClientConnection conn = poolEntry.getConnection();
    }

    private static void testSSLCreate() throws IOException {
        SSLContext sslcontext = SSLContexts.createSystemDefault();
        SocketFactory sf = sslcontext.getSocketFactory();
        SSLSocket socket = (SSLSocket) sf.createSocket("somehost", 443);
        // Enforce TLS and disable SSL
        socket.setEnabledProtocols(new String[] {
                "TLSv1",
                "TLSv1.1",
                "TLSv1.2" });
        // Enforce strong ciphers
        socket.setEnabledCipherSuites(new String[] {
                "TLS_RSA_WITH_AES_256_CBC_SHA",
                "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
                "TLS_DHE_DSS_WITH_AES_256_CBC_SHA" });
        DefaultBHttpClientConnection conn = new DefaultBHttpClientConnection(8 * 1204);
        conn.bind(socket);

    }

    private static void testCreateReactor() throws IOReactorException {
        IOReactorConfig config = IOReactorConfig.DEFAULT;
        IOReactor ioreactor = new DefaultConnectingIOReactor(config);
    }

}
