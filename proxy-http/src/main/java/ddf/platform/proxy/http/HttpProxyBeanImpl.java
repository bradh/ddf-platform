/**
 * Copyright (c) Codice Foundation
 * 
 * This is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser
 * General Public License as published by the Free Software Foundation, either version 3 of the
 * License, or any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details. A copy of the GNU Lesser General Public License
 * is distributed along with this program and can be found at
 * <http://www.gnu.org/licenses/lgpl.html>.
 * 
 **/

package ddf.platform.proxy.http;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Map;

import org.apache.http.ConnectionClosedException;
import org.apache.http.ConnectionReuseStrategy;
import org.apache.http.HttpClientConnection;
import org.apache.http.HttpException;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.HttpRequestInterceptor;
import org.apache.http.HttpResponse;
import org.apache.http.HttpResponseInterceptor;
import org.apache.http.HttpServerConnection;
import org.apache.http.impl.DefaultBHttpClientConnection;
import org.apache.http.impl.DefaultBHttpServerConnection;
import org.apache.http.impl.DefaultConnectionReuseStrategy;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.HTTP;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.HttpCoreContext;
import org.apache.http.protocol.HttpProcessor;
import org.apache.http.protocol.HttpRequestExecutor;
import org.apache.http.protocol.HttpRequestHandler;
import org.apache.http.protocol.HttpService;
import org.apache.http.protocol.ImmutableHttpProcessor;
import org.apache.http.protocol.RequestConnControl;
import org.apache.http.protocol.RequestContent;
import org.apache.http.protocol.RequestExpectContinue;
import org.apache.http.protocol.RequestTargetHost;
import org.apache.http.protocol.RequestUserAgent;
import org.apache.http.protocol.ResponseConnControl;
import org.apache.http.protocol.ResponseContent;
import org.apache.http.protocol.ResponseDate;
import org.apache.http.protocol.ResponseServer;
import org.apache.http.protocol.UriHttpRequestHandlerMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/*
 * Creates a local HTTP proxy server to proxy requests externally
 */
public class HttpProxyBeanImpl implements HttpProxyBean {
    private static final String HTTP_IN_CONN = "http.proxy.in-conn";
    private static final String HTTP_OUT_CONN = "http.proxy.out-conn";
    private static final String HTTP_CONN_KEEPALIVE = "http.proxy.conn-keepalive";
    
	private String proxyPort = "8888";
	private String targetHost = null;
	private String targetPort = "80";
	private static final Logger LOGGER = LoggerFactory
			.getLogger(HttpProxyBeanImpl.class);
    Thread t = null;
	
    /**
	 * Constructs a Http Proxy to accept requests locally and proxy out to an
	 * external server.
	 * 
	 */
	public HttpProxyBeanImpl() {

	}
	
	public void init(){	
		if (t == null){
			try {
				configureStartServer();
			} catch (IOException e) {
				LOGGER.debug(e.getMessage());
			}
		} else{
			LOGGER.debug("Thread is active: " + t.getId());
		}
	}
	
	/**
	 * Stop and remove server
	 */
	public void destroy() {
		LOGGER.trace("INSIDE: destroy()");
		t.interrupt();
		t = null;
	}

	/**
	 * Invoked when updates are made to the configuration of existing Http
	 * Proxies. This method is invoked by the container as specified by the
	 * update-strategy and update-method attributes in Spring beans XML file.
	 * 
	 * Note: Currently update is not working. It is best to restart server after
	 * for changes to take affect.
	 * 
	 * @param properties
	 */
	public void updateCallback(Map<String, Object> properties) {
		LOGGER.trace("ENTERING: updateCallback");
		//Set updated attributes
		setProxyPort((String)properties.get("proxyPort"));
		setTargetHost((String)properties.get("targetHost"));
		setTargetPort((String)properties.get("targetPort"));
		
		destroy();
		init();
		
		LOGGER.trace("EXITING: updateCallback");
	}

	/**
	 * Configures and starts the Http Proxy Server
	 * @throws IOException 
	 */
	private void configureStartServer() throws IOException {
        LOGGER.debug("Configuring Proxy: targetHost=" + targetHost + ", targetPort=" + targetPort + ", proxyPort=" + proxyPort);
        final HttpHost target = new HttpHost(targetHost, Integer.parseInt(targetPort));
        t = new RequestListenerThread(Integer.parseInt(proxyPort), target);
        t.setDaemon(false);
        t.start();
	}
	
	 static class ProxyHandler implements HttpRequestHandler  {

	        private final HttpHost target;
	        private final HttpProcessor httpproc;
	        private final HttpRequestExecutor httpexecutor;
	        private final ConnectionReuseStrategy connStrategy;

	        public ProxyHandler(
	                final HttpHost target,
	                final HttpProcessor httpproc,
	                final HttpRequestExecutor httpexecutor) {
	            super();
	            this.target = target;
	            this.httpproc = httpproc;
	            this.httpexecutor = httpexecutor;
	            this.connStrategy = DefaultConnectionReuseStrategy.INSTANCE;
	        }

	        public void handle(
	                final HttpRequest request,
	                final HttpResponse response,
	                final HttpContext context) throws HttpException, IOException {

	            final HttpClientConnection conn = (HttpClientConnection) context.getAttribute(
	                    HTTP_OUT_CONN);

	            context.setAttribute(HttpCoreContext.HTTP_CONNECTION, conn);
	            context.setAttribute(HttpCoreContext.HTTP_TARGET_HOST, this.target);

	            // Remove hop-by-hop headers
	            request.removeHeaders(HTTP.CONTENT_LEN);
	            request.removeHeaders(HTTP.TRANSFER_ENCODING);
	            request.removeHeaders(HTTP.CONN_DIRECTIVE);
	            request.removeHeaders("Keep-Alive");
	            request.removeHeaders("Proxy-Authenticate");
	            request.removeHeaders("TE");
	            request.removeHeaders("Trailers");
	            request.removeHeaders("Upgrade");
	            
	            LOGGER.debug("Request URI: " + request.getRequestLine().getUri());
	            LOGGER.debug("Request Protocol Version: " + request.getProtocolVersion());
	            LOGGER.debug("Request Method: " + request.getRequestLine().getMethod());
	            
	            
	            this.httpexecutor.preProcess(request, this.httpproc, context);
	            final HttpResponse targetResponse = this.httpexecutor.execute(request, conn, context);
	            this.httpexecutor.postProcess(response, this.httpproc, context);

	            // Remove hop-by-hop headers
	            targetResponse.removeHeaders(HTTP.CONTENT_LEN);
	            targetResponse.removeHeaders(HTTP.TRANSFER_ENCODING);
	            targetResponse.removeHeaders(HTTP.CONN_DIRECTIVE);
	            targetResponse.removeHeaders("Keep-Alive");
	            targetResponse.removeHeaders("TE");
	            targetResponse.removeHeaders("Trailers");
	            targetResponse.removeHeaders("Upgrade");

	            response.setStatusLine(targetResponse.getStatusLine());
	            response.setHeaders(targetResponse.getAllHeaders());
	            response.setEntity(targetResponse.getEntity());

	            LOGGER.debug("Response: " + response.getStatusLine());

	            final boolean keepalive = this.connStrategy.keepAlive(response, context);
	            context.setAttribute(HTTP_CONN_KEEPALIVE, new Boolean(keepalive));
	        }

	    }

    static class RequestListenerThread extends Thread {

        private final HttpHost target;
        private final ServerSocket serversocket;
        private final HttpService httpService;

        public RequestListenerThread(final int port, final HttpHost target) throws IOException {
            this.target = target;
            this.serversocket = new ServerSocket(port);            

            // Set up HTTP protocol processor for incoming connections
            final HttpProcessor inhttpproc = new ImmutableHttpProcessor(
                    new HttpRequestInterceptor[] {
                            new RequestContent(),
                            new RequestTargetHost(),
                            new RequestConnControl(),
                            new RequestUserAgent("Test/1.1"),
                            new RequestExpectContinue(true)
             });

            // Set up HTTP protocol processor for outgoing connections
            final HttpProcessor outhttpproc = new ImmutableHttpProcessor(
                    new HttpResponseInterceptor[] {
                            new ResponseDate(),
                            new ResponseServer("Test/1.1"),
                            new ResponseContent(),
                            new ResponseConnControl()
            });

            // Set up outgoing request executor
            final HttpRequestExecutor httpexecutor = new HttpRequestExecutor();

            // Set up incoming request handler
            final UriHttpRequestHandlerMapper reqistry = new UriHttpRequestHandlerMapper();
            reqistry.register("*", new ProxyHandler(
                    this.target,
                    outhttpproc,
                    httpexecutor));

            // Set up the HTTP service
            this.httpService = new HttpService(inhttpproc, reqistry);
        }

        @Override
        public void run() {
            LOGGER.debug("Listening on: " + this.serversocket.getLocalPort());
            while (!Thread.interrupted()) {
                try {
                    final int bufsize = 8 * 1024;
                    // Set up incoming HTTP connection
                    final Socket insocket = this.serversocket.accept();
                    final DefaultBHttpServerConnection inconn = new DefaultBHttpServerConnection(bufsize);
                    LOGGER.debug("Incoming connection from " + insocket.getInetAddress());
                    inconn.bind(insocket);

                    // Set up outgoing HTTP connection
                    final Socket outsocket = new Socket(this.target.getHostName(), this.target.getPort());
                    final DefaultBHttpClientConnection outconn = new DefaultBHttpClientConnection(bufsize);
                    outconn.bind(outsocket);
                    LOGGER.debug("Outgoing connection to " + outsocket.getInetAddress());

                    // Start worker thread
                    final Thread t = new ProxyThread(this.httpService, inconn, outconn);
                    t.setDaemon(true);
                    t.start();
                } catch (final InterruptedIOException ex) {
                    break;
                } catch (final IOException e) {
                	LOGGER.debug("I/O error initialising connection thread: "
                            + e.getMessage());
                    break;
                }
            }
        }
    }

    static class ProxyThread extends Thread {

        private final HttpService httpservice;
        private final HttpServerConnection inconn;
        private final HttpClientConnection outconn;

        public ProxyThread(
                final HttpService httpservice,
                final HttpServerConnection inconn,
                final HttpClientConnection outconn) {
            super();
            this.httpservice = httpservice;
            this.inconn = inconn;
            this.outconn = outconn;
        }

        @Override
        public void run() {
            final HttpContext context = new BasicHttpContext(null);

            // Bind connection objects to the execution context
            context.setAttribute(HTTP_IN_CONN, this.inconn);
            context.setAttribute(HTTP_OUT_CONN, this.outconn);

            try {
                while (!Thread.interrupted()) {
                    if (!this.inconn.isOpen()) {
                        this.outconn.close();
                        break;
                    }

                    this.httpservice.handleRequest(this.inconn, context);

                    final Boolean keepalive = (Boolean) context.getAttribute(HTTP_CONN_KEEPALIVE);
                    if (!Boolean.TRUE.equals(keepalive)) {
                        this.outconn.close();
                        this.inconn.close();
                        break;
                    }
                }
            } catch (final ConnectionClosedException ex) {
            	LOGGER.error("Client closed connection");
            } catch (final IOException ex) {
            	LOGGER.error("I/O error: " + ex.getMessage());
            } catch (final HttpException ex) {
            	LOGGER.error("Unrecoverable HTTP protocol violation: " + ex.getMessage());
            } finally {
                try {
                    this.inconn.shutdown();
                } catch (final IOException ignore) {}
                try {
                    this.outconn.shutdown();
                } catch (final IOException ignore) {}
            }
        }

    }

	public String getProxyPort() {
		return proxyPort;
	}

	public void setProxyPort(String proxyPort) {
		this.proxyPort = proxyPort;
	}

	public String getTargetHost() {
		return targetHost;
	}

	public void setTargetHost(String targetHost) {
		this.targetHost = targetHost;
	}

	public String getTargetPort() {
		return targetPort;
	}

	public void setTargetPort(String targetPort) {
		this.targetPort = targetPort;
	}
    
    

}
