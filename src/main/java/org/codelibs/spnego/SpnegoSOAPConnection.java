/** 
 * Copyright (C) 2009 "Darwin V. Felix" <darwinfelix@users.sourceforge.net>
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

package org.codelibs.spnego;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.PrivilegedActionException;
import java.util.logging.Logger;

import javax.security.auth.login.LoginException;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.soap.MessageFactory;
import javax.xml.soap.MimeHeaders;
import javax.xml.soap.SOAPConnection;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.codelibs.spnego.SpnegoHttpFilter.Constants;

import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/**
 * This class can be used to make SOAP calls to a protected SOAP Web Service.
 * 
 * <p>
 * The idea for this class is to replace code that looks like this...
 * </p>
 * <pre>
 *  final SOAPConnectionFactory soapConnectionFactory =
 *      SOAPConnectionFactory.newInstance();
 *  conn = soapConnectionFactory.createConnection();
 * </pre>
 * 
 * <p>
 * with code that looks like this...
 * </p>
 * <pre>
 *  conn = new SpnegoSOAPConnection("spnego-client", "dfelix", "myp@s5");
 * </pre>
 * 
 * <p><b>Example:</b></p>
 * <pre>
 * System.setProperty("java.security.krb5.conf", "C:/Users/dfelix/krb5.conf");
 * System.setProperty("java.security.auth.login.config", "C:/Users/dfelix/login.conf");
 * 
 * <b>final SpnegoSOAPConnection conn =
 *     new SpnegoSOAPConnection(this.module, this.kuser, this.kpass);</b>
 * 
 * try {
 *     MessageFactory factory = MessageFactory.newInstance();
 *     SOAPMessage message = factory.createMessage();
 *     
 *     SOAPHeader header = message.getSOAPHeader();
 *     SOAPBody body = message.getSOAPBody();
 *     header.detachNode();
 *     
 *     QName bodyName = new QName("http://wombat.ztrade.com",
 *         "GetLastTradePrice", "m");
 *     SOAPBodyElement bodyElement = body.addBodyElement(bodyName);
 *     
 *     QName name = new QName("symbol");
 *     SOAPElement symbol = bodyElement.addChildElement(name);
 *     symbol.addTextNode("SUNW");
 *     
 *     URL endpoint = new URL("http://spnego.sourceforge.net/soap.html");
 *     SOAPMessage response = conn.call(message, endpoint);
 *     
 *     SOAPBody soapBody = response.getSOAPBody();
 *     
 *     Iterator iterator = soapBody.getChildElements(bodyName);
 *     bodyElement = (SOAPBodyElement)iterator.next();
 *     String lastPrice = bodyElement.getValue();
 *     
 *     System.out.print("The last price for SUNW is ");
 *     System.out.println(lastPrice);
 *     
 * } finally {
 *     conn.close();
 * }
 * </pre>
 * 
 * <p>
 * To see a full working example, take a look at the 
 * <a href="http://spnego.sourceforge.net/ExampleSpnegoSOAPClient.java" 
 * target="_blank">ExampleSpnegoSOAPClient.java</a> 
 * example.
 * </p>
 * 
 * <p>
 * Also, take a look at the  
 * <a href="http://spnego.sourceforge.net/protected_soap_service.html" 
 * target="_blank">how to connect to a protected SOAP Web Service</a> 
 *  example.
 * </p>
 * 
 * @see SpnegoHttpURLConnection
 * 
 * @author Darwin V. Felix
 *
 */
public class SpnegoSOAPConnection extends SOAPConnection {
    
    /** Default LOGGER. */
    private static final Logger LOGGER = 
        Logger.getLogger(SpnegoSOAPConnection.class.getName());

    private final SpnegoHttpURLConnection conn;
    
    private final DocumentBuilderFactory documentFactory = 
        DocumentBuilderFactory.newInstance();
    
    private final MessageFactory messageFactory;
    
    /**
     * Creates an instance where the LoginContext relies on a keytab 
     * file being specified by "java.security.auth.login.config" or 
     * where LoginContext relies on tgtsessionkey.
     * 
     * @param loginModuleName 
     * @throws LoginException 
     */
    public SpnegoSOAPConnection(final String loginModuleName) throws LoginException {
        super();
        this.conn = new SpnegoHttpURLConnection(loginModuleName);
        
        try {
            this.messageFactory = MessageFactory.newInstance();
        } catch (SOAPException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Create an instance where the GSSCredential is specified by the parameter 
     * and where the GSSCredential is automatically disposed after use.
     *  
     * @param creds credentials to use
     */
    public SpnegoSOAPConnection(final GSSCredential creds) {
        this(creds, true);
    }

    /**
     * Create an instance where the GSSCredential is specified by the parameter 
     * and whether the GSSCredential should be disposed after use.
     * 
     * @param creds credentials to use
     * @param dispose true if GSSCredential should be diposed after use
     */
    public SpnegoSOAPConnection(final GSSCredential creds, final boolean dispose) {
        super();
        this.conn = new SpnegoHttpURLConnection(creds, dispose);
        
        try {
            this.messageFactory = MessageFactory.newInstance();
        } catch (SOAPException e) {
            throw new IllegalStateException(e);
        }
    }
    
    /**
     * Create an instance where the GSSCredential is specified by the parameter 
     * and whether the GSSCredential should be disposed after use.
     * 
     * Set confidentiality and mutual integrity to both be false or both be true. 
     * 
     * @param creds credentials to use
     * @param dispose true if GSSCredential should be diposed after use
     * @param confidential
     * @param integrity
     */
    public SpnegoSOAPConnection(final GSSCredential creds, final boolean dispose
        , final boolean confidential, final boolean integrity) {
        super();
        this.conn = new SpnegoHttpURLConnection(creds, dispose);
        this.conn.setConfidentiality(confidential);
        this.conn.setMessageIntegrity(integrity);
        
        try {
            this.messageFactory = MessageFactory.newInstance();
        } catch (SOAPException e) {
            throw new IllegalStateException(e);
        }
    }
    
    /**
     * Creates an instance where the LoginContext does not require a keytab
     * file. However, the "java.security.auth.login.config" property must still
     * be set prior to instantiating this object.
     * 
     * @param loginModuleName 
     * @param username 
     * @param password 
     * @throws LoginException 
     */
    public SpnegoSOAPConnection(final String loginModuleName,
        final String username, final String password) throws LoginException {

        super();
        this.conn = new SpnegoHttpURLConnection(loginModuleName, username, password);
        
        try {
            this.messageFactory = MessageFactory.newInstance();
        } catch (SOAPException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public final SOAPMessage call(final SOAPMessage request, final Object endpoint)
        throws SOAPException {
        
        LOGGER.fine(() -> "endpoint=" + endpoint);
        
        SOAPMessage message = null;
        final ByteArrayOutputStream bos = new ByteArrayOutputStream();
        
        this.conn.setRequestMethod("POST");
        
        try {
            final MimeHeaders headers = request.getMimeHeaders();
            final String[] contentType = headers.getHeader(Constants.CONTENT_TYPE);
            final String[] soapAction = headers.getHeader(Constants.SOAP_ACTION);
            
            // build the Content-Type HTTP header parameter if not defined
            if (null == contentType) {
                final StringBuilder header = new StringBuilder();
    
                if (null == soapAction) {
                    header.append("application/soap+xml; charset=UTF-8;");
                } else {
                    header.append("text/xml; charset=UTF-8;");
                }
    
                // not defined as a MIME header but we need it as an HTTP header parameter
                this.conn.addRequestProperty(Constants.CONTENT_TYPE, header.toString());
            } else {
                if (contentType.length > 1) {
                    throw new IllegalArgumentException("Content-Type defined more than once.");
                }
                
                // user specified as a MIME header so add it as an HTTP header parameter
                this.conn.addRequestProperty(Constants.CONTENT_TYPE, contentType[0]);
            }
            
            // specify SOAPAction as an HTTP header parameter
            if (null != soapAction) {
                if (soapAction.length > 1) {
                    throw new IllegalArgumentException("SOAPAction defined more than once.");
                }
                this.conn.addRequestProperty(Constants.SOAP_ACTION, soapAction[0]);
            }
    
            request.writeTo(bos);
            
            // make the call
            this.conn.connect(new URL(endpoint.toString()), bos);
            
            // parse the response
            message = this.createMessage(this.conn.getInputStream());
            
        } catch (IOException | GSSException | PrivilegedActionException e) {
            throw new SOAPException(e);
        } finally {
            try {
                bos.close();
            } catch (IOException ioe) {
                assert true;
            }
            this.close();
        }

        return message;
    }

    @Override
    public final void close() {
        if (null != this.conn) {
            this.conn.disconnect();
        }
    }
    
    private SOAPMessage createMessage(final InputStream stream) throws SOAPException {
        final Document document;
        
        try {
            document = this.parse(stream);
        } catch (IOException | SAXException | ParserConfigurationException e) {
            throw new SOAPException(e);
        }

        Node soapBody = null;

        // confirm that we have a soap envelope
        final Element parent = document.getDocumentElement();
        
        if ("Envelope".equalsIgnoreCase(parent.getLocalName())) {
            // confirm that we have a body element
            
            final NodeList children = parent.getChildNodes();
            
            for (int i = 0; i < children.getLength(); i++) {
                final Node node = children.item(i);
                if ("Body".equalsIgnoreCase(node.getLocalName())) {
                    soapBody = parent.removeChild(node);
                    break;
                }
            }

            if (null == soapBody) {
                throw new IllegalArgumentException(
                        "Response did not contain a SOAP 'Body'.");
            }
        } else {
            throw new IllegalArgumentException(
                    "Response did not contain a SOAP 'Envelope'.");
        }
        
        try {
            return this.transform(soapBody);
        } catch (TransformerFactoryConfigurationError | TransformerException | IOException | SAXException
                | ParserConfigurationException e) {
            throw new SOAPException(e);
        }
    }

    private Document parse(final InputStream stream) 
        throws SAXException, IOException, ParserConfigurationException {
        
        this.documentFactory.setNamespaceAware(true);
        
        return this.documentFactory.newDocumentBuilder().parse(stream);
    }
    
    private SOAPMessage transform(final Node soapBody) throws SOAPException, IOException
        , TransformerException, SAXException, ParserConfigurationException {

        final SOAPMessage message = messageFactory.createMessage();
        
        final Transformer transformer = 
            TransformerFactory.newInstance().newTransformer();
        
        final NodeList children = soapBody.getChildNodes();
        
        LOGGER.fine(() -> "number of children=" + children.getLength());

        for (int i = 0; i < children.getLength(); i++) {
            final int pos = i;
            LOGGER.fine(() -> "child[" + pos + "]=" + children.item(pos).getLocalName());
            
            try (final ByteArrayOutputStream bos = new ByteArrayOutputStream()) {

                transformer.transform(new DOMSource(children.item(i)), new StreamResult(bos));
                bos.flush();

                try (final ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray())) {
                    final Document document = this.parse(bis);
                    message.getSOAPBody().addDocument(document);
                }
            }
        }

        return message;
    }
}
