/*
 * eID Client - Server Project.
 * Copyright (C) 2018 - 2018 BOSA.
 *
 * This is free software; you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License version 3.0 as published by
 * the Free Software Foundation.
 *
 * This software is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this software; if not, see https://www.gnu.org/licenses/.
 */

package be.fedict.eid.applet.service.signer.time;

import be.fedict.eid.applet.service.signer.facets.RevocationData;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.Header;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Store;

import java.io.InputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * A TSP time-stamp service implementation.
 *
 * @author Frank Cornelis
 */
public class TSPTimeStampService implements TimeStampService {

	private static final Log LOG = LogFactory.getLog(TSPTimeStampService.class);

	static {
		if (null == Security.getProvider(BouncyCastleProvider.PROVIDER_NAME)) {
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	public static final String DEFAULT_USER_AGENT = "eID Applet Service TSP Client";

	private final String tspServiceUrl;

	private ASN1ObjectIdentifier requestPolicy;

	private final String userAgent;

	private final TimeStampServiceValidator validator;

	private String username;

	private String password;

	private String proxyHost;

	private int proxyPort;

	private String digestAlgo;

	private ASN1ObjectIdentifier digestAlgoOid;

	public TSPTimeStampService(String tspServiceUrl, TimeStampServiceValidator validator) {
		this(tspServiceUrl, validator, null, null);
	}

	/**
	 * Main constructor.
	 *
	 * @param tspServiceUrl the URL of the TSP service.
	 * @param validator     the trust validator used to validate incoming TSP response
	 *                      signatures.
	 * @param requestPolicy the optional TSP request policy.
	 * @param userAgent     the optional User-Agent TSP request header value.
	 */
	public TSPTimeStampService(String tspServiceUrl, TimeStampServiceValidator validator, ASN1ObjectIdentifier requestPolicy, String userAgent) {
		if (null == tspServiceUrl) {
			throw new IllegalArgumentException("TSP service URL required");
		}
		this.tspServiceUrl = tspServiceUrl;

		if (null == validator) {
			throw new IllegalArgumentException("TSP validator required");
		}
		this.validator = validator;

		this.requestPolicy = requestPolicy;

		if (null != userAgent) {
			this.userAgent = userAgent;
		} else {
			this.userAgent = DEFAULT_USER_AGENT;
		}

		this.digestAlgo = "SHA-1";
		this.digestAlgoOid = TSPAlgorithms.SHA1;
	}

	/**
	 * Sets the request policy OID.
	 */
	public void setRequestPolicy(ASN1ObjectIdentifier policyOid) {
		this.requestPolicy = policyOid;
	}

	/**
	 * Sets the credentials used in case the TSP service requires
	 * authentication.
	 */
	public void setAuthenticationCredentials(String username, String password) {
		this.username = username;
		this.password = password;
	}

	/**
	 * Resets the authentication credentials.
	 */
	public void resetAuthenticationCredentials() {
		this.username = null;
		this.password = null;
	}

	/**
	 * Sets the digest algorithm used for time-stamping data. Example value:
	 * "SHA-1".
	 */
	public void setDigestAlgo(String digestAlgo) {
		if ("SHA-1".equals(digestAlgo)) {
			this.digestAlgoOid = TSPAlgorithms.SHA1;
		} else if ("SHA-256".equals(digestAlgo)) {
			this.digestAlgoOid = TSPAlgorithms.SHA256;
		} else if ("SHA-384".equals(digestAlgo)) {
			this.digestAlgoOid = TSPAlgorithms.SHA384;
		} else if ("SHA-512".equals(digestAlgo)) {
			this.digestAlgoOid = TSPAlgorithms.SHA512;
		} else {
			throw new IllegalArgumentException("unsupported digest algo: " + digestAlgo);
		}
		this.digestAlgo = digestAlgo;
	}

	/**
	 * Configures the HTTP proxy settings to be used to connect to the TSP
	 * service.
	 */
	public void setProxy(String proxyHost, int proxyPort) {
		this.proxyHost = proxyHost;
		this.proxyPort = proxyPort;
	}

	/**
	 * Resets the HTTP proxy settings.
	 */
	public void resetProxy() {
		this.proxyHost = null;
		this.proxyPort = 0;
	}

	public byte[] timeStamp(byte[] data, RevocationData revocationData) throws Exception {
		// digest the message
		MessageDigest messageDigest = MessageDigest.getInstance(this.digestAlgo);
		byte[] digest = messageDigest.digest(data);

		// generate the TSP request
		BigInteger nonce = new BigInteger(128, new SecureRandom());
		TimeStampRequestGenerator requestGenerator = new TimeStampRequestGenerator();
		requestGenerator.setCertReq(true);
		if (null != this.requestPolicy) {
			requestGenerator.setReqPolicy(this.requestPolicy);
		}
		TimeStampRequest request = requestGenerator.generate(this.digestAlgoOid, digest, nonce);
		byte[] encodedRequest = request.getEncoded();

		// create the HTTP client
		HttpClient httpClient = createHttpClient();

		// create the HTTP POST request
		HttpPost httpPost = new HttpPost(this.tspServiceUrl);
		httpPost.addHeader("User-Agent", this.userAgent);
		httpPost.setEntity(new ByteArrayEntity(encodedRequest, ContentType.create("application/timestamp-query")));

		// invoke TSP service
		HttpResponse response = httpClient.execute(httpPost);
		if (response.getStatusLine().getStatusCode() != HttpStatus.SC_OK) {
			LOG.error("Error contacting TSP server " + this.tspServiceUrl);
			throw new Exception("Error contacting TSP server " + this.tspServiceUrl);
		}

		// HTTP input validation
		Header responseContentTypeHeader = response.getFirstHeader("Content-Type");
		if (responseContentTypeHeader == null) {
			throw new RuntimeException("Missing Content-Type header");
		}
		String contentType = responseContentTypeHeader.getValue();
		if (!contentType.startsWith("application/timestamp-reply")) {
			LOG.debug("Response content: " + EntityUtils.toString(response.getEntity()));
			throw new RuntimeException("Invalid Content-Type: " + contentType);
		}
		if (response.getEntity().getContentLength() == 0) {
			throw new RuntimeException("Content-Length is zero");
		}

		// TSP response parsing and validation
		InputStream inputStream = response.getEntity().getContent();
		TimeStampResponse timeStampResponse = new TimeStampResponse(inputStream);
		timeStampResponse.validate(request);

		if (0 != timeStampResponse.getStatus()) {
			LOG.debug("status: " + timeStampResponse.getStatus());
			LOG.debug("status string: " + timeStampResponse.getStatusString());
			PKIFailureInfo failInfo = timeStampResponse.getFailInfo();
			if (null != failInfo) {
				LOG.debug("fail info int value: " + failInfo.intValue());
				if (PKIFailureInfo.unacceptedPolicy == failInfo.intValue()) {
					LOG.debug("unaccepted policy");
				}
			}
			throw new RuntimeException("timestamp response status != 0: " + timeStampResponse.getStatus());
		}
		TimeStampToken timeStampToken = timeStampResponse.getTimeStampToken();
		SignerId signerId = timeStampToken.getSID();
		BigInteger signerCertSerialNumber = signerId.getSerialNumber();
		X500Name signerCertIssuer = signerId.getIssuer();
		LOG.debug("signer cert serial number: " + signerCertSerialNumber);
		LOG.debug("signer cert issuer: " + signerCertIssuer);

		// TSP signer certificates retrieval
		@SuppressWarnings("unchecked") Store<X509CertificateHolder> certStore = timeStampToken.getCertificates();
		Collection<X509CertificateHolder> certificates = certStore.getMatches(null);
		X509CertificateHolder signerCertificateHolder = null;
		Map<String, X509CertificateHolder> certificateMap = new HashMap<>();
		for (X509CertificateHolder certificateHolder : certificates) {
			if (signerCertIssuer.equals(certificateHolder.getIssuer()) && signerCertSerialNumber.equals(certificateHolder.getSerialNumber())) {
				signerCertificateHolder = certificateHolder;
			}
			String ski = Hex.encodeHexString(getSubjectKeyId(certificateHolder));
			certificateMap.put(ski, certificateHolder);
			LOG.debug("embedded certificate: " + certificateHolder.getSubject() + "; SKI=" + ski);
		}

		if (signerCertificateHolder == null) {
			throw new RuntimeException("TSP response token has no signer certificate");
		}

		// TSP signer cert path building
		List<X509Certificate> tspCertificateChain = new LinkedList<>();
		X509CertificateHolder currentCertificateHolder = signerCertificateHolder;
		do {
			LOG.debug("adding to certificate chain: " + currentCertificateHolder.getSubject());
			tspCertificateChain.add(getFromHolder(currentCertificateHolder));
			if (currentCertificateHolder.getSubject().equals(currentCertificateHolder.getIssuer())) {
				break;
			}
			String aki = Hex.encodeHexString(getAuthorityKeyId(currentCertificateHolder));
			currentCertificateHolder = certificateMap.get(aki);
		} while (null != currentCertificateHolder);

		// verify TSP signer signature
		SignerInformationVerifier signerInformationVerifier = new JcaSimpleSignerInfoVerifierBuilder()
				.setProvider(BouncyCastleProvider.PROVIDER_NAME)
				.build(signerCertificateHolder);
		timeStampToken.validate(signerInformationVerifier);

		// verify TSP signer certificate
		this.validator.validate(tspCertificateChain, revocationData);

		LOG.debug("time-stamp token time: " + timeStampToken.getTimeStampInfo().getGenTime());

		return timeStampToken.getEncoded();
	}

	private HttpClient createHttpClient() {
		HttpClientBuilder builder = HttpClients.custom();
		if (null != this.username) {
			BasicCredentialsProvider credentialsProvider = new BasicCredentialsProvider();
			credentialsProvider.setCredentials(AuthScope.ANY, new UsernamePasswordCredentials(this.username, this.password));
			builder.setDefaultCredentialsProvider(credentialsProvider);
		}
		if (null != this.proxyHost) {
			builder.setProxy(new HttpHost(this.proxyHost, this.proxyPort));
		}

		return builder.build();
	}

	private byte[] getSubjectKeyId(X509CertificateHolder cert) {
		return SubjectKeyIdentifier.fromExtensions(cert.getExtensions()).getKeyIdentifier();
	}

	private byte[] getAuthorityKeyId(X509CertificateHolder cert) {
		return AuthorityKeyIdentifier.fromExtensions(cert.getExtensions()).getKeyIdentifier();
	}

	private X509Certificate getFromHolder(X509CertificateHolder certificateHolder) throws CertificateException {
		return new JcaX509CertificateConverter().setProvider( "BC" ).getCertificate( certificateHolder );
	}
}