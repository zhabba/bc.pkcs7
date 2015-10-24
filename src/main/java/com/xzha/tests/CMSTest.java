package com.xzha.tests;

import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.KeyTransRecipientInformation;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.*;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;

import java.io.*;
import java.nio.charset.Charset;
import java.security.*;
import java.security.cert.*;
import java.util.*;

/**
 * Class com.xzha.tests.CMSTest
 * created at 15.10.15 - 12:14
 */
public class CMSTest {
	private static final String KEY_STORE_PASSWORD = "test";
	private static final String KEY_STORE_PATH = "crt/certificates.p12";
	private static final String STORE_TYPE = "pkcs12";
	private static final String KEY_ALIACE = "Key1";
	public static String PLAIN_TEXT = "Hello World! I like it!";

	static final String DIGEST_SHA1 = "SHA1withRSA";
	static final String BC_PROVIDER = "BC";

	public static void main(String[] args) throws CMSException, CertificateException, OperatorCreationException, IOException, KeyStoreException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, CertPathValidatorException {
		try {
			KeyStore ks = getKeystore(KEY_STORE_PATH, STORE_TYPE, KEY_STORE_PASSWORD);

			/**
			 * Enevelope - de-envelope data
			 */
			byte[] enveloped = envelopeData(ks, KEY_ALIACE, PLAIN_TEXT.getBytes(Charset.forName("UTF-8")));
			System.out.println("Enveloped text:\n" + binaryToSmime(Base64.encode(enveloped)) + "\n");

			String deEnveloped = new String(extractEnvelopedData(ks, KEY_STORE_PASSWORD, KEY_ALIACE, enveloped));
			System.out.println("Deenveloped text:\n" + deEnveloped + "\n");


			/**
			 * Sign-and-envelope - de-envelope data
			 */

			byte[] signed = signAndEnevelopeData(ks, KEY_STORE_PASSWORD, KEY_ALIACE, PLAIN_TEXT.getBytes(Charset.forName("UTF-8")));
			String signed64 = binaryToSmime(Base64.encode(signed));
			System.out.println("Signed and enveloped data:\n" + signed64 + "\n");


			byte[] decoded64 = smimeToBinary(signed64);
			boolean ver64 = checkPKCS7Signature(decoded64);
			System.out.println("64 Signature verivied = " + ver64 + "\n");

			String exctracted64 = new String(extractEnvelopedAndSignedData(decoded64), Charset.forName("UTF-8"));
			System.out.println("64 Extracted text:\n" + exctracted64 + "\n");

			/**
			 * Verify signature
			 */
			boolean ver = checkPKCS7Signature(signed);
			System.out.println("Signature verivied = " + ver + "\n");


			String exctracted = new String(extractEnvelopedAndSignedData(signed), Charset.forName("UTF-8"));
			System.out.println("Extracted text:\n" + exctracted + "\n");

		} catch (Exception e) {
			e.printStackTrace();
		}

	}


	/**
	 * Load keystore from file
	 *
	 * @param keyStorePath
	 * @param keyStoreType
	 * @param keyPass
	 * @return
	 * @throws IOException
	 * @throws KeyStoreException
	 * @throws CertificateException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 */
	public static KeyStore getKeystore(String keyStorePath, String keyStoreType, String keyPass) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
		FileInputStream is = new FileInputStream(keyStorePath);
		KeyStore keystore = KeyStore.getInstance(keyStoreType);
		keystore.load(is, keyPass.toCharArray());
		is.close();

		return keystore;
	}

	/**
	 * Envelope data without signing and w/o including certs
	 * @param ks KeyStore
	 * @param keyAlias String
	 * @param dataToEnvelope byte[]
	 * @return
	 * @throws Exception
	 */
	public static byte[] envelopeData(KeyStore ks, String keyAlias, byte[] dataToEnvelope) throws Exception {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		X509Certificate cert = (X509Certificate) ks.getCertificate(keyAlias);

		// set up the generator
		CMSEnvelopedDataGenerator gen = new CMSEnvelopedDataGenerator();
		gen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(cert).setProvider(BC_PROVIDER));

		// create the enveloped-data object
		CMSProcessable data = new CMSProcessableByteArray(dataToEnvelope);

		CMSEnvelopedData enveloped = gen.generate(
				(CMSTypedData) data,
				new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC).setProvider(BC_PROVIDER).build());
		return enveloped.getEncoded();
	}

	/**
	 * Extract enveloped data without sign verification
	 * @param ks
	 * @param keyStorePass
	 * @param keyAlias
	 * @param dataEncrypted
	 * @return
	 * @throws CMSException
	 * @throws UnrecoverableKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws KeyStoreException
	 */
	public static byte[] extractEnvelopedData(KeyStore ks, String keyStorePass, String keyAlias, byte[] dataEncrypted) throws CMSException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		byte[] contents;
		CMSEnvelopedData enveloped = new CMSEnvelopedData(dataEncrypted);
		Collection recip = enveloped.getRecipientInfos().getRecipients();
		KeyTransRecipientInformation rinfo = (KeyTransRecipientInformation) recip.iterator().next();
		PrivateKey pKey = (PrivateKey) ks.getKey(keyAlias, keyStorePass.toCharArray());
		contents = rinfo.getContent(new JceKeyTransEnvelopedRecipient(pKey).setProvider(BC_PROVIDER));
		return contents;
	}

	/**
	 * Sign and envelope data invlude sign and cert
	 *
	 * @return
	 * @throws Exception
	 */
	public static byte[] signAndEnevelopeData(KeyStore ks, String keyStorePass, String keyAlias, byte[] dataToSignAndEnvelope) throws Exception {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		// Get private key and sign
		PrivateKey pKey = (PrivateKey) ks.getKey(keyAlias, keyStorePass.toCharArray());

		// Build CMS
		X509Certificate certFromKeystore = (X509Certificate) ks.getCertificate(keyAlias);
		List certList = new ArrayList();
		CMSTypedData data = new CMSProcessableByteArray(dataToSignAndEnvelope);
		certList.add(certFromKeystore);
		Store certs = new JcaCertStore(certList);
		CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
		ContentSigner sha1Signer = new JcaContentSignerBuilder(DIGEST_SHA1).setProvider(BC_PROVIDER).build(pKey);
		gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC_PROVIDER).build()).build(sha1Signer, certFromKeystore));
		gen.addCertificates(certs);
		CMSSignedData signedData = gen.generate(data, true);

		return signedData.getEncoded();
	}


	public static byte[] extractEnvelopedAndSignedData(byte[] signed) throws Exception {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		CMSSignedData s = new CMSSignedData(signed);
		return (byte[]) s.getSignedContent().getContent();
	}


	/**
	 * Convert byte[] to S/MIME string
	 * @param data
	 * @return
	 */
	public static String binaryToSmime(byte[] data) {
		StringBuilder sb = new StringBuilder();
		sb.append("-----BEGIN PKCS7-----\n");
		for (int i = 0; i < data.length; ) {
			byte[] chunk = Arrays.copyOfRange(data, i, (i + 63));
			sb.append(new String(chunk));
			sb.append("\n");
			i += 63;
		}
		sb.append("-----END PKCS7-----");
		return sb.toString();
	}

	/**
	 * Convert S/MIME string to byte[]
	 * @param smimeString
	 * @return
	 */
	public static byte[] smimeToBinary (String smimeString) {
		if (smimeString != null && !smimeString.isEmpty()) { //TODO:: Use pcl Utils for this check
			smimeString = smimeString.replace("-----BEGIN PKCS7-----", "");
			smimeString = smimeString.replace("-----END PKCS7-----", "");
			smimeString = smimeString.replace("\n", "");
			smimeString = smimeString.trim();
			return Base64.decode(smimeString);
		} else {
			return new byte[]{};
		}
	}

	/**
	 *
	 * @param signed
	 * @return
	 * @throws CMSException
	 * @throws CertificateException
	 * @throws OperatorCreationException
	 */
	public static boolean checkPKCS7Signature(byte[] signed) throws CMSException, CertificateException, OperatorCreationException {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		CMSSignedData signedData = new CMSSignedData(signed);
		Store certStore = signedData.getCertificates(); // This is where you access embedded certificates
		SignerInformationStore signers = signedData.getSignerInfos();
		Collection c = signers.getSigners();
		Iterator it = c.iterator();
		int verified = 0;
		while (it.hasNext()) {
			SignerInformation signer = (SignerInformation) it.next();
			Collection certCollection = certStore.getMatches(signer.getSID());

			Iterator certIt = certCollection.iterator();
			X509CertificateHolder cert = (X509CertificateHolder) certIt.next();

			if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC_PROVIDER).build(cert))) {
				verified++;
			}
		}

		return verified > 0;
	}
}
