package com.example.admin.test;

/**
 * Created by 15.84 on 01/11/2016.
 */

import android.content.*;
import android.os.*;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.*;
import org.bouncycastle.cert.jcajce.*;
import org.bouncycastle.jce.*;
import org.bouncycastle.operator.*;
import org.bouncycastle.operator.jcajce.*;
import org.bouncycastle.util.encoders.*;
import java.io.*;
import java.math.*;
import java.nio.charset.*;
import java.security.*;
import java.security.cert.*;
import java.text.*;
import java.util.*;
import javax.security.auth.x500.*;

public class Certificate {

    private static final String BC = org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME;
    private static final String KEY_STORE_TYPE = "PKCS12";
    private static final String KEY_STORE_TYPE_CERT = "cert";

    private Date iBegin;
    private Date iEnd;
    private String iEmail;
    private String iIssuer;
    private X509Certificate iX509Certificate;
    private PrivateKey iPriKey;
    private PublicKey iPubKey;
    private BigInteger iSerialNumber;
    private String iSubject;


    /** Construct a new SMINECertificate. */
    public Certificate () {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }


    /**
     * Construct a new SMINECertificate from a file.
     *
     * @param file File instance contains certificate.
     * @param password Password to read file.
     */
    public Certificate (File file, String password) {
        this();

        try {
            FileInputStream fileInStream = new FileInputStream(file);
            KeyStore keystore = KeyStore.getInstance(KEY_STORE_TYPE);
            keystore.load(fileInStream, password.toCharArray());
            Enumeration<String> e = keystore.aliases();
            for (; e.hasMoreElements();) {
                String alias = (String)e.nextElement();
                Key key = keystore.getKey(alias, password.toCharArray());
                if (key instanceof PrivateKey) {
                    // Get certificate of public key
                    X509Certificate cert = (X509Certificate)keystore.getCertificate(alias);
                    setBegin(cert.getNotBefore());
                    setEmail(alias);
                    setEnd(cert.getNotAfter());
                    setIssuer(cert.getIssuerX500Principal().getName());
                    setPriKey((PrivateKey)key);
                    setPubKey(cert.getPublicKey());
                    setSerialNumber(cert.getSerialNumber());
                    setSubject(cert.getSubjectX500Principal().getName());
                    break; // stop loop
                } // if
            } // for
            fileInStream.close();
        } catch (FileNotFoundException ex) {
            throw new RuntimeException("Construct SMINECertificate failed.", ex);
        } catch (IOException ex) {
            throw new RuntimeException("Construct SMINECertificate failed.", ex);
        } catch (KeyStoreException ex) {
            throw new RuntimeException("Construct SMINECertificate failed.", ex);
        } catch (java.security.cert.CertificateParsingException ex) {
            throw new RuntimeException("Construct SMINECertificate failed.", ex);
        } catch (Exception ex) {
            throw new RuntimeException("Construct SMINECertificate failed.", ex);
        } // catch
    } // Certificate()


    /**
     * Construct a new SMINECertificate.
     *
     * @param email Owner email as "name@kyeema.com".
     * @param subject Subject Info as "CN=kyeema, OU=kyeema, O=kyeema Corp, C=US".
     * @param issuer Issuer Info as "CN=SecureMail, OU=kyeema, O=kyeema Corp, C=US".
     * @param begin Begin Date of certificate expiration.
     * @param end End Date of certificate expiration.
     */
    public Certificate (String email, String subject, String issuer, Date begin, Date end) {
        this();
        try {
            setEmail(email);
            setSubject(subject);
            setIssuer(issuer);
            setBegin(begin);
            setEnd(end);

            // generate
            // warning http://android-developers.blogspot.com/2013/08/some-securerandom-thoughts.html
            KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", BC);
            kpGen.initialize(2048, new SecureRandom());
            KeyPair pair = kpGen.generateKeyPair();

            setPriKey(pair.getPrivate());
            setPubKey(pair.getPublic());
            setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));

        } catch (java.security.NoSuchAlgorithmException ex) {
            throw new RuntimeException("Construct SMINECertificate failed.", ex);
        } catch (Exception ex) {
            throw new RuntimeException("Construct SMINECertificate failed.", ex);
        } // catch
    } // Certificate()


    /**
     * Return the date as dd/MM/yyyy. For other format please use the overloaded method.
     *
     * @return the date.
     */
    public final String getBegin () {
        return getBegin("dd/MM/yyyy");
    } // getBegin()


    /**
     * Return the date using the specified format.
     *
     * @param fmt date format to apply.
     * @return the date.
     */
    public final String getBegin (String fmt) {
        SimpleDateFormat df = new SimpleDateFormat(fmt, Locale.getDefault());
        return iBegin == null ? "" : df.format(iBegin);
    } // getBegin()


    /**
     * Return the date as date value.
     *
     * @return the date as date value.
     */
    public final Date getBeginAsDate () {
        return iBegin;
    } // getBeginAsDate()


    /**
     * Return the date as long value.
     *
     * @return the date as long.
     */
    public final long getBeginAsLong () {
        return iBegin == null ? 0 : iBegin.getTime();
    } // getBeginAsLong()


    /**
     * Return the value of this field.
     *
     * @return string.
     */
    public final String getEmail () {
        return iEmail == null ? "" : iEmail;
    } // getEmail()


    /**
     * Return the date as dd/MM/yyyy. For other format please use the overloaded method.
     *
     * @return the date.
     */
    public final String getEnd () {
        return getEnd("dd/MM/yyyy");
    } // getEnd()


    /**
     * Return the date using the specified format.
     *
     * @param fmt date format to apply.
     * @return the date.
     */
    public final String getEnd (String fmt) {
        SimpleDateFormat df = new SimpleDateFormat(fmt, Locale.getDefault());
        return iEnd == null ? "" : df.format(iEnd);
    } // getEnd()


    /**
     * Return the date as date value.
     *
     * @return the date as date value.
     */
    public final Date getEndAsDate () {
        return iEnd;
    } // getEndAsDate()


    /**
     * Return the date as long value.
     *
     * @return the date as long.
     */
    public final long getEndAsLong () {
        return iEnd == null ? 0 : iEnd.getTime();
    } // getEndAsLong()


    /**
     * Return the value of this field.
     *
     * @return string.
     */
    public final String getIssuer () {
        return iIssuer == null ? "" : iIssuer;
    } // getIssuer()


    /**
     * Return the value of this field.
     *
     * @return string.
     */
    public final BigInteger getSerialNumber () {
        return iSerialNumber;
    } // getSerialNumber()


    /**
     * Return the value of this field.
     *
     * @return string.
     */
    public final String getSubject () {
        return iSubject == null ? "" : iSubject;
    } // getSubject()


    /**
     * Return the value of this field. private key using decrypt message
     * @return PrivateKey.
     */
    public final PrivateKey getPriKey () {
        return iPriKey;
    } // getPriKey()


    /**
     * Return the value of this field.
     *
     * @return PublicKey.
     */
    public final PublicKey getPubKey () {
        return iPubKey;
    } // getPubKey()


    /**
     * Build a keystore p12 from self info.
     * @param keyUsage using format p12 file digitalSignature or keyEncipherment.
     */
    public KeyStore saveWithSelfSigned (String password, X509KeyUsage keyUsage) {
        try {
            // create a new X509Cert builder
            X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(new X500Principal(getIssuer()), getSerialNumber(), getBeginAsDate(), getEndAsDate(), new X500Principal(getSubject()), getPubKey());
            // add extension
            certGen.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));
            certGen.addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_emailProtection));
            certGen.addExtension(Extension.keyUsage, true, keyUsage);
            certGen.addExtension(Extension.subjectAlternativeName, true, new GeneralNames(new GeneralName(GeneralName.rfc822Name, getEmail())));

            // prepare signer
            ContentSigner signerGenerator = new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider(BC).build(getPriKey());
            // generate cert from builder, this is public key, using encrypt message
            X509Certificate cert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(certGen.build(signerGenerator));

            // validate cert
            cert.checkValidity(new Date());
            cert.verify(cert.getPublicKey());

            KeyStore store = KeyStore.getInstance(KEY_STORE_TYPE);
            store.load(null);
            // set KeyEntry
            store.setKeyEntry(getEmail(), getPriKey(), password.toCharArray(), new java.security.cert.Certificate[] { cert });
            return store;
        } catch (FileNotFoundException ex) {
            throw new RuntimeException("Failed to build and save a self-signed smine certificate!", ex);
        } catch (IOException ex) {
            throw new RuntimeException("Failed to build and save a self-signed smine certificate!", ex);
        } catch (KeyStoreException ex) {
            throw new RuntimeException("Failed to build and save a self-signed smine certificate!", ex);
        } catch (java.security.cert.CertificateParsingException ex) {
            throw new RuntimeException("Failed to build and save a self-signed smine certificate!", ex);
        } catch (Exception ex) {
            throw new RuntimeException("Failed to build and save a self-signed smine certificate!", ex);
        } catch (Throwable t) {
            t.printStackTrace();
            throw new RuntimeException("Failed to build and save a self-signed smine certificate!", t);
        } // catch
    } // saveWithSelfSigned()


    /**
     * Set the date field.
     *
     * @param date new date.
     * @return itself.
     * @throws Exception if date is null, empty or invalid format.
     */
    public final Certificate setBegin (Date date) throws Exception {
        iBegin = date;
        return this;
    } // setBegin()


    /**
     * Set the date field.
     *
     * @param date string representing a date in the default format dd/MM/yyyy.
     * @return itself.
     * @throws Exception if date is null, empty or invalid format.
     */
    public final Certificate setBegin (String date) throws Exception {
        return setBegin(date, "dd/MM/yyyy");
    } // setBegin()


    /**
     * Set the date field.
     *
     * @param date string representing a date in the specifed format.
     * @param fmt format of date string.
     * @return itself.
     * @throws Exception if date is null, empty or invalid format.
     */
    public final Certificate setBegin (String date, String fmt) throws Exception {
        Date dt = null;
        if (date != null && !date.equals("")) {
            DateFormat df = new SimpleDateFormat(fmt, Locale.getDefault());
            try {
                dt = df.parse(date);
            } catch (Exception ex) {
                // throw new ITDException(ErrorCode.DATA_VALIDATION,
                // ErrorLevel.USER, "SMINECertificate.setBegin();", new
                // Exception("Date " + date + " format is invalid."));
            } // catch
        } // if
        if (iBegin == null && iBegin != dt || iBegin != null && !iBegin.equals(dt))
            iBegin = dt;
        // if
        return this;
    } // setBegin()


    /**
     * Set this field with new value.
     *
     * @param value string value to set this field.
     * @return itself.
     */
    public final Certificate setEmail (String value) {
        iEmail = value;
        return this;
    } // setEmail()


    /**
     * Set the date field.
     *
     * @param date new date.
     * @return itself.
     * @throws Exception if date is null, empty or invalid format.
     */
    public final Certificate setEnd (Date date) throws Exception {
        iEnd = date;
        return this;
    } // setEnd()


    /**
     * Set the date field.
     *
     * @param date string representing a date in the default format dd/MM/yyyy.
     * @return itself.
     * @throws Exception if date is null, empty or invalid format.
     */
    public final Certificate setEnd (String date) throws Exception {
        return setEnd(date, "dd/MM/yyyy");
    } // setEnd()


    /**
     * Set the date field.
     *
     * @param date string representing a date in the specifed format.
     * @param fmt format of date string.
     * @return itself.
     * @throws Exception if date is null, empty or invalid format.
     */
    public final Certificate setEnd (String date, String fmt) throws Exception {
        Date dt = null;
        if (date != null && !date.equals("")) {
            DateFormat df = new SimpleDateFormat(fmt);
            try {
                dt = df.parse(date);
            } catch (Exception ex) {
                // throw new ITDException(ErrorCode.DATA_VALIDATION,
                // ErrorLevel.USER, "SMINECertificate.setEnd();", new
                // Exception("Date " + date + " format is invalid."));
            } // catch
        } // if
        if (iEnd == null && iEnd != dt || iEnd != null && !iEnd.equals(dt))
            iEnd = dt;
        return this;
    } // setEnd()


    /**
     * Set this field with new value.
     *
     * @param value string value to set this field.
     * @return itself.
     */
    public final Certificate setIssuer (String value) {
        iIssuer = value;
        return this;
    } // setIssuer()


    /**
     * Set this field with new value.
     *
     * @param value PrivateKey value to set this field.
     * @return itself.
     */
    public final Certificate setPriKey (PrivateKey value) {
        iPriKey = value;
        return this;
    } // setPriKey()


    /**
     * Set this field with new value.
     *
     * @param value PublicKey value to set this field.
     * @return itself.
     */
    public final Certificate setPubKey (PublicKey value) {
        iPubKey = value;
        return this;
    } // setPubKey()


    /**
     * Set this field with new value.
     *
     * @param value string value to set this field.
     * @return itself.
     */
    public final Certificate setSerialNumber (BigInteger value) {
        iSerialNumber = value;
        return this;
    } // setSerialNumber()


    /**
     * Set this field with new value.
     *
     * @param value string value to set this field.
     * @return itself.
     */
    public final Certificate setSubject (String value) {
        iSubject = value;
        return this;
    } // setSubject()

} // SMINECertificate

