package org.example;

import com.lowagie.text.Rectangle;
import com.lowagie.text.pdf.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.URL;
import java.security.*;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.HashMap;

public class Main {
  public static X509CRL downloadCRL(String crlUrl) throws Exception {
    URL url = new URL(crlUrl);
    try (InputStream in = url.openStream()) {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      return (X509CRL) cf.generateCRL(in);
    }
  }

  public static void main(String[] args) throws Exception {
    // Thêm BouncyCastle làm provider cho các thuật toán mã hoá/PKI
    BouncyCastleProvider BC = new BouncyCastleProvider();
    Security.addProvider(BC);

    // Đường dẫn file và thông tin keystore
    String src = "./license.pdf";
    String dest = "./signed_license.pdf";
    String keystore = "./test.p12";
    char[] password = "1".toCharArray();

    String crlUrl = "http://crl3.fis.com.vn/fptca-sha256-2025.crl";
    String crlRootUrl = "https://rootca.gov.vn/crl/vnrca256.crl";
    String tsaUrl = "http://dss.nowina.lu/pki-factory/tsa/ee-good-tsa";

    // -----------------------------
    // Tải private key và certificate chain từ keystore PKCS#12
    KeyStore ks = KeyStore.getInstance("PKCS12");
    ks.load(new FileInputStream(keystore), password);
    String alias = ks.aliases().nextElement(); // lấy alias đầu tiên
    PrivateKey pk = (PrivateKey) ks.getKey(alias, password); // private key dùng để ký
    Certificate[] chain = ks.getCertificateChain(alias); // chuỗi chứng chỉ

    X509Certificate signerCert = (X509Certificate) ks.getCertificate(alias);
    X509Certificate issuerCert = (X509Certificate) chain[1];

    System.out.println("Loaded alias: " + alias);
    System.out.println("Certificate chain length: " + chain.length);

    // -----------------------------
    // Chuẩn bị file PDF để ký
    PdfReader reader = new PdfReader(src); // đọc file PDF gốc
    FileOutputStream fos = new FileOutputStream(dest); // stream ghi file kết quả
    PdfStamper stamper = PdfStamper.createSignature(reader, fos, '\0'); // tạo PDF để ký

    // -----------------------------
    // Thiết lập thông tin chữ ký hiển thị
    PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
    appearance.setReason("Approval RSA");
    appearance.setLocation("Ho Chi Minh City, Vietnam");
    appearance.setVisibleSignature(new Rectangle(36, 748, 200, 780), 1, "Signature");
    appearance.setCrypto(pk, chain, null, PdfSignatureAppearance.WINCER_SIGNED); // liên kết key và cert
    // NOTE: PdfSignatureAppearance.NOT_CERTIFIED: PDF không phải là tài liệu chứng nhận, chỉ là chữ ký số bình thường
    // NOTE: PdfSignatureAppearance.CERTIFIED_NO_CHANGES_ALLOWED: Đây là chữ ký chứng nhận PDF, không cho phép thay đổi tài liệu sau khi ký
    appearance.setCertificationLevel(PdfSignatureAppearance.NOT_CERTIFIED); // mức độ chứng thực PDF

    // -----------------------------
    // Tạo dictionary mô tả chữ ký (metadata)
    PdfDictionary dic = new PdfDictionary();
    dic.put(PdfName.FT, PdfName.SIG); // field type: signature
    dic.put(PdfName.FILTER, PdfName.ADOBE_PPKLITE); // bộ lọc chữ ký Adobe
    dic.put(PdfName.SUBFILTER, PdfName.ADBE_PKCS7_DETACHED); // kiểu PKCS#7 detached
    dic.put(PdfName.M, new PdfDate()); // thời gian ký
    dic.put(PdfName.NAME, new PdfString("signature_rsa"));
    appearance.setCryptoDictionary(dic); // gán dictionary cho chữ ký

    // -----------------------------
    // Chuẩn bị vùng placeholder cho dữ liệu chữ ký (/Contents)
    int estimatedSize = 102400; // kích thước ước lượng vùng trống
    HashMap<PdfName, Integer> exc = new HashMap<>();
    exc.put(PdfName.CONTENTS, estimatedSize * 2 + 2); // vùng trống /Contents (hex → *2)
    appearance.preClose(exc); // tạo PDF placeholder trống và đóng tạm trước khi ký

    // -----------------------------
    // Hash nội dung PDF (trừ phần chữ ký)
    InputStream data = appearance.getRangeStream(); // lấy dữ liệu vùng cần ký
    MessageDigest md = MessageDigest.getInstance("SHA256"); // hash SHA-256
    byte[] buf = new byte[102400];
    int n;
    while ((n = data.read(buf)) > 0) { // đọc từng phần và cập nhật hash
      md.update(buf, 0, n);
    }
    byte[] hash = md.digest(); // kết quả hash

    // -----------------------------
    // Ký theo chuẩn Adobe bằng PdfPKCS7
    // lấy CRL
    X509CRL crl = downloadCRL(crlUrl);
    X509CRL rootCrl = downloadCRL(crlRootUrl);
    CRL[] crlArray = new CRL[] { crl, rootCrl };

    System.out.println("thisUpdate: " + crl.getThisUpdate());
    System.out.println("nextUpdate: " + crl.getNextUpdate());

    System.out.println("thisUpdate root: " + rootCrl.getThisUpdate());
    System.out.println("nextUpdate root: " + rootCrl.getNextUpdate());

    // lấy TSA
    TSAClient tsa = new TSAClientBouncyCastle(tsaUrl);

    // khởi tạo chữ ký PKCS7
    PdfPKCS7 signer = new PdfPKCS7(pk, chain, crlArray, "SHA256", "BC", false);

    // lấy OCSP (nếu không nhúng CRL)
    String ocspUrl = PdfPKCS7.getOCSPURL(signerCert);
    OcspClient ocsp = new OcspClientBouncyCastle(signerCert, issuerCert, ocspUrl);
    byte[] ocspBytes = ocsp.getEncoded();

    // lấy Calendar
    Calendar cal = Calendar.getInstance();

    // sinh authenticated attributes chuẩn CMS/PKCS#7
    byte[] authAttr = signer.getAuthenticatedAttributeBytes(hash, cal, null);
    signer.update(authAttr, 0, authAttr.length);

    // sinh PKCS#7 có signed attributes
    byte[] encodedSig = signer.getEncodedPKCS7(hash, cal, tsa, null);

    // -----------------------------
    // Sao chép chữ ký thật vào vùng đệm cố định
    byte[] paddedSig = new byte[estimatedSize]; // vùng trống 8192 byte
    System.arraycopy(encodedSig, 0, paddedSig, 0, encodedSig.length); // chép chữ ký thật vào đầu vùng trống

    System.out.println("Signature length: " + encodedSig.length); // ~93300 bytes
    System.out.println("OCSP INFO: " + ocspUrl);
    // System.out.println("CRL INFO: " + signer.getCRLs());

    // -----------------------------
    // Tạo dictionary chứa chữ ký thật
    PdfDictionary dic2 = new PdfDictionary();
    dic2.put(PdfName.CONTENTS, new PdfString(paddedSig).setHexWriting(true)); // dữ liệu hex của chữ ký

    // Nhúng chữ ký vào PDF và đóng file
    appearance.close(dic2); // ghi chữ ký vào PDF và đóng

    System.out.println("PDF signed successfully: " + dest);

  }
}
