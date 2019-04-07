package pck;
 
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.Writer;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;
import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V1CertificateGenerator;

import java.security.InvalidKeyException;
import java.security.KeyPair;

 
@SuppressWarnings({ "unused", "deprecation" })
public class MainCS {
   /*
    * Constantes
    */
    public final static String HOST ="localhost";
    public final static int PORT = 4004;
	public static final String AES = "AES";
	public static final String RSA = "RSA";
	public static final String HMACMD5 = "HMACMD5";

	
	public static final String HOLA = "HOLA";
	public static final String ALGORITMOS = "ALGORITMOS";
	public static final String DP = ":";
	private static final String OK = "OK";
    
    /*
     * declaracion de variables
     */
    private Socket socket;
    private PrintWriter pw;
    private BufferedReader br;
    private String input;
    private String output;
    
    /*
     * Certificado
     */
	private KeyPair keyPair;
	private PublicKey publicKey;
	private SecretKey secretKey;
   
    public static void main(String[] args) {
        MainCS mainSS = new MainCS();
       
        mainSS.conectar();
    }
 
    private void conectar() {
    	byte[] b = new byte[32];
    	new Random().nextBytes(b);
    	
        System.out.println("Intentando conexion con servidor ss...");
       
        try {
            socket = new Socket(HOST, PORT);
            pw = new PrintWriter(socket.getOutputStream(), true);
            br = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            System.out.println("conectado");
           
            //Envia Hola y llega ok del server
            output=HOLA;
            send(output);
            System.out.println("Cliente:"+output);
            input=read();
            System.out.println("Servidor:"+input );
            
            //Envia Algoritmos a usar
            output=ALGORITMOS+DP+AES+DP+RSA+DP+HMACMD5;
            send(output);
            System.out.println("Cliente:"+output);
            input=read();
            System.out.println("Servidor:"+input );
            
            //Se genera el certificado para mandar al servidor, se guarda en el output y se envia

           keyPair = KeyPairGenerator.getInstance(RSA, new BouncyCastleProvider()).generateKeyPair();
            
           output = generateCertificate(keyPair);
          
          
          	System.out.println("Cliente:"+ output);
          	send(output);
          	input=read();
          	System.out.println("Servidor:"+input );
            
            //sale la llave publica del certidicado generado por el servidor
          
            publicKey = getCertificate(input).getPublicKey();
            
            
            //creacion llave de session encriptacion y envio
            
            secretKey = new SecretKeySpec(b, "AES");
            
            String certEncoded= DatatypeConverter.printHexBinary(cifrarAsim(secretKey.getEncoded()));
            System.out.println("cliente enviando certificado cifrado...");
            output= certEncoded;
            send(output);
            System.out.println("Cliente:"+output);
            input=read();
            
            System.out.println("Server:"+input);
            
            
            String PkeyServer = input;
            byte[] PkeyCif= DatatypeConverter.parseHexBinary(PkeyServer);
            
            secretKey=new SecretKeySpec(descifrarAsim(PkeyCif),"AES");
            
            
            //Envio de OK requerido por protocolo
            send(OK);
            System.out.println("Cliente:"+OK);
            
           //Envio de datos y encriptacion con hash
           BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
           System.out.println("Envie datos(EJ:15;41 24.2028,2 10.4418):"); 
           output = stdIn.readLine();
           byte[] datosEnc= cifrarSime(output.getBytes());
           byte[] datosHash= hasher(output.getBytes(),secretKey, "HMACMD5");
           
           String sDatosEnc =DatatypeConverter.printHexBinary(datosEnc);
           String sDatosHash =DatatypeConverter.printHexBinary(datosHash);
           
           send(sDatosEnc);
           send(sDatosHash);
           
           System.out.println("Cliente(Datos encriptados):"+ sDatosEnc);
           System.out.println("Cliente(Datos hash):"+ sDatosHash);
           
           input=read();
           System.out.println("Servidor:"+input );
           
           System.out.println("termino con exito");
           stdIn.close();
           socket.close();
           pw.close();
           br.close();
           
        } catch (Exception e) {
           
            System.err.println("Error: " + e.getMessage()); System.exit(0);
        }
       
     
       
    }
    
   /*
    * Metodos extra
    */
    
    
    /*
     * Metodo para ciframiento asimetrico
     */
    private byte[] cifrarAsim(byte[] encoded) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		Cipher ci = Cipher.getInstance(RSA);
		ci.init(Cipher.ENCRYPT_MODE, publicKey);
		return ci.doFinal(encoded);
	}
    /*
     * Metodo para desciframiento asimetrico
     */
	private byte[] descifrarAsim(byte[] codific) throws Exception {
		Cipher ci = Cipher.getInstance("RSA");
		ci.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
		return ci.doFinal(codific);	
	}
	/*
	 * Metodo de cifriamiento simetrico
	 */
	private byte[] cifrarSime(byte[] clearText) throws Exception {

		Cipher ci = Cipher.getInstance("AES/ECB/PKCS5Padding");
		ci.init(Cipher.ENCRYPT_MODE, secretKey);
		return ci.doFinal(clearText);
	}
	/*
	 * Envia string a travez del socket
	 */
	private void send(String msg){
       pw.println(msg);
    }
    /*
     * retorna los mensajes que entran por el socket
     */
    private String read() throws IOException{
        String response= br.readLine();
        return response;
       
    }
    /*
     * genera hash
     */
	private byte[] hasher(byte[] b, SecretKey k, String m) throws Exception {
		Mac foo = Mac.getInstance(m);
		foo.init(k);
		byte[] bytes = foo.doFinal(b);
		return bytes;
	}
    /*
     * Genera un certificado con el key dado y lo pasa a string
     */
    private String generateCertificate(KeyPair keyPair) throws Exception {
    	X509V1CertificateGenerator  gen = new X509V1CertificateGenerator();

    	Security.addProvider(new BouncyCastleProvider());
        gen.setNotBefore(new Date(System.currentTimeMillis()-40000000));
        gen.setNotAfter(new Date(System.currentTimeMillis() + 40000000));
        gen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        gen.setIssuerDN(new X500Principal("CN=idk"));
        gen.setSubjectDN(new X500Principal("CN=idk"));
        gen.setPublicKey(keyPair.getPublic());
        gen.setSignatureAlgorithm("MD5withRSA");
    	X509Certificate returner = gen.generateX509Certificate(keyPair.getPrivate());
    	byte [] byteArray=returner.getEncoded();	
    	String foo= DatatypeConverter.printHexBinary(byteArray);
    	
        return foo;
    }
    /*
     * Genera un certificado apartir de un string
     */
    private X509Certificate getCertificate(String certificate) throws CertificateException, IOException {
		
    	byte[] c= DatatypeConverter.parseHexBinary(certificate);
    	return new JcaX509CertificateConverter().getCertificate(new X509CertificateHolder(c));
    }
 
}