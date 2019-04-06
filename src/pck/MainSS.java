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
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Random;

import javax.crypto.SecretKey;
import javax.security.auth.x500.X500Principal;
import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V1CertificateGenerator;

import java.security.KeyPair;

 
@SuppressWarnings({ "unused", "deprecation" })
public class MainSS {
   /*
    * Constantes
    */
    public final static String HOST ="localhost";
    public final static int PORT = 4004;
	public static final String AES = "AES";
	public static final String Blowfish = "Blowfish";
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
   
    public static void main(String[] args) {
        MainSS mainSS = new MainSS();
       
        mainSS.conectar();
    }
 
    private void conectar() {
    	byte[] b = new byte[128];
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
            
            
            
            
            //se envia y recibe el arreglo de bytes
           output = DatatypeConverter.printHexBinary(b);
           System.out.println("Cliente:"+ output);
           send(output);
           input=read();
           System.out.println("Servidor:"+input );
           
           //Se envia OK
           output = OK;
           
           send(output);
           System.out.println("Cliente:"+ output);
          
           
           //Envio de datos
           BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
           System.out.println("Envie datos(EJ:15;41 24.2028,2 10.4418):"); 
           output = stdIn.readLine();
           
           send(output);
           
           System.out.println("Cliente:"+ output);
           send(output);
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
   
    private void send(String msg){
       pw.println(msg);
    }
    private String read() throws IOException{
        String response= br.readLine();
        return response;
       
    }
    
    private String generateCertificate(KeyPair keyPair) throws Exception {
    	X509V1CertificateGenerator  gen = new X509V1CertificateGenerator();

    	Security.addProvider(new BouncyCastleProvider());
        gen.setNotBefore(new Date(System.currentTimeMillis()-1));
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
 
 
}