import java.awt.BorderLayout;
import java.awt.Desktop;
import java.awt.EventQueue;

import javax.crypto.Cipher;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.awt.event.ActionListener;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.awt.event.ActionEvent;

public class WBcECCED {
	public static String ALGORITHM = "EC";
	public static String CIPHER_ALGORITHM = "ECIESwithAES";
	public static String KEY_SPEC;
	public static KeyPair KEY_PAIR;

	private JFrame frmEccPerformanceTest;
	private JTextField txtFilesize;
	private JTextField txtEcc;
	private JTextField txtTimes;
	private JTextField txtElapse;
	private JLabel lblStatus;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					WBcECCED window = new WBcECCED();
					window.frmEccPerformanceTest.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the application.
	 */
	public WBcECCED() {
		initialize();
	}

	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {
		frmEccPerformanceTest = new JFrame();
		frmEccPerformanceTest.setTitle("ECC Performance Test");
		frmEccPerformanceTest.setBounds(100, 100, 450, 300);
		frmEccPerformanceTest.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		
		JPanel panel = new JPanel();
		frmEccPerformanceTest.getContentPane().add(panel, BorderLayout.CENTER);
		panel.setLayout(null);
		
		JLabel lblFilesize = new JLabel("Filesize");
		lblFilesize.setBounds(22, 32, 46, 15);
		panel.add(lblFilesize);
		
		txtFilesize = new JTextField();
		txtFilesize.setBounds(114, 29, 213, 21);
		panel.add(txtFilesize);
		txtFilesize.setColumns(10);
		
		JLabel lblBytes = new JLabel("Bytes");
		lblBytes.setBounds(358, 32, 46, 15);
		panel.add(lblBytes);
		
		JLabel lblEcc = new JLabel("ECC");
		lblEcc.setBounds(22, 78, 46, 15);
		panel.add(lblEcc);
		
		txtEcc = new JTextField();
		txtEcc.setBounds(114, 75, 213, 21);
		panel.add(txtEcc);
		txtEcc.setColumns(10);
		
		JLabel lblTimes = new JLabel("Times");
		lblTimes.setBounds(22, 128, 46, 15);
		panel.add(lblTimes);
		
		txtTimes = new JTextField();
		txtTimes.setBounds(114, 125, 213, 21);
		panel.add(txtTimes);
		txtTimes.setColumns(10);
		
		JButton btnExecute = new JButton("Execute");
		btnExecute.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				Thread execute = new Thread() {
					public void run() {
						try {
							lblStatus.setText("Running");
							int fileSize = Integer.parseInt(txtFilesize.getText());
							int times = Integer.parseInt(txtTimes.getText());
							KEY_SPEC = txtEcc.getText();
							
							byte[] original = new byte[fileSize];
							byte[] encrypt;
							byte[] decrypt;
							SecureRandom sr = new SecureRandom();
							
							sr.nextBytes(original);
							establishKeys(KEY_SPEC);
							
							PublicKey publicKey = KEY_PAIR.getPublic();
							PrivateKey privateKey = KEY_PAIR.getPrivate();
							
							long msbefore;
							long msafter;
							long enc_total = 0;
							long dec_total = 0;
							
							for (int i = 0; i < times; i++) {
								msbefore = getCurrentTime();
								encrypt = encrypt(publicKey, original);
								msafter = getCurrentTime();
								enc_total = enc_total + (msafter - msbefore);
								
								msbefore = getCurrentTime();
								decrypt = decrypt(privateKey, encrypt);
								msafter = getCurrentTime();
								dec_total = dec_total + (msafter - msbefore);
							}
							
							String result = "AVENC: " + (float)enc_total/times + " ms / AVDEC: " + (float)dec_total/times + " ms";
							txtElapse.setText(result);
							
							lblStatus.setText("Ready");
							
							
						} catch (Exception e) {
							e.printStackTrace();
						}
					}
				};
				execute.start();
			}
		});
		btnExecute.setBounds(337, 228, 87, 23);
		panel.add(btnExecute);
		
		JLabel lblElapse = new JLabel("Elapse");
		lblElapse.setBounds(22, 176, 46, 15);
		panel.add(lblElapse);
		
		txtElapse = new JTextField();
		txtElapse.setBounds(114, 173, 213, 21);
		panel.add(txtElapse);
		txtElapse.setColumns(10);
		
		lblStatus = new JLabel("Ready");
		lblStatus.setBounds(22, 232, 46, 15);
		panel.add(lblStatus);
		
		JButton btnCurve = new JButton("Curves..");
		btnCurve.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				try {
					Desktop.getDesktop().browse(new URL(("http://www.bouncycastle.org/wiki/pages/viewpage.action?pageId=362269")).toURI());
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
		btnCurve.setBounds(337, 74, 87, 23);
		panel.add(btnCurve);
	}
	public JTextField getTxtFilesize() {
		return txtFilesize;
	}
	public JTextField getTxtEcc() {
		return txtEcc;
	}
	public JTextField getTxtTimes() {
		return txtTimes;
	}
	public JTextField getTxtElapse() {
		return txtElapse;
	}
	public JLabel getLblStatus() {
		return lblStatus;
	}
	
	public void establishKeys(String keySpec) throws Exception{
		Security.addProvider(new BouncyCastleProvider());
		KeyPairGenerator ecKeyGen = KeyPairGenerator.getInstance(ALGORITHM);
		ecKeyGen.initialize(new ECGenParameterSpec(KEY_SPEC));
		KEY_PAIR = ecKeyGen.generateKeyPair();
	}
	
	public long getCurrentTime() {
		Date today = new Date();
		return today.getTime();
	}
	
	public byte[] encrypt(PublicKey publicKey, byte[] data) throws Exception{
		byte[] result;
		Cipher iesCipher = Cipher.getInstance(CIPHER_ALGORITHM);
		iesCipher.init(Cipher.ENCRYPT_MODE, publicKey);;
		result = iesCipher.doFinal(data);
		return result;
	}
	
	public byte[] decrypt(PrivateKey privateKey, byte[] data) throws Exception{
		byte[] result;
		Cipher iesCipher = Cipher.getInstance(CIPHER_ALGORITHM);
		iesCipher.init(Cipher.DECRYPT_MODE, privateKey);
		result = iesCipher.doFinal(data);
		return result;
	}
}
