package delegate;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Label;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.WindowAdapter;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.ConcurrentModificationException;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;

import javax.crypto.NoSuchPaddingException;
import javax.imageio.ImageIO;
import javax.swing.AbstractButton;
import javax.swing.ButtonGroup;
import javax.swing.ButtonModel;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.border.EmptyBorder;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import model.Application;
import model.DefaultKey3Location;
import model.Key3DBParseException;

import org.apache.log4j.Logger;
import org.apache.log4j.chainsaw.Main;

import worker.BruteForceWorker;
import worker.ProcessWorker;
import worker.TestPasswordWorker;
import worker.WordListWorker;

public class MainFrame extends JFrame implements ProgressDisplay, ItemListener {

	private static final long serialVersionUID = 1L;
	private final static Logger logger = Logger.getLogger(MainFrame.class);
	
	private final static int QUEUE_WORDS_PER_WORKER = 100000;
	// only used for bruteforcing
	private final static int MAX_WORDLENGTH = 12;
	private final static File DEFAULT_WORDLIST = new File("wordlist.txt");
	private final static String TITLE_IMAGE = "/title.gif";

	// GUI elements
	private final JTextField key3Path = new JTextField(25);
	private final JLabel parameterDescr = new JLabel("Chars");
	private final JTextField parameter = new JTextField("abcdefghijklmnopqrstuvwxyz1234567890");
	private final JPanel paramAddPanel = new JPanel();
	private final JCheckBox useShell = new JCheckBox("use shell");
	private final JComboBox<String> wordLen = new JComboBox<String>(); 	
	private final JTextField wordlistPath = new JTextField(25);
	private final JComboBox<String> threads = new JComboBox<String>();
	private final JButton key3PathButton = new JButton("...");
	private final JButton wordlistPathButton = new JButton("...");
	private final JButton recoverButton = new JButton("recover password");
	private final JButton cancel = new JButton("cancel");
	private final JTextField output = new JTextField(
			"If checkbox is set or no wordlist given, a bruteforce attack up to"
					+ " wordlength " + MAX_WORDLENGTH
					+ " will be tried.", JLabel.CENTER);
	private BufferedImage titleImg;
	private JLabel titleLabel;
	private final ButtonGroup btnGroup = new ButtonGroup();
	private final JCheckBox doBruteforce = new JCheckBox("bruteforce");
	private final JCheckBox doWordlist = new JCheckBox("wordlist");
	private final JCheckBox doProccess = new JCheckBox("proccess");

	// stuff 
	private final List<TestPasswordWorker> workers = new ArrayList<TestPasswordWorker>();
	private final List<Thread> producers = new ArrayList<Thread>();
	private int maxWordQueue = 1000000;
	private final ArrayBlockingQueue<byte[]> wordQueue = new ArrayBlockingQueue<byte[]>(maxWordQueue);
	private long startCrackTime;
	private long tries;
	private boolean working = false;
	private String lastCommand = "echo your_command";
	private String lastChars = "abcdefghijklmnopqrstuvwxyz1234568790";

	// TODO need more ?
	private final String shells[][] = new String[][]{
			new String[]{"sh", "-c", ""},	// every unix ?
			new String[]{"cmd", "/C", ""}	// every (relevant) windows ?
	};
	private String shell[];
	
	
	public MainFrame() {
		super("MozillaRecovery 0.5a");
		
		tries = 0;
		startCrackTime = System.currentTimeMillis();
		
		String os = System.getProperty("os.name").toLowerCase();
		if(os.indexOf("win") >= 0){
			shell = shells[1];
		}else{
			// fall back to /bin/sh
			shell = shells[0];
		}
		initGUI();
		initListener();
	}

	
	protected void enableButtons(boolean b) {
		if(b){
			enableSpecific();
		}else{
			wordlistPath.setEnabled(b);
			wordlistPathButton.setEnabled(b);
			parameter.setEnabled(b);
			useShell.setEnabled(b);
			wordLen.setEnabled(b);
		}
		recoverButton.setEnabled(b);
		key3PathButton.setEnabled(b);
		key3Path.setEnabled(b);
		threads.setEnabled(b);
		doBruteforce.setEnabled(b);
		doWordlist.setEnabled(b);
		doProccess.setEnabled(b);
		cancel.setEnabled(!b);
	}
	
	private void shutdownWorkerThreads(boolean force){
		for (TestPasswordWorker thread : workers) {
			thread.shutdownWhenEmpty();
			if(force) thread.interrupt();
		}
	}
	private void shutdownProducerThreads(boolean wait){
		for (Thread thread : producers) {
			thread.interrupt();
			if(wait){
				try {
					thread.join();
				} catch (InterruptedException e) {
					// if someone else killed it, thats fine, too
				}
			}
		}
	}
	private synchronized void stopAllThreads(boolean wait){
		working = false;
		shutdownProducerThreads(false);
		wordQueue.clear();
		shutdownWorkerThreads(true);
		if(! wait) return;
		for (Thread producer : producers) {
			try {producer.join();}
			catch (InterruptedException e) {}
		}
		for (Thread worker : workers) {
			try {worker.join();}
			catch (InterruptedException e) {}
		}		
	}
	
	private synchronized void recoverPasswords(){
		if( ! new File(key3Path.getText()).exists() ){ // TODO check here i readable ?
			output.setText("The key3db path is wrong.");
			return;
		}
		//stopAllThreads(true); // just to be sure, we left no man behind
		wordQueue.clear();
		working = true;
		int threadCount = threads.getSelectedIndex()+1;
		
		try {
			for (int i = 0; i < threadCount; i++) {
				TestPasswordWorker worker;
					worker = new TestPasswordWorker(key3Path.getText(), wordQueue, this);
				workers.add(worker);
				worker.start();
			}
		} catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException  e) {
			output.setText("Crypto exception: ." + e.getMessage());
			// TODO log ?
			return;
		} catch (IOException e) {
			output.setText("Problems reading the key3.db file: " + e.getMessage());
			// TODO log ?
			return;
		} catch (Key3DBParseException e) {
			output.setText("Problems parsing the key3.db file: " + e.getMessage());
			// TODO log ?
			return;
		}
		
		maxWordQueue = workers.size() * QUEUE_WORDS_PER_WORKER;
		tries = 0;
		startCrackTime = System.currentTimeMillis();
		
		String cmd = btnGroup.getSelection().getActionCommand();
		Thread producer;
		switch(cmd){
		
			case "bruteforce":
				System.out.println("do bruteforce");
				if(parameter.getText().length() < 1){
					output.setText("You need to specify which chars to use.");
					return;
				}
				lastChars = parameter.getText();
				producer = new BruteForceWorker(parameter.getText().toCharArray(), wordLen.getSelectedIndex()+1, this, wordQueue);
				output.setText("Starting bruteforce attack.");
				break;
				
			case "wordlist":
				if( ! new File(wordlistPath.getText()).isFile()){
					output.setText("The choosen wordlist is no file or not readable.");
					return;
				}
				try {
					producer = new WordListWorker(wordlistPath.getText(), this, wordQueue);
				} catch (IOException e) {
					output.setText("Problems loading wordlist: " + e.getMessage());
					return;
				}
				output.setText("Starting wordlist attack.");
				break;
				
			case "process":
				try {
					lastCommand = parameter.getText();
					Process proc;
					if(useShell.isSelected()){
						shell[2] = parameter.getText();
						proc = Runtime.getRuntime().exec(shell);
					}else{
						proc = Runtime.getRuntime().exec(parameter.getText());
					}
					producer = new ProcessWorker(proc, this, wordQueue);
				} catch (IOException e) {
					output.setText("Problems executing subprocess: " + e.getMessage());
					return;
				}
				output.setText("Starting subprocess wordlist attack.");
				break;
				
			default:
				return; // should never happen, but who knows
		}
		producers.add(producer);
		producer.start();
		enableButtons(false);
	}

	private String getFileNameFromUser() {
		File userdir = new File(System.getProperty("user.dir"));
		JFileChooser fc = new JFileChooser(userdir);
		int state = fc.showOpenDialog(null);
		if (state == JFileChooser.APPROVE_OPTION) {
			File file = fc.getSelectedFile();
			return file.getAbsolutePath();
		}
		return null;
	}

	private void initGUI() {
		// set shutdown hook
		// not really the correct place TODO think about where is
		final MainFrame tmp = this; 
		addWindowListener(new WindowAdapter() {
			public void windowClosing(java.awt.event.WindowEvent e) {
				logger.info("Closing frame.");
				tmp.shutdownProducerThreads(false);
				tmp.shutdownWorkerThreads(true);
				// TODO: join the threads ? (stopAllThreads(true) could lead to deadlock)
			};
		});
		
		setSize(650, 300);
		setLocationRelativeTo(null);
		setVisible(true);
		setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
		setResizable(false);
		enableButtons(true);	
		
		JPanel selectPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
		btnGroup.add(doBruteforce); selectPanel.add(doBruteforce); doBruteforce.setActionCommand("bruteforce");
		btnGroup.add(doWordlist); selectPanel.add(doWordlist); doWordlist.setActionCommand("wordlist");
		btnGroup.add(doProccess); selectPanel.add(doProccess); doProccess.setActionCommand("process");
		doBruteforce.setSelected(true);
		parameter.setText(lastChars);
		enableSpecific();
		
		paramAddPanel.setMinimumSize(new Dimension(130, 30));
		paramAddPanel.setPreferredSize(new Dimension(130, 30));
		
		for (int i = 1; i <= MAX_WORDLENGTH; i++) {			
			wordLen.addItem(""+i);
		}
		wordLen.setSelectedIndex((7 < MAX_WORDLENGTH) ? 7 : MAX_WORDLENGTH-1);
		
		output.setEditable(false);
		output.setBackground(null);
		output.setBorder(new EmptyBorder(10, 5, 10, 5) );
		output.setHorizontalAlignment(JTextField.CENTER);
		
		DefaultKey3Location loc = new DefaultKey3Location();
		String path = loc.findLocation(Application.FIREFOX);
		if (path == null) {
			path = loc.findLocation(Application.THUNDERBIRD);
		}
		key3Path.setText(path == null ? "" : path);
		
		if (DEFAULT_WORDLIST.exists()) {
			wordlistPath.setText(DEFAULT_WORDLIST.getAbsolutePath());
		}

		try {
			titleImg = ImageIO.read(getClass().getResource(TITLE_IMAGE));
			titleLabel = new JLabel(new ImageIcon(titleImg));
			this.add(titleLabel, BorderLayout.PAGE_START);
		} catch (IOException e) {
			e.printStackTrace();
			logger.error(e.getMessage());
		}

		for(int i = 1; i <= Runtime.getRuntime().availableProcessors(); ++i){
			threads.addItem(""+i);
		}
		threads.setSelectedIndex(threads.getItemCount()-1);
		
		JPanel panel = new JPanel();
		panel.setLayout(new GridBagLayout());
		
		GridBagConstraints c = new GridBagConstraints();
		c.fill = GridBagConstraints.HORIZONTAL;
		c.insets = new Insets(2, 3, 2, 3);
		
		c.gridx = 0;
		c.gridy = 0;
		c.gridwidth = 1;
		c.weightx = 1;
		c.weighty = 1;
		panel.add(new Label("key3.db:"), c);

		c.gridx = 1;
		c.weightx = 5;
		panel.add(key3Path, c);
		
		c.gridx = 2;
		c.weightx = 1;
		panel.add(key3PathButton, c);

		c.gridx = 0;
		c.gridy = 1;
		panel.add(new Label("Type:"), c);
		
		c.gridx = 1;
		c.gridwidth = 2;
		panel.add(selectPanel, c);
		
		c.gridx = 0;
		c.gridy = 2;
		c.gridwidth = 1;
		panel.add(new Label("Wordlist:"), c);

		c.gridx = 1;
		panel.add(wordlistPath, c);

		c.gridx = 2;
		panel.add(wordlistPathButton, c);

		c.gridx = 0;
		c.gridy = 3;
		panel.add(parameterDescr, c);
		
		c.gridx = 1;
		c.gridy = 3;
		panel.add(parameter, c);
		
		c.gridx = 2;
		panel.add(paramAddPanel, c);
		
		c.gridx = 0;
		c.gridy = 4;
		panel.add(new JLabel("Threads"), c);
		
		c.gridx = 1;
		c.gridy = 4;
		panel.add(threads, c);
		
		c.gridx = 1;
		c.gridy = 5;
		panel.add(recoverButton, c);

		c.gridx = 2;
		c.gridy = 5;
		panel.add(cancel, c);

		this.add(panel, BorderLayout.CENTER);
		this.add(output, BorderLayout.SOUTH);
		this.revalidate();
	}

	private void initListener() {
		wordlistPathButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent arg0) {
				String path = getFileNameFromUser();
				if (path != null) {
					wordlistPath.setText(path);
				}
			}

		});

		key3PathButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent arg0) {
				String path = getFileNameFromUser();
				if (path != null) {
					key3Path.setText(path);
				}
			}

		});

		recoverButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				recoverPasswords();
			}
		});

		cancel.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent arg0) {
				stopAllThreads(false);
			}
		});

		titleLabel.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent arg0) {
				AboutFrame frame = new AboutFrame();
				frame.setLocationRelativeTo(MainFrame.this);
			}
		});
		
		doBruteforce.addItemListener(this);
		doProccess.addItemListener(this);
		doWordlist.addItemListener(this);
	}
	@Override
	public void itemStateChanged(ItemEvent arg) {
		if(arg.getStateChange() != ItemEvent.SELECTED)
			return;
		enableSpecific();
	}
	private void enableSpecific(){	// TODO rename this shit
		if(btnGroup.getSelection() == null)
			return;
		switch(btnGroup.getSelection().getActionCommand()){
			case "bruteforce":
				parameterDescr.setText("Chars");
				paramAddPanel.removeAll();
				paramAddPanel.add(new JLabel("length")); // not really nice to recreate it over and over, but meh
				paramAddPanel.add(wordLen);
				paramAddPanel.revalidate();
				paramAddPanel.repaint();
				wordLen.setEnabled(true);
				if(!parameter.getText().equals(lastChars))
					lastCommand = parameter.getText(); 
				parameter.setText(lastChars);
				wordlistPath.setEnabled(false);
				wordlistPathButton.setEnabled(false);
				parameter.setEnabled(true);
				break;
			case "wordlist":
				paramAddPanel.removeAll();
				paramAddPanel.repaint();
				wordlistPath.setEnabled(true);
				wordlistPathButton.setEnabled(true);
				parameter.setEnabled(false);
				break;
			case "process":
				parameterDescr.setText("Command");
				paramAddPanel.removeAll();
				paramAddPanel.add(useShell);
				useShell.setEnabled(true);
				paramAddPanel.revalidate();
				paramAddPanel.repaint();
				if(!parameter.getText().equals(lastCommand))
					lastChars = parameter.getText();
				parameter.setText(lastCommand);
				wordlistPath.setEnabled(false);
				wordlistPathButton.setEnabled(false);
				parameter.setEnabled(true);
				break;
		}
	}


	@Override
	public synchronized void setResult(String password) {
		if(password.length() == 0){
			output.setText("No master password set");
			logger.info("No master password set");
		}else{			
			long tps = (long) (tries / ((System.currentTimeMillis()-startCrackTime)/1000.0));
			output.setText("Found password: '" + password + "' Passwords tried: " + tries + " (" + tps + "/s).");
			logger.info("Found password: '" + password + "'");
		}
		stopAllThreads(false);
	}

	@Override
	public synchronized void addProgress(int size, String lastWord) {
		if(workers.size() == 0) return;
		tries += size;
		long tps = (long) (tries / ((System.currentTimeMillis()-startCrackTime)/1000.0));
		output.setText("Passwords tried: " + tries + " (" + tps + "/s). Current word: " + lastWord);
	}

	@Override
	public synchronized void workerDone(TestPasswordWorker worker) {
		logger.info("Worker " + worker.getName() + " done.");
		workers.remove(worker);
		if(workers.size() == 0){
			if(working){
				output.setText("Could not find password. Passwords tried: " + tries);
				logger.info("Could not find password.");
				working = false;
			}
		}
		if(producers.size()+workers.size() == 0) enableButtons(true);
	}

	@Override
	public synchronized void producerDone(Thread producer) {
		logger.info("Producer " + producer.getName() + " done.");
		producers.remove(producer);
		if(producers.size() == 0)
			shutdownWorkerThreads(false);	
		if(producers.size()+workers.size() == 0) enableButtons(true);
	}

}
