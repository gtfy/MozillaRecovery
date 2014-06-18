package delegate;

import javax.swing.JEditorPane;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JTextArea;

public class AboutFrame extends JFrame {

	private static final long serialVersionUID = 1L;
	private static final String text = "<html><body><h2>MozillaRecovery</h2><h3>Version: 0.5a</h3>"
			+ "<strong>Author:</strong><br/>Katja Hahn<br/>"
			+ "<strong>Author:</strong><br/> <bold>like2code</bold>@evilzone.org<br/>"
			+ "<strong>Last update:</strong><br/> 18. June 2014"
			+ "</body></html>";

	public AboutFrame() {
		initGUI();
	}

	private void initGUI() {
		this.setSize(200, 250);
		this.setResizable(false);
		this.setVisible(true);
		this.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);

		JEditorPane area = new JEditorPane("text/html", text);
		area.setEditable(false);
		//area.setLineWrap(true);
		//area.setWrapStyleWord(true);
		//area.setEditable(false);
		this.add(area);
	}
}
