package core.view;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.InputStream;
import java.io.OutputStream;

import core.model.NetworkModel;

public class ServerListener implements ActionListener {

	private NetworkModel network;
	private String server;
	private OutputStream out;
	private InputStream in;

	public ServerListener(String server, NetworkModel network, OutputStream out, InputStream in) {
		this.server = server;
		this.network = network;
		this.out = out;
		this.in = in;
	}

	public void actionPerformed(ActionEvent e) {
		String action = e.getActionCommand();
		if (action.equals("Audit"))
			network.auditNonBlock(server, out, in, false);
		else if (action.equals("Dry Run"))
			network.dryrunNonBlock(server, out, in);
		else if (action.equals("Config"))
			network.configNonBlock(server, out, in);
		else if (action.equals("Build ISO"))
			network.genIsoServer(server, "./");
 	}

}
