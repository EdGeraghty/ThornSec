package profile;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Set;
import java.util.Vector;

import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.swing.JOptionPane;

import core.data.InterfaceData;
import core.iface.IUnit;
import core.model.DeviceModel;
import core.model.FirewallModel;
import core.model.InterfaceModel;
import core.model.MachineModel;
import core.model.NetworkModel;
import core.model.ServerModel;
import core.profile.AStructuredProfile;
import core.unit.fs.FileOwnUnit;
import core.unit.fs.FilePermsUnit;
import core.unit.fs.FileUnit;
import core.unit.pkg.InstalledUnit;

public class Router extends AStructuredProfile {

	private DNS  dns;
	private DHCP dhcp;
	private QoS  qos;
	
	private FirewallModel firewall;
	
	private Vector<String> userIfaces;
	private Vector<String> wanIfaces;
	
	private HashMap<String, InetAddress[]> resolved;
	
	private String domain;
	
	private boolean isPPP;
	private boolean isStatic;

	public Router(ServerModel me, NetworkModel networkModel) {
		super("router", me, networkModel);
		
		this.dns  = new DNS(me, networkModel);
		this.dhcp = new DHCP(me, networkModel);
		this.qos  = new QoS(me, networkModel);
		
		//:2+ is a wildcard for VPN traffic interfaces
		this.userIfaces = new Vector<String>();
		this.userIfaces.addElement(":2+");

		this.wanIfaces = new Vector<String>();
		
		this.isPPP    = false;
		this.isStatic = false;
		
		this.resolved = new HashMap<String, InetAddress[]>();
	}

	public DHCP getDHCP() {
		return this.dhcp;
	}
	
	public DNS getDNS() {
		return this.dns;
	}
	
	public Vector<IUnit> getPersistentConfig() {
		Vector<IUnit> units = new Vector<IUnit>();

		String sysctl = "";
		sysctl += "net.ipv4.ip_forward=1\n";
		sysctl += "net.ipv6.conf.all.disable_ipv6=1\n";
		sysctl += "net.ipv6.conf.default.disable_ipv6=1\n";
		sysctl += "net.ipv6.conf.lo.disable_ipv6=1";

		units.addElement(((ServerModel)me).getConfigsModel().addConfigFile("sysctl", "proceed", sysctl, "/etc/sysctl.conf"));
		
		units.addAll(this.dhcp.getPersistentConfig());
		units.addAll(this.dns.getPersistentConfig());
		units.addAll(this.qos.getPersistentConfig());
		
		units.addAll(routerScript());
		
		return units;
	}

	protected Vector<IUnit> getInstalled() {
		Vector<IUnit> units = new Vector<IUnit>();
		
		//units.addElement(new InstalledUnit("xsltproc", "xsltproc"));
		units.addElement(new InstalledUnit("traceroute", "traceroute"));
		units.addElement(new InstalledUnit("speedtest_cli", "speedtest-cli"));
		
		units.addAll(this.dns.getInstalled());
		units.addAll(this.dhcp.getInstalled());
		units.addAll(this.qos.getInstalled());

		return units;
	}
	
	protected Vector<IUnit> getLiveConfig() {
		Vector<IUnit> units = new Vector<IUnit>();
		
		units.addAll(this.dhcp.getLiveConfig());
		units.addAll(this.dns.getLiveConfig());
		units.addAll(this.qos.getLiveConfig());

		units.addAll(dailyBandwidthEmailDigestUnits());

		return units;
	}
	
	private InetAddress[] hostToInetAddress(String uri) {
		InetAddress[] destination = null;
		
		if (this.resolved.containsKey(uri)) {
			destination = this.resolved.get(uri);
		}
		else {
			destination = networkModel.stringToAllIPs(uri);
			
			this.resolved.put(uri, destination);
		}
		
		return destination;
	}
	
	private Vector<IUnit> machineIngressRules(MachineModel machine) {
		Vector<IUnit> units = new Vector<IUnit>();
		
		HashMap<String, Set<Integer>> ingress = machine.getRequiredIngress();

		for (String uri : ingress.keySet()) {
			InetAddress[] destinations = hostToInetAddress(uri);
			Integer cidr = machine.getCIDR(uri);
			
			String setName = networkModel.getIPSet().getSetName(name);
			
			networkModel.getIPSet().addToSet(setName, cidr, new Vector<InetAddress>(Arrays.asList(destinations)));
			
			String rule = "";
			rule += "-p tcp";
			rule += (ingress.get(uri).isEmpty() || ingress.get(uri).contains(0)) ? "" : " -m multiport --dports " + collection2String(ingress.get(uri));
			rule += (uri.equals("255.255.255.255")) ? "" : " -m set --match-set " + setName + " src";
			rule += " -j ACCEPT";
			
			this.firewall.addFilter(
					machine.getHostname() + "_" + setName + "_ingress",
					machine.getIngressChain(),
					rule,
					"Allow call in to " + uri
			);
		}

		return units;
	}
	
	private Vector<IUnit> machineEgressRules(MachineModel machine) {
		Vector<IUnit> units = new Vector<IUnit>();

		HashMap<String, HashMap<Integer, Set<Integer>>> egress = machine.getRequiredEgress();

		for (String uri : egress.keySet()) {
			InetAddress[] destinations = hostToInetAddress(uri);
			
			String setName = networkModel.getIPSet().getSetName(uri);
			
			networkModel.getIPSet().addToSet(setName, machine.getCIDR(uri), new Vector<InetAddress>(Arrays.asList(destinations)));
			
			String rule = "";
			rule += "-p tcp";
			rule += (egress.get(uri).values().isEmpty() || collection2String(egress.get(uri).values()).equals("0")) ? "" : " -m multiport --dports " + collection2String(egress.get(uri).values());
			rule += (uri.equals("255.255.255.255")) ? "" : " -m set --match-set " + setName + " dst";
			rule += " -j ACCEPT";
			
			this.firewall.addFilter(
					machine.getHostname() + "_" + setName + "_egress",
					machine.getEgressChain(),
					rule,
					"Allow call out to " + uri
			);
		}

		return units;
	}
	
	private Vector<IUnit> serverForwardRules(ServerModel server) {
		Vector<IUnit> units = new Vector<IUnit>();
		
		HashMap<String, Set<Integer>> forward = server.getRequiredForward();

		for (String destination : forward.keySet()) {
			MachineModel destinationMachine = networkModel.getMachineModel(destination);
			
			String request = "";
			request += "-p tcp";
			request += " -m tcp";
			request += " -m multiport";
			request += " --sports " + collection2String(forward.get(destination));
			request += " -s " + collection2String(destinationMachine.getAddresses());
			request += " -d " + collection2String(server.getAddresses());
			request += " -j ACCEPT";

			String reply = "";
			reply += "-p tcp";
			reply += " -m tcp";
			reply += " -m multiport";
			reply += " --dports " + collection2String(forward.get(destination));
			reply += " -d " + collection2String(destinationMachine.getAddresses());
			reply += " -s " + collection2String(server.getAddresses());
			reply += " -j ACCEPT";
			
			this.firewall.addFilter(
					server.getHostname() + "_" + destinationMachine.getHostname() + "_forward",
					server.getForwardChain(),
					request,
					"Allow traffic from " + destination
			);
			this.firewall.addFilter(
					destinationMachine.getHostname() + "_" + server.getHostname() + "_forward",
					destinationMachine.getForwardChain(),
					request,
					"Allow traffic to " + destination
			);
			this.firewall.addFilter(
					server.getHostname() + "_" + destinationMachine.getHostname() + "_forward",
					server.getForwardChain(),
					reply,
					"Allow traffic from " + destination
			);
			this.firewall.addFilter(
					destinationMachine.getHostname() + "_" + server.getHostname() + "_forward",
					destinationMachine.getForwardChain(),
					reply,
					"Allow traffic to " + destination
			);
		}

		return units;
	}

	private Vector<IUnit> machineDnatRules(MachineModel machine) {
		Vector<IUnit> units = new Vector<IUnit>();

		HashMap<String, Set<Integer>> dnat = machine.getRequiredDnat();

		//Only create these rules if we actually *have* users.
		if (!networkModel.getIPSet().isEmpty("user")) {
			for (String destinationName : dnat.keySet()) {
				MachineModel destinationMachine = networkModel.getMachineModel(destinationName);
				
				String rule = "";
				rule += "-p tcp";
				rule += " -m tcp";
				rule += " -m multiport";
				rule += " --dports " + collection2String(dnat.get(destinationName));
				rule += " ! -s " + collection2String(machine.getAddresses());
				rule += " -d " + collection2String(destinationMachine.getAddresses());
				rule += " -j DNAT";
				rule += " --to-destination " + collection2String(machine.getAddresses());
				
				this.firewall.addNatPrerouting(
						machine.getHostname() + "_" + destinationMachine.getHostname() + "_dnat",
						rule,
						"DNAT traffic for " + destinationName + " to " + machine.getHostname()
				);
			}
		}
		
		//If we've given it an external IP, it's listening, and a request comes in from the outside world, let it have it!
		if (networkModel.getData().getExternalIp(machine.getLabel()) != null && !machine.getRequiredListenTCP().isEmpty()) {
			String rule = "";
			rule += "-i " + collection2String(me.getNetworkData().getWanIfaces(getLabel()));
			rule += (this.isStatic) ? " -d " + networkModel.getData().getExternalIp(machine.getLabel()).getHostAddress() : "";
			rule += " -p tcp";
			rule += " -m multiport";
			rule += " --dports " + collection2String(machine.getRequiredListenTCP());
			rule += " -j DNAT";
			rule += " --to-destination " + collection2String(machine.getAddresses());
			
			this.firewall.addNatPrerouting(
					machine.getHostname() + "_external_ip_dnat",
					rule,
					"DNAT external traffic on " + networkModel.getData().getExternalIp(machine.getLabel()).getHostAddress() + " to " + machine.getHostname() + " if it has an external IP & is listening"
			);
		}

		return units;
	}

	private Vector<IUnit> machineAllowUserForwardRules(MachineModel machine) {
		Vector<IUnit> units = new Vector<IUnit>();

		Vector<Integer> listen = machine.getRequiredListenTCP();
		String machineName = machine.getLabel();
		
		//Only create these rules if we actually *have* users.
		if (networkModel.getIPSet().isEmpty("user")) { return units; }
		
		if (machine instanceof ServerModel && listen.size() > 0) {
			String rule = "";
			rule += "-p tcp";
			rule += " -m multiport";
			rule += " --dports " + collection2String(listen);
			rule += " -m set";
			rule += " --match-set user src";
			rule += " -j ACCEPT";
	
			this.firewall.addFilter(
					machineName + "_users_forward",
					machine.getForwardChain(),
					rule,
					"Allow traffic from users"
			);
		}
		else if (machine instanceof DeviceModel && networkModel.getInternalOnlyDevices().contains(machine)) {
			//First, iterate through everything which should be listening for everyone
			String listenRule = "";
			listenRule += "-p tcp";
			listenRule += (!listen.isEmpty()) ? " -m multiport --dports " + collection2String(listen) : "";
			listenRule += " -m set";
			listenRule += " --match-set user src";
			listenRule += " -j ACCEPT";
	
			this.firewall.addFilter(
					machineName + "_users_forward",
					machine.getForwardChain(),
					listenRule,
					"Allow traffic from users"
			);

			//These are management ports
			Set<Integer> ports = ((DeviceModel) machine).getManagementPorts();
			
			if (ports != null && !ports.isEmpty()) {
				String managementRule = "";
				managementRule += "-p tcp";
				managementRule += " -m multiport --dports " + collection2String(ports);
				managementRule += " -m set";
				managementRule += " --match-set " + machineName + "_admins src";
				managementRule += " -j ACCEPT";
		
				this.firewall.addFilter(
						machineName + "_admins_management_forward",
						machine.getForwardChain(),
						managementRule,
						"Allow management traffic from admins"
				);
			}
		}
		
		return units;
	}

	private Vector<IUnit> machineIngressEgressForwardRules(MachineModel machine) {
		Vector<IUnit> units = new Vector<IUnit>();

		String wanIfaces = collection2String(networkModel.getData().getWanIfaces(me.getLabel()));
		
		String ingressRule = "";
		ingressRule += "-i " + wanIfaces;
		ingressRule += " -j " + machine.getIngressChain();

		String egressRule = "";
		egressRule += "-o " + wanIfaces;
		egressRule += " -j " + machine.getEgressChain();

		this.firewall.addFilter(
				machine.getHostname() + "_jump_on_ingress",
				machine.getForwardChain(),
				ingressRule,
				"Jump to our ingress chain for incoming (external) traffic"
		);

		this.firewall.addFilter(
				machine.getHostname() + "_jump_on_egress",
				machine.getForwardChain(),
				egressRule,
				"Jump to our egress chain for outgoing (external) traffic"
		);
		
		return units;
	}

	private Vector<IUnit> userAllowServerForwardRules(DeviceModel user) {
		Vector<IUnit> units = new Vector<IUnit>();

		if (!networkModel.getAllServers().isEmpty()) {
			String rule = "";
			rule += "-m set";
			rule += " --match-set servers dst";
			rule += " -j ACCEPT";
	
			this.firewall.addFilter(
					user.getHostname() + "_servers_forward",
					user.getForwardChain(),
					rule,
					"Allow traffic to servers"
			);
		}
		
		return units;
	}

	private Vector<IUnit> userAllowInternalOnlyForwardRules(DeviceModel user) {
		Vector<IUnit> units = new Vector<IUnit>();

		if (!networkModel.getInternalOnlyDevices().isEmpty()) {
			String rule = "";
			rule += "-m set";
			rule += " --match-set internalonly dst";
			rule += " -j ACCEPT";
	
			this.firewall.addFilter(
					user.getHostname() + "_internalonly_forward",
					user.getForwardChain(),
					rule,
					"Allow traffic to internal-only devices"
			);
		}
		
		return units;
	}
	
	private Vector<IUnit> serverAdminRules(MachineModel machine) {
		Vector<IUnit> units = new Vector<IUnit>();

		String machineName = machine.getLabel();
		
		//We need to check there's anything in the set, first
		if (networkModel.getIPSet().isEmpty(machineName + "_admins")) {
			if (((ServerModel)machine).isRouter() && ((ServerModel)machine).isMetal()) {
				String rule = "";
				rule += "-p tcp";
				rule += " --dport " + networkModel.getData().getSSHPort(machineName);
				rule += " -j ACCEPT";
		
				this.firewall.addFilter(
						machine.getHostname() + "_allow_admin_ssh",
						machine.getForwardChain(),
						rule,
						"Allow SSH from admins"
				);
			}
			else {
				//Hmm. Should probably throw something here
			}
		}
		else {
			String rule = "";
			rule += "-p tcp";
			rule += " --dport " + networkModel.getData().getSSHPort(machineName);
			rule += " -m set";
			rule += " --match-set " + machineName + "_admins src";
			rule += " -j ACCEPT";
	
			this.firewall.addFilter(
					machine.getHostname() + "_allow_admin_ssh",
					machine.getForwardChain(),
					rule,
					"Allow SSH from admins"
			);
		}
		
		return units;
	}

	private Vector<IUnit> networkIptUnits() {
		Vector<IUnit> units = new Vector<IUnit>();
		
		for (ServerModel server : networkModel.getAllServers()) {
			machineIngressRules(server);
			machineEgressRules(server);
			serverForwardRules(server);
			machineDnatRules(server);
			machineAllowUserForwardRules(server);
			serverAdminRules(server);
		}
		
		for (DeviceModel device : networkModel.getUserDevices()) {
			
			if (device.getSubnets().isEmpty()) { continue; } //Unless they don't have any interfaces

			//No need for further ingress rules here
			machineDnatRules(device);
			machineAllowUserForwardRules(device);
			userAllowServerForwardRules(device);
			userAllowInternalOnlyForwardRules(device);
			machineEgressRules(device);
		}
		
		for (DeviceModel device : networkModel.getInternalOnlyDevices()) {
			//No need for ingress or egress rules here, they only listen on fwd
			machineDnatRules(device); //May be behind a load balancer
			machineAllowUserForwardRules(device);
		}

		for (DeviceModel device : networkModel.getExternalOnlyDevices()) {
			//No need for forward or ingress rules here
			machineDnatRules(device); //May be behind a load balancer
			machineAllowUserForwardRules(device);
			machineEgressRules(device);
		}
		
		for (MachineModel machine : networkModel.getAllMachines()) {
			//Make sure to push traffic to {in,e}gress chains
			if (machine.getSubnets().isEmpty()) { continue; } //Unless they don't have any interfaces
			machineIngressEgressForwardRules(machine);
		}
		
		if (networkModel.getData().getAutoGuest()) {
			DeviceModel autoguest = new DeviceModel("autoguest", networkModel);
			autoguest.setCIDR(22);
			autoguest.setFirstOctet(10);;
			autoguest.setSecondOctet(250);
			autoguest.setThirdOctet(0);
			
			autoguest.getInterfaceModel().addIface(new InterfaceData(
					"autoguest", //host
					"lan0:9001", //iface
					null, //mac
					"static", //inet
					null, //bridgeports
					networkModel.stringToIP("10.250.0.0"), //subnet
					networkModel.stringToIP("10.250.0.0"), //address
					networkModel.stringToIP("255.255.252.0"), //netmask
					null, //broadcast
					networkModel.stringToIP("10.0.0.1"), //gateway
					"Auto Guest pool" //comment
			));
			
			baseIptConfig(autoguest);
			
			networkModel.getIPSet().addToSet("autoguest", 22, networkModel.stringToIP("10.250.0.0"));
			
			String rule = "";
			rule += "-p tcp";
			rule += " -m set --match-set autoguest src";
			rule += " -j ACCEPT";
						
			this.firewall.addFilter(
					autoguest.getEgressChain(),
					"autoguest_egress",
					rule,
					"Allow automatic guest pool to call out to the internet"
			);
			
			machineIngressEgressForwardRules(autoguest);
		}
		
		return units;
	}
	
	private String collection2String(Object collection) {
		
		if (collection instanceof HashMap) {
			collection = ((HashMap<?, ?>) collection).keySet();
		}
		
		return collection.toString()
				.replace("[", "")
				.replace("]", "")
				.replace(" ", "")
				.replace("/", "")
				.replace("null,", "")
				.replace(",null", "");
	}
	
	private String buildUserDailyBandwidthEmail(String sender, String subject, DeviceModel user, Boolean includeBlurb) {
		String email = "";
		email += "echo -e \\\"";
		
		email += "subject:" + subject + "\\n";
		email += "from:" + sender + "\\n";
		email += "recipients:" + user.getEmailAddress() + "\\n";
		email += "\\n";
		email += "UL: \\`iptables -L " + user.getEgressChain() + " -v -n | tail -n 2 | head -n 1 | awk '{ print \\$2 }'\\`\\n";
		email += "DL: \\`iptables -L " + user.getIngressChain() + " -v -n | tail -n 2 | head -n 1 | awk '{ print \\$2 }'\\`";
		
		if (includeBlurb) {
			email += "\\n";
			email += "\\n";
			email += "=====================================================================================";
			email += "\\n";
			email += "\\n";
			email += "As you know, one of the key advantages afforded by operating our network through Thornsec is that it monitors for uploading traffic. ";
			email += "The reason for this is that we want to try and check for any data exfiltration from our network.";
			email += "\\n";
			email += "\\n";
			email += "Part of this monitoring allows our router to give you a daily digest of how much you've downloaded and uploaded.";
			email += "\\n";
			email += "\\n";
			email += "This is not a punitive email, this information is not logged, and is only sent to you, as a user.  This will hopefully alert you to any strange activity ";
			email += "coming from your device.";
			email += "\\n";
			email += "\\n";
			email += "If you think there is something suspicious about the figures above, please forward this email to the Tech Team so they can look into it for you.";
			email += "\\n";
			email += "\\n";
			email += "Thanks!";
			email += "\\n";
			email += "Tech Team";
		}
		
		email += "\\\"";
		email += "|sendmail \"" + user.getEmailAddress() + "\"\n\n";
		
		return email;
	}
	
	private Vector<IUnit> dailyBandwidthEmailDigestUnits() {
		Vector<IUnit> units = new Vector<IUnit>();

		String script = "";
		script += "#!/bin/bash\n";
		
		//Iterate through users first; they need alerting individually
		for (DeviceModel user : networkModel.getUserDevices()) {
			if (!networkModel.getDeviceModel(user.getLabel()).getInterfaces().isEmpty()) { //But only if they're an internal user 
				//Email the user only
				script += "\n\n";

				script += buildUserDailyBandwidthEmail(networkModel.getData().getAdminEmail(),
												"[" + user.getLabel() + "." + networkModel.getData().getLabel() + "] Daily Bandwidth Digest",
												user,
												true);

				script += "iptables -Z " + user.getIngressChain() + "\n";
				script += "iptables -Z " + user.getEgressChain();
			}
		}

		script += "\n\n";

		script += "echo -e \\\"";
		script += "subject: [" + networkModel.getData().getLabel() + "." + networkModel.getData().getDomain(me.getLabel()) + "] Daily Bandwidth Digest\\n";
		script += "from:" + me.getLabel() + "@" + networkModel.getData().getDomain(me.getLabel()) + "\\n";
		script += "recipients:" + networkModel.getData().getAdminEmail() + "\\n";

		//Iterate through everything which should be reported back to admins.
		//This used to be an individual email per device/server, but this is useless as it just spams the admins
		for (DeviceModel peripheral : networkModel.getAllPeripheralDevices()) {
			script += "\\n\\n";
			script += "Digest for " + peripheral.getLabel() + ":\\n";
			script += "UL: \\`iptables -L " + peripheral.getEgressChain() + " -v -n | tail -n 2 | head -n 1 | awk '{ print \\$2 }'\\`\\n";
			script += "DL: \\`iptables -L " + peripheral.getIngressChain() + " -v -n | tail -n 2 | head -n 1 | awk '{ print \\$2 }'\\`";
		}

		//Then servers
		for (ServerModel srv : networkModel.getAllServers()) {
			script += "\\n\\n";
			script += "Digest for " + srv.getLabel() + ":\\n";
			script += "UL: \\`iptables -L " + srv.getEgressChain() + " -v -n | tail -n 2 | head -n 1 | awk '{ print \\$2 }'\\`\\n";
			script += "DL: \\`iptables -L " + srv.getIngressChain() + " -v -n | tail -n 2 | head -n 1 | awk '{ print \\$2 }'\\`";
		}

		script += "\\\"";
		script += "|sendmail \"" + networkModel.getData().getAdminEmail() + "\"\n";

		//Zero all the chains
		for (MachineModel machine : networkModel.getAllMachines()) {
			script += "\niptables -Z " + machine.getIngressChain();
			script += "\niptables -Z " + machine.getEgressChain();
		}
		
		units.addElement(new FileUnit("daily_bandwidth_alert_script_created", "proceed", script, "/etc/cron.daily/bandwidth", "I couldn't create the bandwidth digest script.  This means you and your users won't receive daily updates on bandwidth use"));
		units.addElement(new FilePermsUnit("daily_bandwidth_alert_script", "daily_bandwidth_alert_script_created", "/etc/cron.daily/bandwidth", "750", "I couldn't set the bandwidth digest script to be executable.  This means you and your users won't receive daily updates on bandwidth use"));
		
		return units;
	}

	public Vector<IUnit> getNetworking() {
		Vector<IUnit> units = new Vector<IUnit>();

		units.addElement(new FileUnit("leave_my_resolv_conf_alone", "proceed",
				"make_resolv_conf() { :; }",
				"/etc/dhcp/dhclient-enter-hooks.d/leave_my_resolv_conf_alone"));
		units.addElement(new FilePermsUnit("leave_my_resolv_conf_alone", "leave_my_resolv_conf_alone",
				"/etc/dhcp/dhclient-enter-hooks.d/leave_my_resolv_conf_alone",
				"755",
				"I couldn't stop various systemd services deciding to override your DNS settings. This will cause you intermittent, difficult to diagnose problems as it randomly sets your DNS to wherever it decides. Great for desktops, atrocious for servers..."));
		
		InterfaceModel interfaces = me.getInterfaceModel();

		firewall = ((ServerModel)me).getFirewallModel();
		domain   = networkModel.getData().getDomain(me.getLabel());
		
		JsonArray extInterfaces = (JsonArray) networkModel.getData().getPropertyObjectArray(me.getLabel(), "wan");

		if (extInterfaces.size() == 0) {
			JOptionPane.showMessageDialog(null, "You must specify at least one WAN interface for your router.\n\nValid options are 'ppp', 'static', and 'dhcp'");
			System.exit(1);
		}
		
		for (int i = 0; i < extInterfaces.size(); ++i) {
			JsonObject row = extInterfaces.getJsonObject(i);

			String wanIface = row.getString("iface");
			
			//If we've already declared this iface, give it an alias
			if (wanIfaces.contains(wanIface)) {
				wanIface += ":" + i;
			}
			
			//These are fine to be null if not given
			InetAddress staticAddress = networkModel.stringToIP(row.getString("address", null));
			InetAddress netmask       = networkModel.stringToIP(row.getString("netmask", null));
			InetAddress gateway       = networkModel.stringToIP(row.getString("gateway", null));
			InetAddress broadcast     = networkModel.stringToIP(row.getString("broadcast", null));
			
			switch (row.getString("inettype", null)) {
				case "dhcp":
					interfaces.addIface(new InterfaceData(
							me.getLabel(), //host
							wanIface, //iface
							null, //mac
							"dhcp", //inet
							null, //bridgeports
							null, //subnet
							null, //address
							null, //netmask
							null, //broadcast
							null, //gateway
							"DHCP WAN physical network interface" //comment
					));
					
					String dhclient = "option rfc3442-classless-static-routes code 121 = array of unsigned integer 8;\n";
					dhclient += "send host-name = gethostname();\n";
					dhclient += "supersede domain-search \\\"" + this.domain + "\\\";\n";
					dhclient += "supersede domain-name-servers 10.0.0.1;\n";
					dhclient += "request subnet-mask, broadcast-address, time-offset, routers,\n";
					dhclient += "	domain-name, domain-name-servers, domain-search, host-name,\n";
					dhclient += "	dhcp6.name-servers, dhcp6.domain-search,\n";
					dhclient += "	netbios-name-servers, netbios-scope, interface-mtu,\n";
					dhclient += "	rfc3442-classless-static-routes, ntp-servers;";
					units.addElement(new FileUnit("router_ext_dhcp_persist", "proceed", dhclient, "/etc/dhcp/dhclient.conf"));

					firewall.addFilterInput("router_ext_dhcp_in",
							"-i " + wanIface
							+ " -d 255.255.255.255"
							+ " -p udp"
							+ " --dport 68"
							+ " --sport 67"
							+ " -j ACCEPT",
							"Make sure the Router can send DHCP requests");
					firewall.addFilterOutput("router_ext_dhcp_ipt_out", 
							"-o " + wanIface
							+ " -p udp"
							+ " --dport 67"
							+ " --sport 68"
							+ " -j ACCEPT",
							"Make sure the Router can receive DHCP responses");
					break;
				case "ppp":
					units.addElement(new InstalledUnit("ext_ppp", "ppp"));
					units.addElement(me.getInterfaceModel().addPPPIface("router_ext_ppp_iface", wanIface));
					((ServerModel)me).getProcessModel().addProcess("/usr/sbin/pppd call provider$");
					
					((ServerModel)me).getConfigsModel().addConfigFilePath("/etc/ppp/peers/dsl-provider$");
					((ServerModel)me).getConfigsModel().addConfigFilePath("/etc/ppp/options$");
					
					units.addElement(((ServerModel)me).getConfigsModel().addConfigFile("resolv_conf", "proceed", "nameserver 127.0.0.1", "/etc/ppp/resolv.conf"));
					
					firewall.addMangleForward("clamp_mss_to_pmtu",
							"-p tcp --tcp-flags SYN,RST SYN -m tcpmss --mss 1400:1536 -j TCPMSS --clamp-mss-to-pmtu",
							"Clamp the MSS to PMTU. This makes sure the packets over PPPoE are the correct size (and take into account the PPPoE overhead)");
					
					this.isPPP = true;
					
					break;
				case "static":
					interfaces.addIface(new InterfaceData(
							me.getLabel(), //host
							wanIface, //iface
							null, //mac
							"static", //inet
							null, //bridgeports
							null, //subnet
							staticAddress, //address
							netmask, //netmask
							broadcast, //broadcast
							gateway, //gateway
							"Static WAN physical network interface" //comment
					));
					
					this.isStatic = true;
					
					break;
				default:
					JOptionPane.showMessageDialog(null, "Valid options for your router's WAN inettype are 'ppp', 'static', and 'dhcp'");
					System.exit(1);
					break;
			}
			
			wanIfaces.addElement(wanIface);
		}

		Vector<String> routerLanIfaces = new Vector<String>(networkModel.getData().getLanIfaces(me.getLabel()).keySet());
		
		String lanBridge = "lan0";

		InetAddress netmask = networkModel.getData().getNetmask();
		
		//We don't actually care about LAN ifaces if we're a metal/router
		if (((ServerModel) me).isMetal()) {
			//We very deliberately hang everything off a bridge, to stop internal traffic over the WAN iface
			units.addElement(new InstalledUnit("bridge_utils", "bridge-utils"));
			
			InetAddress subnet  = networkModel.stringToIP("10.0.0.0");
			InetAddress address = networkModel.stringToIP("10.0.0.1");

			interfaces.addIface(new InterfaceData(
					me.getLabel(), //host
					lanBridge, //iface
					null, //mac
					"static", //inet
					new String[] {"none"}, //bridgeports
					subnet, //subnet
					null, //address
					netmask, //netmask
					null, //broadcast
					address, //"gateway" - because this is a router iface, it only looks at gateways
					"VM interface on a bridge to nowhere" //comment
			));
		}
		else {
			//First, add this machine's own interfaces
			for (String lanIface : routerLanIfaces) {
				interfaces.addIface(new InterfaceData(
						me.getLabel(), //host
						lanIface, //iface
						null, //mac
						"manual", //inet
						null, //bridgeports
						null, //subnet
						null, //address
						null, //netmask
						null, //broadcast
						null, //gateway
						"LAN physical network interface" //comment
				));
			}
			
			//Now, bridge 'em
			InetAddress subnet  = networkModel.stringToIP("10.0.0.0");
			InetAddress address = networkModel.stringToIP("10.0.0.1");
			interfaces.addIface(new InterfaceData(
					"lan", //host
					lanBridge, //iface
					null, //mac
					"static", //inet
					routerLanIfaces.toArray(new String[routerLanIfaces.size()]), //bridgeports
					subnet, //subnet
					address, //address
					netmask, //netmask
					null, //broadcast
					address, //gateway
					"bridge all physical interfaces" //comment
			));
		}
		
		
		//Now add for our servers
		//for (ServerModel srv : networkModel.getAllServers()) {
		for (MachineModel machine : networkModel.getAllMachines()) {
			if (machine.equals(me)) { continue; } //Skip if we're talking about ourself
			
			Integer classifier = null;
			
			if (machine instanceof ServerModel) {
				classifier = 0; 
			}
			else if (machine instanceof DeviceModel) {
				classifier = 1;
			}
			
			for (InterfaceData machineLanIface : machine.getInterfaceModel().getIfaces()) {
				//Parse our MAC address into an integer to stop collisions when adding/removing interfaces
			//	String alias = null; //getAlias(machineLanIface.getMac());
				
				//if (machineLanIface.getMac() == null) {
				//	alias = getAlias(machineLanIface.getIface());
				//}
				//else {
				//	alias = getAlias(machineLanIface.getMac());
			//	}
				String ifaceName = null;
				String ifaceComment = null;
				
				if (((ServerModel) me).isMetal()) {
					ifaceName    = "vm" + machine.getThirdOctet();
					ifaceComment = "Router/Metal interface. This is a fake interface just for the VM";
				}
				else {
					ifaceName    = lanBridge + ":" + classifier + machine.getThirdOctet();
					ifaceComment = "Router interface. Let's bridge to lan";
				}
				
				interfaces.addIface(new InterfaceData(
						machine.getLabel(), //host
						ifaceName, //iface
						machineLanIface.getMac(), //mac
						"static", //inet
						machineLanIface.getBridgePorts(), //bridgeports
						machineLanIface.getSubnet(), //subnet
						machineLanIface.getAddress(), //address
						netmask, //netmask
						machineLanIface.getBroadcast(), //broadcast
						machineLanIface.getGateway(), //gateway
						ifaceComment //comment
				));

				String[] cnames  = networkModel.getData().getCnames(machine.getLabel());
				String[] subdomains = new String[cnames.length + 1];
				System.arraycopy(new String[] {machine.getHostname()},0,subdomains,0, 1);
				System.arraycopy(cnames,0,subdomains,1, cnames.length);

				this.dns.addDomainRecord(networkModel.getData().getDomain(machine.getLabel()), machineLanIface.getGateway(), subdomains, machineLanIface.getAddress());
			}
		}
		
		if (networkModel.getData().getAutoGuest()) {
			interfaces.addIface(new InterfaceData(
					"autoguest", //host
					"lan0:9001", //iface
					null, //mac
					"static", //inet
					null, //bridgeports
					networkModel.stringToIP("10.250.0.0"), //subnet
					null, //address
					networkModel.stringToIP("255.255.252.0"), //netmask
					null, //broadcast
					networkModel.stringToIP("10.250.0.1"), //gateway
					"Auto Guest pool, bridged to our lan" //comment
			));
		}
		
		//Initialise the basic firewall rules for everything
		for (MachineModel machine : networkModel.getAllMachines()) {
			if (machine.getSubnets().isEmpty()) { continue; } //Unless they don't have any interfaces
			baseIptConfig(machine);
		}

		for (String wanIface : wanIfaces) {
			//Masquerade on the external iface
			this.firewall.addNatPostrouting(me.getHostname() + "_masquerade_external",
					"-o " + wanIface
					+ " -j MASQUERADE",
					"Mask the IP address of any external traffic coming from our network on " + wanIface + " to obscure internal IPs");
		}
	
		//If we're not forcing VPN only, also allow clearnet devices
		if (!networkModel.getData().getVpnOnly()) {
			userIfaces.addElement(":1+");
		}
		
		units.addAll(dhcp.getNetworking());
		units.addAll(dns.getNetworking());
		units.addAll(qos.getNetworking());
		
		units.addAll(networkIptUnits());
		
		return units;
	}
	
	private Vector<IUnit> baseIptConfig(MachineModel machine) {
		Vector<IUnit> units = new Vector<IUnit>();

		//Do we want to be logging drops?
		Boolean debugMode = Boolean.parseBoolean(networkModel.getData().getProperty(me.getLabel(), "debug", false));
		
		//Create our egress chain for bandwidth (exfil?) tracking
		//In future, we could perhaps do some form of traffic blocking malarky here?
		this.firewall.addChain(machine.getEgressChain(), "filter", machine.getEgressChain());
		//Create our ingress chain for download bandwidth tracking
		this.firewall.addChain(machine.getIngressChain(), "filter", machine.getIngressChain());
		//Create our forward chain for all other rules
		this.firewall.addChain(machine.getForwardChain(), "filter", machine.getForwardChain());

		//Force traffic to/from a given subnet to jump to our chains
		this.firewall.addFilterForward(machine.getHostname() + "_ipt_server_src",
				"-s " + machine.getSubnets().elementAt(0).getHostAddress() + "/" + machine.getCIDR()
				+ " -j "+ machine.getForwardChain(),
				"Force any internal traffic coming from " + machine.getHostname() + " to its own chain");
		this.firewall.addFilterForward(machine.getHostname() + "_ipt_server_dst",
				"-d " + machine.getSubnets().elementAt(0).getHostAddress() + "/" + machine.getCIDR()
				+ " -j " + machine.getForwardChain(),
				"Force any internal traffic going to " + machine.getHostname() + " to its own chain");

		//We want to default drop anything not explicitly whitelisted
		//Make sure that these are the very first rules as the chain may have been pre-populated
		this.firewall.addFilter(machine.getHostname() + "_fwd_default_drop", machine.getForwardChain(), 0,
				"-j DROP",
				"Drop any internal traffic for " + machine.getHostname() + " which has not already hit one of our rules");
		
		//Don't allow any traffic in from the outside world
		this.firewall.addFilter(machine.getHostname() + "_ingress_default_drop", machine.getIngressChain(), 0,
				"-j DROP",
				"Drop any external traffic for " + machine.getHostname() + " which has not already hit one of our rules");

		//Don't allow any traffic out to the outside world
		this.firewall.addFilter(machine.getHostname() + "_egress_default_drop", machine.getEgressChain(), 0,
				"-j DROP",
				"Drop any outbound traffic from " + machine.getHostname() + " which has not already hit one of our rules");

		//Have we set debug on? Let's do some logging!
		if (debugMode) {
			this.firewall.addFilter(machine.getHostname() + "_fwd_log", machine.getForwardChain(), 1,
					"-j LOG --log-prefix \"" + machine.getHostname() + "-forward-dropped:\"",
					"Log any traffic from " + machine.getHostname() + " before dropping it");
			this.firewall.addFilter(machine.getHostname() + "_ingress_log", machine.getIngressChain(), 1,
					"-j LOG --log-prefix \"" + machine.getHostname() + "-ingress-dropped:\"",
					"Log any traffic from " + machine.getHostname() + " before dropping it");
			this.firewall.addFilter(machine.getHostname() + "_ingress_log", machine.getEgressChain(), 1,
					"-j LOG --log-prefix \"" + machine.getHostname() + "-egress-dropped:\"",
					"Log any traffic from " + machine.getHostname() + " before dropping it");
		}
		
		//Allow responses to established traffic on all chains
		this.firewall.addFilter(machine.getHostname() + "_allow_related_ingress_traffic_tcp", machine.getIngressChain(),
				"-p tcp"
				+ " -m state --state ESTABLISHED,RELATED"
				+ " -j ACCEPT",
				"Allow " + machine.getHostname() + " to receive responses to accepted outbound tcp traffic");
		this.firewall.addFilter(machine.getHostname() + "_allow_related_ingress_traffic_udp", machine.getIngressChain(),
				"-p udp"
				+ " -m state --state ESTABLISHED,RELATED"
				+ " -j ACCEPT",
				"Allow " + machine.getHostname() + " to receive responses to accepted outbound udp traffic");
		this.firewall.addFilter(machine.getHostname() + "_allow_related_fwd_traffic_tcp", machine.getForwardChain(),
				"-p tcp"
				+ " -m state --state ESTABLISHED,RELATED"
				+ " -j ACCEPT",
				"Allow " + machine.getHostname() + " to receive responses to accepted forward tcp traffic");
		this.firewall.addFilter(machine.getHostname() + "_allow_related_fwd_traffic_udp", machine.getForwardChain(),
				"-p udp"
				+ " -m state --state ESTABLISHED,RELATED"
				+ " -j ACCEPT",
				"Allow " + machine.getHostname() + " to receive responses to accepted forward udp traffic");
		this.firewall.addFilter(machine.getHostname() + "_allow_related_outbound_traffic_tcp", machine.getEgressChain(),
				"-p tcp"
				+ " -m state --state ESTABLISHED,RELATED"
				+ " -j ACCEPT",
				"Allow " + machine.getHostname() + " to send responses to accepted inbound tcp traffic");
		this.firewall.addFilter(machine.getHostname() + "_allow_outbound_traffic_udp", machine.getEgressChain(),
				"-p udp"
				+ " -j ACCEPT",
				"Allow " + machine.getHostname() + " to send udp traffic");

		//Add our forward chain rules (backwards(!))
		//Allow our router to talk to us
		this.firewall.addFilter(machine.getHostname() + "_allow_router_traffic", machine.getForwardChain(),
				"-s " + machine.getSubnets().elementAt(0).getHostAddress() + "/30"
				+ " -j ACCEPT",
				"Allow traffic between " + machine.getHostname() + " and its router");

		return units;
	}
	
	private Vector<IUnit> routerScript() {
		Vector<IUnit> units = new Vector<IUnit>();
		
		String admin = "";
		admin += "#!/bin/bash\n";
		admin += "\n";
		admin += "RED='\\\\033[0;31m'\n"; 
		admin += "GREEN='\\\\033[0;32m'\n"; 
		admin += "NC='\\\\033[0m'\n";
		admin += "\n";
		admin += "function checkInternets {\n"; 
		admin += "        clear\n";
		admin += "\n";
		admin += "        echo \\\"Checking your internet connectivity, please wait...\\\"\n"; 
		admin += "        echo \n";
		admin += "        echo \\\"1/3 (8.8.8.8 - Google DNS)     : \\$(ping -q -w 1 -c 1 8.8.8.8 &> /dev/null && echo -e \\\"\\${GREEN}\\\"OK!\\\"\\${NC}\\\" || echo -e \\\"\\${RED}\\\"ERROR\\\"\\${NC}\\\")\\\"\n";
		admin += "        echo \\\"2/3 (208.67.222.222 - OpenDNS) : \\$(ping -q -w 1 -c 1 208.67.222.222 &> /dev/null && echo -e \\\"\\${GREEN}\\\"OK!\\\"\\${NC}\\\" || echo -e \\\"\\${RED}\\\"ERROR\\\"\\${NC}\\\")\\\"\n";
		admin += "        echo \\\"3/3 (1.1.1.1 - Cloudflare DNS) : \\$(ping -q -w 1 -c 1 1.1.1.1 &> /dev/null && echo -e \\\"\\${GREEN}\\\"OK!\\\"\\${NC}\\\" || echo -e \\\"\\${RED}\\\"ERROR\\\"\\${NC}\\\")\\\"\n";
		admin += "        echo \n";
		admin += "        read -n 1 -s -r -p \\\"Press any key to return to the main menu...\\\"\n";
		admin += "}\n";
		admin += "\n";
		admin += "function checkDNS {\n";
		admin += "        clear\n";
		admin += "\n";
		admin += "        echo \\\"Checking your external DNS server is resolving correctly\\\"\n";
		admin += "        echo \n";
		admin += "        echo \\\"Getting the DNS record for Google.com : \\$( dig +short google.com. &> /dev/null && echo -e \\\"\\${GREEN}\\\"OK!\\\"\\${NC}\\\" || echo -e \\\"\\${RED}\\\"ERROR\\\"\\${NC}\\\")\\\"\n";
		admin += "        echo \n";
		admin += "        read -n 1 -s -r -p \\\"Press any key to return to the main menu...\\\"\n";
		admin += "}\n";
		admin += "\n";
		admin += "function restartUnbound {\n";
		admin += "        clear\n";
		admin += "\n";
		admin += "        echo \\\"Restarting the DNS Server - please wait...\\\"\n";
		admin += "        echo \n";
		admin += "        echo \\\"Stopping DNS Server : \\$(service unbound stop &> /dev/null && echo -e \\\"\\${GREEN}\\\"OK!\\\"\\${NC}\\\" || echo -e \\\"\\${RED}\\\"ERROR\\\"\\${NC}\\\")\\\"\n";
		admin += "        echo \\\"Starting DNS Server : \\$(service unbound start &> /dev/null && echo -e \\\"\\${GREEN}\\\"OK!\\\"\\${NC}\\\" || echo -e \\\"\\${RED}\\\"ERROR\\\"\\${NC}\\\")\\\"\n";
		admin += "        echo \n";
		admin += "        read -n 1 -s -r -p \\\"Press any key to return to the main menu...\\\"\n";
		admin += "}\n";
		admin += "\n";
		admin += "function restartDHCP {\n";
		admin += "        clear\n";
		admin += "\n";
		admin += "        echo \\\"Restarting the DHCP Server - please wait...\\\"\n";
		admin += "        echo \n";
		admin += "        echo \\\"Stopping DHCP Server : \\$(service isc-dhcp-server stop &> /dev/null && echo -e \\\"\\${GREEN}\\\"OK!\\\"\\${NC}\\\" || echo -e \\\"\\${RED}\\\"ERROR\\\"\\${NC}\\\")\\\"\n";
		admin += "        echo \\\"Starting DHCP Server : \\$(service isc-dhcp-server start &> /dev/null && echo -e \\\"\\${GREEN}\\\"OK!\\\"\\${NC}\\\" || echo -e \\\"\\${RED}\\\"ERROR\\\"\\${NC}\\\")\\\"\n";
		admin += "        echo \n";
		admin += "        read -n 1 -s -r -p \\\"Press any key to return to the main menu...\\\"\n"; 
		admin += "}\n";
		admin += "\n";
		if (this.isPPP) {
			admin += "function restartPPPoE {\n";
			admin += "        clear\n";
			admin += "\n";
			admin += "        echo \\\"Restarting the PPPoE Client - please wait...\\\"\n";
			admin += "        echo \n";
			admin += "        echo \\\"Stopping PPPoE Client : \\$(poff &> /dev/null && echo -e \\\"\\${GREEN}\\\"OK!\\\"\\${NC}\\\" || echo -e \\\"\\${RED}\\\"ERROR\\\"\\${NC}\\\")\\\"\n";
			admin += "        echo \\\"Starting PPPoE Client : \\$(pon &> /dev/null && echo -e \\\"\\${GREEN}\\\"OK!\\\"\\${NC}\\\" || echo -e \\\"\\${RED}\\\"ERROR\\\"\\${NC}\\\")\\\"\n";
			admin += "        echo \n";
			admin += "        sleep 2\n";
			admin += "        checkInternets\n";
			admin += "}\n";
			admin += "\n";
		}
		admin += "function reloadIPT {\n";
		admin += "        clear\n";
		admin += "\n";
		admin += "        echo \\\"Reloading the firewall - please wait...\\\"\n";
		admin += "        echo \n";
		admin += "        echo \\\"Flushing firewall rules  (1/2)  : \\$(iptables -F &> /dev/null && echo -e \\\"\\${GREEN}\\\"OK!\\\"\\${NC}\\\" || echo -e \\\"\\${RED}\\\"ERROR\\\"\\${NC}\\\")\\\"\n";
		admin += "        echo \\\"Flushing firewall rules  (2/2)  : \\$(ipset destroy &> /dev/null && echo -e \\\"\\${GREEN}\\\"OK!\\\"\\${NC}\\\" || echo -e \\\"\\${RED}\\\"ERROR\\\"\\${NC}\\\")\\\"\n";
		admin += "        echo \\\"Reloading firewall rules (2/2) : \\$(/etc/ipsets/ipsets.up.sh | ipset restore &> /dev/null && echo -e \\\"\\${GREEN}\\\"OK!\\\"\\${NC}\\\" || echo -e \\\"\\${RED}\\\"ERROR\\\"\\${NC}\\\")\\\"\n";
		admin += "        echo \\\"Reloading firewall rules (2/2) : \\$(/etc/iptables/iptables.conf.sh | iptables-restore &> /dev/null && echo -e \\\"\\${GREEN}\\\"OK!\\\"\\${NC}\\\" || echo -e \\\"\\${RED}\\\"ERROR\\\"\\${NC}\\\")\\\"\n";
		admin += "        echo \n";
		admin += "        read -n 1 -s -r -p \\\"Press any key to return to the main menu...\\\"\n";
		admin += "}\n";
		admin += "\n";
		admin += "function tracert {\n";
		admin += "        clear\n";
		admin += "\n";
		admin += "        echo \\\"Conducting a traceroute between the router and Google.com - please wait...\\\"\n";
		admin += "        echo \n";
		admin += "        traceroute google.com\n";
		admin += "        echo \n";
		admin += "        read -n 1 -s -r -p \\\"Press any key to return to the main menu...\\\"\n";
		admin += "}\n";
		admin += "\n";
		if (this.isPPP) {
			admin += "function configurePPPoE {\n";
			admin += "        correct=\\\"false\\\"\n";
			admin += "        \n";
			admin += "        while [ \\\"\\${correct}\\\" = \\\"false\\\" ]; do\n";
			admin += "            clear\n";
			admin += "            \n";
			admin += "            echo \\\"Enter your ISP's login username and press [ENTER]\\\"\n";
			admin += "            read -r username\n";
			admin += "            echo \\\"Enter your ISP's login password and press [ENTER]\\\"\n";
			admin += "            read -r password\n";
			admin += "            \n";
			admin += "            clear\n";
			admin += "            \n";
			admin += "            echo -e \\\"Username: \\${GREEN}\\${username}\\${NC}\\\"\n";
			admin += "            echo -e \\\"Password: \\${GREEN}\\${password}\\${NC}\\\"\n";
			admin += "            \n";
			admin += "            read -r -p \\\"Are the above credentials correct? [Y/n]\\\" yn\n";
			admin += "            \n";
			admin += "            case \\\"\\${yn}\\\" in\n";
			admin += "                [nN]* ) correct=\\\"false\\\";;\n";
			admin += "                    * ) correct=\\\"true\\\";\n";
			admin += "                        printf \\\"%s      *      %s\\\" \\\"\\${username}\\\" \\\"\\${password}\\\" > /etc/ppp/chap-secrets;;\n";
			admin += "			esac\n";
			admin += "		done\n";
			admin += "      \n";
			admin += "      read -n 1 -s -r -p \\\"Press any key to return to the main menu...\\\"\n";
			admin += "\n";
			admin += "}\n";
			admin += "\n";
		}
		admin += "function speedtest {\n";
		admin += "        clear\n";
		admin += "\n";
		admin += "        echo \\\"Running a speed test - please wait...\\\"\n";
		admin += "        echo \n";
		admin += "        speedtest-cli\n";
		admin += "        echo \n";
		admin += "        read -n 1 -s -r -p \\\"Press any key to return to the main menu...\\\"\n"; 
		admin += "}\n";
		admin += "\n";
		admin += "if [ \\\"\\${EUID}\\\" -ne 0 ]\n";
		admin += "    then echo -e \\\"\\${RED}This script requires running as root.  Please sudo and try again.\\${NC}\\\"\n";
		admin += "    exit\n";
		admin += "fi\n";
		admin += "\n";
		admin += "while true; do\n";
		admin += "        clear\n";
		admin += "        echo \\\"Choose an option:\\\"\n";
		admin += "        echo \\\"1) Check Internet Connectivity\\\"\n";
		admin += "        echo \\\"2) Check External DNS\\\"\n";
		admin += "        echo \\\"3) Restart Internal DNS Server\\\"\n";
		admin += "        echo \\\"4) Restart Internal DHCP Server\\\"\n";
		admin += "        echo \\\"5) Flush & Reload Firewall\\\"\n";
		admin += "        echo \\\"6) Traceroute\\\"\n";
		if (this.isPPP) {
			admin += "        echo \\\"7) Restart PPPoE (Internet) Connection\\\"\n";
			admin += "        echo \\\"C) Configure PPPoE credentials\\\"\n";
		}
		admin += "        echo \\\"S) Run a line speed test\\\"\n";
		admin += "        echo \\\"R) Reboot Router\\\"\n";
		admin += "        echo \\\"Q) Quit\\\"\n";
		admin += "        read -r -p \\\"Select your option: \\\" opt\n";
		admin += "        case \\\"\\${opt}\\\" in\n";
		admin += "                1   ) checkInternets;;\n";
		admin += "                2   ) checkDNS;;\n";
		admin += "                3   ) restartUnbound;;\n";
		admin += "                4   ) restartDHCP;;\n";
		admin += "                5   ) reloadIPT;;\n";
		admin += "                6   ) tracert;;\n";
		if (this.isPPP) {
			admin += "                7   ) restartPPPoE;;\n";
			admin += "                c|C ) configurePPPoE;;\n";
		}
		admin += "                s|S ) speedtest;;\n";
		admin += "                r|R ) reboot;;\n";
		admin += "                q|Q ) exit;;\n";
		admin += "        esac\n";
		admin += "done";

		units.addElement(new FileUnit("router_admin", "proceed", admin, "/root/routerAdmin.sh"));
		units.addElement(new FileOwnUnit("router_admin", "router_admin", "/root/routerAdmin.sh", "root"));
		units.addElement(new FilePermsUnit("router_admin", "router_admin_chowned", "/root/routerAdmin.sh", "500"));
		
		return units;
	}
	
//	private String cleanString(String string) {
//		String invalidChars = "[^a-zA-Z0-9-]";
//		String safeChars    = "_";
//		
//		return string.replaceAll(invalidChars, safeChars);
//	}
	
	private String getAlias(String toParse) {
		MessageDigest digest = null;
		
		try {
			digest = MessageDigest.getInstance("SHA-512");
			digest.reset();
			digest.update(toParse.getBytes("utf8"));
		}
		catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		
		String digested = String.format("%040x", new BigInteger(1, digest.digest()));
		
		return digested.replaceAll("[^0-9]", "").substring(0, 8);
	}
}
