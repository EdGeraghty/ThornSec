/*
 * This code is part of the ThornSec project.
 * 
 * To learn more, please head to its GitHub repo: @privacyint
 * 
 * Pull requests encouraged.
 */
package profile.service.machine;

import java.util.HashSet;
import java.util.Set;

import core.iface.IUnit;
import core.model.network.NetworkModel;

import core.profile.AStructuredProfile;

/**
 * This profile will create and configure a VPN service
 */
public class StrongSwan extends AStructuredProfile {

	public StrongSwan(String label, NetworkModel networkModel) {
		super("strongswan", networkModel);
	}
	
	protected Set<IUnit> getPersistentConfig() {
		Set<IUnit> units = new HashSet<IUnit>();
        
		;;
		
		return units;
	}

	public Set<IUnit> getPersistentFirewall() {
		Set<IUnit> units = new HashSet<IUnit>();

		/*
		for (ServerModel router : networkModel.getRouterServers()) {
			ISCDHCPServer dhcp = ((ServerModel)router).getRouter().getDHCPServer();
			UnboundDNSServer  dns  = ((ServerModel)router).getRouter().getDNSServer();
			
			for (DeviceModel user : networkModel.getUserDevices()) {
				
				String firstThree = user.getFirstOctet() + "." + user.getSecondOctet() + "." + user.getThirdOctet();
				
				int vpnSubnet = ((user.getSubnets().size()) * 4);

				InetAddress netmask = networkModel.getData().getNetmask();
				InetAddress subnet  = networkModel.stringToIP(firstThree + "." + vpnSubnet);
				InetAddress gateway = networkModel.stringToIP(firstThree + "." + (vpnSubnet + 1));
				InetAddress startIp = networkModel.stringToIP(firstThree + "." + (vpnSubnet + 2));
				InetAddress endIp   = startIp;
				
				String domain    = networkModel.getData().getDomain(router.getLabel());
				String subdomain = user.getLabel() + "." + networkModel.getLabel() + ".vpn";

				String roadWarriorClass = "";
				roadWarriorClass += "\n\n";
				roadWarriorClass += "\tclass \\\"" + user.getLabel() + "\\\" {\n";
				roadWarriorClass += "\t\tmatch if ((substring(hardware, 1, 2) = 7a:a7) and (option dhcp-client-identifier = \\\"" + user.getLabel() + "\\\"));\n";
				roadWarriorClass += "\t}";
				//TODO: subclasses
				//String roadWarriorClass = "";
				//roadWarriorClass += "\n\n";
				//roadWarriorClass += "\tclass \\\"VPN\\\" {\n";
				//roadWarriorClass += "\t\t"
				
				
				dhcp.addClass(roadWarriorClass);
				
				String roadWarrior = "";
				roadWarrior += "\n\n";
				roadWarrior += "\tsubnet " + subnet.getHostAddress() + " netmask " + netmask.getHostAddress() + " {\n";
				roadWarrior += "\t\tpool {\n";
				roadWarrior += "\t\t\tallow members of \\\"" + user.getLabel() + "\\\";\n";
				roadWarrior += "\t\t\trange " + startIp.getHostAddress() + " " + endIp.getHostAddress() + ";\n";
				roadWarrior += "\t\t\toption routers " + gateway.getHostAddress() + ";\n";
				roadWarrior += "\t\t}\n";
				roadWarrior += "\t}";
				
				dhcp.addStanza(roadWarrior);

				dns.addDomainRecord(domain, gateway, new String[]{subdomain}, startIp);
	
				user.getLANInterfaces().addIface(new InterfaceData(
						user.getLabel(), //host
						"lan0:2" + user.getThirdOctet() + vpnSubnet, //iface
						null, //mac
						"static", //inet
						null, //bridgeports
						subnet, //subnet
						startIp, //address
						netmask, //netmask
						null, //broadcast
						gateway, //gateway
						"VPN interface" //comment
				));
			}
		}

		networkModel.getIPSet().addToSet("user", 32, me.getIP());
		
		for (ServerModel router : networkModel.getRouterServers()) {
			InetAddress ip = networkModel.getServerModel(getLabel()).getIP();
			
			((ServerModel)router).getFirewallModel().addNatPrerouting("dnat_" + networkModel.getData().getExternalIp(getLabel()),
					"-p udp"
					+ " -m multiport"
					+ " --dports 500,4500"
					+ " -j DNAT"
					+ " --to-destination " + ip.getHostAddress(),
					"Redirect all external UDP traffic on :500 and :4500 (VPN ports) to our VPN server");
			((ServerModel)router).getFirewallModel().addFilter(getLabel() + "_allow_vpn_fwd", me.getForwardChain(),
					"-p udp"
					+ " -m multiport"
					+ " --dports 500,4500"
					+ " -j ACCEPT",
					"Allow internal UDP traffic on :500 and :4500 (VPN ports) to our VPN server");
			((ServerModel)router).getFirewallModel().addFilter(getLabel() + "_allow_vpn_internally", me.getForwardChain(),
					"-p udp"
					+ " -m multiport"
					+ " --sports 500,4500"
					+ " -j ACCEPT",
					"Allow internal UDP traffic on :500 and :4500 (VPN ports) to our VPN server");
			((ServerModel)router).getFirewallModel().addFilter(getLabel() + "_allow_vpn_in", me.getIngressChain(),
					"-p udp"
					+ " -m multiport"
					+ " --dports 500,4500"
					+ " -j ACCEPT",
					"Allow all external UDP traffic on :500 and :4500 (VPN ports)");

			((ServerModel)router).getFirewallModel().addFilter(getLabel() + "_allow_egress", me.getEgressChain(),
					"-j ACCEPT",
					"Allow the VPN to talk to the outside world");
			((ServerModel)router).getFirewallModel().addFilter(getLabel() + "_allow_ingress", me.getIngressChain(),
					"-m state --state ESTABLISHED,RELATED"
					+ " -j ACCEPT",
					"Allow the VPN to respond to valid traffic");
		}*/
		
		return units;
	}
}
