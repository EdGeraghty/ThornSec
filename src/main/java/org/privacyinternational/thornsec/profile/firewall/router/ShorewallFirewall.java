/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.profile.firewall.router;

import inet.ipaddr.HostName;
import inet.ipaddr.IPAddress;
import org.privacyinternational.thornsec.core.StringUtils;
import org.privacyinternational.thornsec.core.data.machine.configuration.NetworkInterfaceData.Direction;
import org.privacyinternational.thornsec.core.data.machine.configuration.NetworkInterfaceData.Inet;
import org.privacyinternational.thornsec.core.data.machine.configuration.TrafficRule;
import org.privacyinternational.thornsec.core.data.machine.configuration.TrafficRule.Encapsulation;
import org.privacyinternational.thornsec.core.exception.AThornSecException;
import org.privacyinternational.thornsec.core.exception.data.machine.InvalidServerException;
import org.privacyinternational.thornsec.core.exception.runtime.*;
import org.privacyinternational.thornsec.core.iface.IUnit;
import org.privacyinternational.thornsec.core.model.machine.AMachineModel;
import org.privacyinternational.thornsec.core.model.machine.ServerModel;
import org.privacyinternational.thornsec.core.model.machine.configuration.networking.MACVLANModel;
import org.privacyinternational.thornsec.core.model.machine.configuration.networking.MACVLANTrunkModel;
import org.privacyinternational.thornsec.core.model.machine.configuration.networking.NetworkInterfaceModel;
import org.privacyinternational.thornsec.core.unit.fs.FileEditUnit;
import org.privacyinternational.thornsec.core.unit.fs.FileUnit;
import org.privacyinternational.thornsec.core.unit.pkg.InstalledUnit;
import org.privacyinternational.thornsec.profile.firewall.AFirewallProfile;
import org.privacyinternational.thornsec.type.AMachineType;
import org.privacyinternational.thornsec.type.Router;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.stream.Collectors;

/**
 * For more information on this Firewall, please see
 * http://shorewall.org/configuration_file_basics.htm
 * 
 *
 */
//@TODO:This class is mucky, and needs some major refactoring to make readable
public class ShorewallFirewall extends AFirewallProfile {
	public enum Action {
		ACCEPT, DNAT, DROP, REJECT, REDIRECT
	}

	private static final String CONFIG_BASEDIR = "/etc/shorewall";

	private class ShorewallRule {
		private String macro;
		private Action action;

		private Boolean invertSource;

		private String sourceZone;
		private String sourceSubZone;
		private final Collection<Integer> sPorts;

		private String destinationZone;
		private String destinationSubZone;
		private Encapsulation proto;
		private Collection<Integer> dPorts;

		private Collection<IPAddress> origDest;

		private String rate;

		public ShorewallRule() {
			macro = null;
			action = null;

			invertSource = false;
			sourceSubZone = null;
			sPorts = null;

			destinationZone = null;
			destinationSubZone = null;
			proto = null;
			dPorts = null;

			origDest = null;

			rate = null;
		}

		public ShorewallRule(TrafficRule rule) throws InvalidFirewallRuleException {
			this();

			switch (rule.getTable()) {
				case DNAT -> buildDNAT(rule);
				case EGRESS -> buildEgress(rule);
				case FORWARD -> buildForward(rule);
				case INGRESS -> buildIngress(rule);
				default -> throw new InvalidFirewallRuleException(rule.getTable() + " is not recognised");
			}
		}

		/**
		 * Ingests an Ingress TrafficRule, turning it into the Shorewall equivalent.
		 * 
		 * The rule's destinationZone must be a valid machine label.
		 * 
		 * @param rule Ingress TrafficRule
		 */
		private void buildIngress(TrafficRule rule) {
			this.setAction(Action.ACCEPT);
			this.setSourceZone("Internet");
			this.setProto(rule.getEncapsulation());
			this.setDPorts(rule.getPorts());
			this.setDestinationZone(
				rule.getDestinations()
					.stream()
					.map(destination -> cleanZone(destination.getHost()))
					.collect(Collectors.joining(","))
			);
			this.setDestinationSubZone(
				rule.getDestinations()
					.stream()
					.map(HostName::getHost)
					.map(label -> getNetworkModel().getMachineModel(label).orElseThrow().getIPs())
					.flatMap(Collection::stream)
					.map(ip -> ip.withoutPrefixLength().toCompressedString())
					.collect(Collectors.joining(","))
			);
		}


		/**
		 * Ingests a Forward (intra-zone) TrafficRule, turning it into the Shorewall equivalent.
		 * 
		 * The rule's destinationZone must be a valid machine label.
		 * 
		 * @param rule Forward TrafficRule
		 */
		private void buildForward(TrafficRule rule) {
			//boolean destIsExternallyAccessible = rule.getDestinations()
			//		.stream()
			//		.map(HostName::getHost)
			//		.anyMatch(label -> !getNetworkModel().getMachineModel(label).getIPs().isEmpty());

			this.setAction(Action.ACCEPT);
			//TODO
			//if (destIsExternallyAccessible) {
				this.setSourceZone("any");
			//}
			//else {
			//	this.setSourceZone(
			//		getNetworkModel().getSubnets().keySet()
			//		 .stream()
			//		 .filter(type -> !getNetworkModel().getMachines(type).isEmpty())
			//		 .map(ShorewallFirewall.this::cleanZone)
			//		 .collect(Collectors.joining(","))
			//	);
//			}
			this.setProto(rule.getEncapsulation());
			this.setDPorts(rule.getPorts());
			this.setDestinationZone(
				rule.getDestinations()
					.stream()
					.map(destination -> cleanZone(destination.getHost()))
					.collect(Collectors.joining(","))
			);
			this.setDestinationSubZone(
				rule.getDestinations()
					.stream()
					.map(HostName::getHost)
					.map(label -> getNetworkModel().getMachineModel(label).orElseThrow().getIPs())
					.flatMap(Collection::stream)
					.filter(IPAddress::isLocal)
					.map(ip -> ip.withoutPrefixLength().toCompressedString())
					.collect(Collectors.joining(","))
			);
		}

		/**
		 * Ingests an Egress TrafficRule, turning it into the Shorewall equivalent.
		 * @param rule Egress TrafficRule
		 */
		private void buildEgress(TrafficRule rule) {
			this.setAction(Action.ACCEPT);
			this.setSourceZone(cleanZone(rule.getSource()));
			this.setProto(rule.getEncapsulation());
			this.setDPorts(rule.getPorts());
			this.setDestinationZone("Internet");
			this.setDestinationSubZone(
				rule.getDestinations()
					.stream()
					.map(HostName::getHost)
					.collect(Collectors.joining(","))
			);
		}

		/**
		 * Ingests a DNAT TrafficRule, turning it into the Shorewall equivalent.
		 * 
		 * The rule's sourceZone and destinationZone must be valid machine labels
		 * 
		 * @param rule Ingress TrafficRule
		 */
		private void buildDNAT(TrafficRule rule) {
			this.setAction(Action.DNAT);

			//don't DNAT to us if we're the source!
			this.setInvertSource(true);
			this.setSourceZone(
				rule.getDestinations()
					.stream()
					.map(destination -> cleanZone(destination.getHost()))
					.collect(Collectors.joining(","))
			);
			this.setSourceSubZone(
				rule.getDestinations()
					.stream()
					.map(HostName::getHost)
					.map(label -> getNetworkModel().getMachineModel(label).orElseThrow().getIPs())
					.flatMap(Collection::stream)
					.map(ip -> ip.withoutPrefixLength().toCompressedString())
					.collect(Collectors.joining(","))
			);

			//Traffic's now coming to us
			this.setDestinationZone(
				rule.getDestinations()
					.stream()
					.map(destination -> cleanZone(destination.getHost()))
					.collect(Collectors.joining(","))
			);
			this.setDestinationSubZone(
				rule.getDestinations()
					.stream()
					.map(HostName::getHost)
					.map(label -> getNetworkModel().getMachineModel(label).orElseThrow().getIPs())
					.flatMap(Collection::stream)
					.map(ip -> ip.withoutPrefixLength().toCompressedString())
					.collect(Collectors.joining(","))
			);
			this.setDPorts(rule.getPorts());
			this.setProto(rule.getEncapsulation());
			this.setOrigDest(
				getNetworkModel().getMachineModel(rule.getSource())
					.orElseThrow()
					.getIPs()
			);
		}

		private void setMacro(String macro) {
			this.macro = macro;
		}

		private void setAction(Action action) {
			this.action = action;
		}

		private void setSourceZone(String sourceZone) {
			this.sourceZone = sourceZone;
		}

		private void setSourceSubZone(String sourceSubZone) {
			this.sourceSubZone = sourceSubZone;
		}

		private void setInvertSource(Boolean val) {
			this.invertSource = val;
		}

		private void setDestinationZone(String destinationZone) {
			this.destinationZone = destinationZone;
		}

		private void setDestinationSubZone(String destinationSubZone) {
			this.destinationSubZone = destinationSubZone;
		}

		private void setProto(Encapsulation proto) {
			this.proto = proto;
		}

		private void setDPorts(Collection<Integer> dPorts) {
			this.dPorts = dPorts;
		}

		private void setOrigDest(Collection<IPAddress> origDest) {
			this.origDest = origDest;
		}

		private void setRate(String rate) {
			this.rate = rate;
		}

		public String getRule() {
			String _action = (macro == null) ? action.toString() : macro+"("+action.toString()+")";
			String _dPorts = null;
			String _sPorts = null;
			String _origDest = null;
			String _sourceZone = sourceZone;
			String _destinationZone = destinationZone;
			
			if (this.invertSource) {
				_sourceZone = "all!" + sourceZone;
			}

			String _egress = this.destinationSubZone;
			if ((this.destinationSubZone != null)
					&& !(this.destinationSubZone.equals("*"))
					&& !(new HostName(this.destinationSubZone).isAddress())
					&& !(this.destinationSubZone.startsWith("&"))
					&& !(this.destinationSubZone.matches(".*\\.[0-9]+$"))) {
				_egress += ".";
			}
			if (_egress.equals("*")) {
				_egress = null;
			}

			if (dPorts != null) {
				_dPorts = dPorts.stream().map(Object::toString).collect(Collectors.joining(","));
			}
			if (sPorts != null) {
				_sPorts = sPorts.stream().map(Object::toString).collect(Collectors.joining(","));
			}
			if (origDest != null) {
				_origDest = this.origDest.stream().map(dest -> dest.withoutPrefixLength().toCompressedString())
						.collect(Collectors.joining(","));
			}

			String rule = "";
			rule += _action + "\t";
			rule += _sourceZone;
			rule += (sourceSubZone != null) ? ":" + sourceSubZone + "\t" : "\t";
			rule += _destinationZone;
			rule += (_egress != null) ? ":" + _egress + "\t" : "\t";
			rule += (proto != null) ? proto.toString().toLowerCase() + "\t" : "-\t";
			rule += (_dPorts != null) ? _dPorts + "\t" : "-\t";
			rule += (_sPorts != null) ? _sPorts + "\t" : "-\t";
			rule += (_origDest != null) ? _origDest + "\t" : "-\t";
			rule += (rate != null) ? rate : "";

			return rule;
		}
	}

	private class Comment extends ShorewallRule {
		private final String comment;

		public Comment(String comment) {
			this.comment = comment;
		}

		@Override
		public String getRule() {
			return "# " + this.comment;
		}
	}

	public ShorewallFirewall(ServerModel me) {
		super(me);
	}
	
	/**
	 * Zones must be a maximum of 10 alpha-numeric chars long
	 *
	 * @param zone The zone name to be cleaned
	 * @return valid zone name
	 */
	private String cleanZone(Object zone) {
		if (null == zone) {
			return null;
		}

		String _zone = zone.toString();
		String prefix = "";

		if (_zone.startsWith("$")) {
			prefix = "\\$";
		} else if (_zone.startsWith("!")) {
			prefix = "!";
		}

		_zone = StringUtils.stringToAlphaNumeric(_zone);

		// @TODO: Refactor this (we use it for MAC generation elsewhere...)
		if (_zone.length() > 10) {
			MessageDigest md = null;
			try {
				md = MessageDigest.getInstance("SHA-512");
			} catch (final NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

			assert md != null;
			md.update(zone.toString().getBytes());

			final byte[] byteData = md.digest();
			final StringBuilder hashCodeBuffer = new StringBuilder();
			for (final byte element : byteData) {
				hashCodeBuffer.append(Integer.toString((element & 0xff) + 0x100, 16).substring(1));

				if (hashCodeBuffer.length() > 3) {
					break;
				}
			}

			_zone = _zone.substring(0, 7) + hashCodeBuffer.substring(0, 3);
		}

		return prefix + _zone;
	}

	@Override
	public Collection<IUnit> getInstalled() throws ARuntimeException {
		final Collection<IUnit> units = new ArrayList<>();

		units.add(new InstalledUnit("shorewall", "proceed", "shorewall"));

		return units;
	}

	/**
	 * Builds our Maclist file as per http://shorewall.org/manpages/shorewall-maclist.html
	 * 
	 * This maclist file reflects the whole network
	 * 
	 * @return the contents of the maclist file
	 */
	private Collection<String> getMaclistFile() {
		final Collection<String> maclist = new ArrayList<>();

		getServerModel().getNetworkInterfaces()
		.stream()
		.filter(nic -> nic instanceof MACVLANTrunkModel)
		.map(MACVLANTrunkModel.class::cast)
		.forEach(nic -> {
			nic.getVLANs().forEach(vlan -> {
				maclist.addAll(machines2Maclist(vlan.getType()));
			});
		});

		return maclist;
	}

	private Collection<String> getHostsFile() {
		final Collection<String> hosts = new ArrayList<>();

		hosts.add("#Please see http://shorewall.net/manpages/shorewall-zones.html for more details");
		hosts.add("#zone\thosts\toptions");

		assert (null != getServerModel().getNetworkInterfaces());
		getServerModel().getNetworkInterfaces()
		.stream()
		.filter(nic -> nic instanceof MACVLANModel)
		.map(MACVLANModel.class::cast)
		.forEach(nic -> {
			hosts.addAll(machines2Host(nic.getType()));
		});

		return hosts;
	}

	private Collection<ShorewallRule> getRulesFile() throws InvalidServerException {
		Collection<ShorewallRule> rules = new ArrayList<>();

		// Iterate over every machine to build all of its rules
		getNetworkModel().getMachines().forEach((machine) -> {
			Comment machineComment = new Comment(machine.getLabel());
			rules.add(machineComment);

			if (null == machine.getFirewallRules() || machine.getFirewallRules().isEmpty()) {
				return;
			}

			machine.getFirewallRules().forEach(rule -> {
				try {
					rules.add(new ShorewallRule(rule));
				} catch (InvalidMachineModelException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			});
		});

		return rules;
	}

	/**
	 * Build our shorewall zones file.
	 *
	 * See http://shorewall.net/manpages/shorewall-zones.html for more details
	 *
	 * @return the zones file
	 */
	private FileUnit getZonesFile() {
		final FileUnit zones = new FileUnit("shorewall_zones", "shorewall_installed", CONFIG_BASEDIR + "/zones");

		zones.appendLine("#This is the file which creates our various zones");
		zones.appendLine("#Please see http://shorewall.net/manpages/shorewall-zones.html for more details");
		zones.appendLine("#zone\ttype");

		zones.appendLine("Internet\tipv4");

		getNetworkModel().getSubnets()
			.forEach( (subnet, machines) -> {
				zones.appendLine("#" + subnet.getVLAN());
				zones.appendLine(cleanZone(subnet.getVLAN()) + "\tipv4");

				machines.forEach( (machine) -> {
					zones.appendText(cleanZone(machine.getLabel()));
					zones.appendText(machine.getType().equals(Router.class)
										? ""
										: ":" + cleanZone(subnet.getVLAN())
					);
					zones.appendText(machine.getType().equals(Router.class)
										? "\tfirewall"
										: "\tipv4"
					);
					zones.appendText("\t#" + machine.getLabel());
					zones.appendCarriageReturn();
				});

				zones.appendCarriageReturn();
			});

		return zones;
	}

	@Override
	public Collection<IUnit> getLiveConfig() throws ARuntimeException {
		final Collection<IUnit> units = new ArrayList<>();

		units.add(getZonesFile());

		// Now assign machines their (sub)zone, and enforce our maclist
		final FileUnit hosts = new FileUnit("shorewall_hosts", "shorewall_interfaces", CONFIG_BASEDIR + "/hosts");
		hosts.appendLine(getHostsFile().toArray(String[]::new));

		units.add(hosts);

		final FileUnit maclist = new FileUnit("shorewall_maclist", "shorewall_hosts", CONFIG_BASEDIR + "/maclist");
		maclist.appendLine(getMaclistFile().toArray(String[]::new));

		units.add(maclist);

		// Finally, build our FW rules...
		final FileUnit rules = new FileUnit("shorewall_rules", "shorewall_hosts", CONFIG_BASEDIR + "/rules");
		try {
			rules.appendLine("ACCEPT\t\\$FW\t\\$FW"); //Talk to myself, please

			getRulesFile().forEach(rule -> {
				rules.appendLine(rule.getRule());
			});
		}
		catch (InvalidServerException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		units.add(rules);

		return units;
	}

	@Override
	public Collection<IUnit> getLiveFirewall() {
		return new ArrayList<>();
	}

	/**
	 * This is where we build our default rules
	 *
	 * @return a FileUnit with default blocking policies
	 */
	private FileUnit getPoliciesFile() {
		final FileUnit policies = new FileUnit("shorewall_policies", "shorewall_installed", CONFIG_BASEDIR + "/policy");
		policies.appendLine("#Default policies to use for intra-zone communication");
		policies.appendLine("#For specific rules, please look at " + CONFIG_BASEDIR + "/rules");
		policies.appendLine("#Please see http://shorewall.net/manpages/shorewall-policy.html for more details");
		policies.appendLine("#source\tdestination\taction");
		policies.appendLine("Internet\tall+\tDROP"); // DROP all ingress traffic
		policies.appendLine("all+\tall+\tREJECT"); // REJECT all other traffic

		return policies;
	}

	private FileUnit getInterfacesFile() {
		// Dedicate interfaces to parent zones
		final FileUnit interfaces = new FileUnit("shorewall_interfaces", "shorewall_policies",
				CONFIG_BASEDIR + "/interfaces");
		interfaces.appendLine("#Dedicate interfaces to parent zones");
		interfaces.appendLine("#Please see http://shorewall.net/manpages/shorewall-interfaces.html for more details");
		interfaces.appendLine("#zone\tinterface\tbroadcast\toptions");

		// First work out our Internet-facing NICs
		getServerModel().getNetworkInterfaces()
		.stream()
		.filter(nic -> Direction.WAN.equals(nic.getDirection()))
		.forEach(nic -> {
			interfaces.appendLine(buildInterfaceLine(nic));
		});

		// Then do everything else
		getServerModel().getNetworkInterfaces()
		.stream()
		.filter(nic -> Direction.LAN.equals(nic.getDirection()))
		.forEach(nic -> {
			interfaces.appendLine(buildInterfaceLine(nic));
		});

		return interfaces;
	}

	/**
	 * This turns a NetworkInterfaceModel into an interface line in Shorewall's
	 * config
	 * @param nic NetworkInterfaceModel
	 * @return the equivalent line for the interfaces file
	 */
	private String buildInterfaceLine(NetworkInterfaceModel nic) {
		String line = "";
		if (nic instanceof MACVLANModel) {
			line += cleanZone(((MACVLANModel) nic).getType().getVLAN());
		}
		else if (Direction.WAN.equals(nic.getDirection())) {
			line += "Internet";
		}
		line += "\t" + nic.getIface();
		line += "\t-\t";
		//If it's explicitly DHCP or it's on our LAN, it must talk DHCP
		line += (Inet.DHCP.equals(nic.getInet()) || Direction.LAN.equals(nic.getDirection())) ? "dhcp," : "";
		line += "routefilter,arp_filter";
		return line;
	}

	private FileUnit getMasqFile() {
		final FileUnit masq = new FileUnit("shorewall_masquerades", "shorewall_installed", CONFIG_BASEDIR + "/masq");

		getMachineModel().getNetworkInterfaces()
			.stream()
			.filter(nic -> Direction.WAN.equals(nic.getDirection()))
			.forEach(wanNIC -> {
				getServerModel().getNetworkInterfaces()
					.stream()
					.filter(n -> n instanceof MACVLANModel)
					.forEach(macVLAN -> {
						final String line = wanNIC.getIface() + "\t" + macVLAN.getIface();

						if (!masq.containsLine(line)) {
							masq.appendLine(line);
						}
					});
			});

		return masq;
	}

	@Override
	public Collection<IUnit> getPersistentConfig() throws ARuntimeException {
		final Collection<IUnit> units = new ArrayList<>();

		units.add(
			new FileEditUnit(
				"shorewall_implicit_continue_on",
				"shorewall_installed",
				"IMPLICIT_CONTINUE=No",
				"IMPLICIT_CONTINUE=Yes",
				"/etc/shorewall/shorewall.conf",
				"I couldn't enable implicit continue on your firewall - this means many of our firewall configurations will fail."
			)
		);
		units.add(getPoliciesFile());
		units.add(getInterfacesFile());
		units.add(getMasqFile());

		return units;
	}

	@Override
	public Collection<IUnit> getPersistentFirewall() throws AThornSecException {
		return new ArrayList<>();
	}

	/**
	 * Get a machine's IP addresses
	 *
	 * @param machine The machine whose IPs you wish to get
	 * @return a comma-delimited string of all IP addresses for a given machine
	 */
	private String getAddresses(AMachineModel machine) {
		final Collection<String> addresses = new ArrayList<>();

		machine.getNetworkInterfaces()
				.forEach(nic -> {
					nic.getAddresses().ifPresent(nicAddresses -> {
						nicAddresses.forEach(ip -> {
							addresses.add(ip.withoutPrefixLength().toString());
						});
					});
		});

		return String.join(",", addresses);
	}

	/**
	 * Turns a zone and an array of AMachineModels into the Shorewall hosts file format
	 *
	 * @param type the zone
	 * @return the hosts file contents
	 */
	private Collection<String> machines2Host(AMachineType type) {
		final Collection<String> hosts = new ArrayList<>();

		hosts.add("");
		hosts.add("#" + type.toString());

		getNetworkModel().getMachines(type)
			.forEach(machine -> {
				hosts.add(cleanZone(machine.getLabel())
					+ "\t" + type.getVLAN()
					+ ":" + getAddresses(machine)
					+ "\tmaclist");
			});

		return hosts;
	} 

	/**
	 * Parses machines into shorewall maclist lines
	 *
	 * @param type the machine type
	 * @return a Collection of Strings containing the maclist file lines
	 */
	private Collection<String> machines2Maclist(AMachineType type) {
		final Collection<String> maclist = new ArrayList<>();

		maclist.add("#" + type.getVLAN());

		getNetworkModel().getMachines(type)
			.forEach(machine ->
				machine.getNetworkInterfaces().stream()
					.filter(nic -> nic.getMac().isPresent())
					.filter(nic -> nic.getAddresses().isPresent())
					.forEach(nic -> {
						String mac = nic.getMac().get().toNormalizedString();
						String addresses = nic.getAddresses().get().stream()
											.map(IPAddress::withoutPrefixLength)
											.map(Object::toString)
											.collect(Collectors.joining(","));

						maclist.add("ACCEPT"
									+ "\t" + type.getVLAN()
									+ "\t" + mac
									+ "\t" + addresses
									+ "\t#" + machine.getLabel());
				})
			);

		return maclist;
	}
}
