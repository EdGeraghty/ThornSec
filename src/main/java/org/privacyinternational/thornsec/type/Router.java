/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.type;

import inet.ipaddr.IPAddress;
import org.privacyinternational.thornsec.core.data.machine.configuration.NetworkInterfaceData.Direction;
import org.privacyinternational.thornsec.core.exception.AThornSecException;
import org.privacyinternational.thornsec.core.exception.data.InvalidIPAddressException;
import org.privacyinternational.thornsec.core.exception.data.machine.configuration.InvalidNetworkInterfaceException;
import org.privacyinternational.thornsec.core.iface.IUnit;
import org.privacyinternational.thornsec.core.model.machine.AMachineModel;
import org.privacyinternational.thornsec.core.model.machine.ServerModel;
import org.privacyinternational.thornsec.core.model.machine.configuration.networking.MACVLANModel;
import org.privacyinternational.thornsec.core.model.machine.configuration.networking.MACVLANTrunkModel;
import org.privacyinternational.thornsec.core.model.machine.configuration.networking.NetworkInterfaceModel;
import org.privacyinternational.thornsec.core.unit.SimpleUnit;
import org.privacyinternational.thornsec.core.unit.fs.FileUnit;
import org.privacyinternational.thornsec.core.unit.pkg.EnabledServiceUnit;
import org.privacyinternational.thornsec.core.unit.pkg.InstalledUnit;
import org.privacyinternational.thornsec.profile.dhcp.ADHCPServerProfile;
import org.privacyinternational.thornsec.profile.dhcp.ISCDHCPServer;
import org.privacyinternational.thornsec.profile.dns.ADNSServerProfile;
import org.privacyinternational.thornsec.profile.dns.UnboundDNSServer;
import org.privacyinternational.thornsec.profile.firewall.AFirewallProfile;
import org.privacyinternational.thornsec.profile.firewall.router.ShorewallFirewall;

import javax.json.stream.JsonParsingException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;

/**
 * This is a Router.
 *
 * This is where much of the security is enforced across the network. I've tried
 * to split it out as much as possible!
 *
 * If you want to make changes in here, you'll have a lot of reading to do :)!
 */
public class Router extends Server {
	private final ADNSServerProfile dnsServer;
	private final ADHCPServerProfile dhcpServer;
	private final AFirewallProfile firewall;

	private MACVLANTrunkModel vlanTrunk;

	public Router(ServerModel me) throws AThornSecException, JsonParsingException {
		super(me);

		this.vlanTrunk = null;

		masqueradeWANIfaces();
		buildLANIfaces();
		buildTrunk();

		//TODO: shouldn't be hardcoded
		this.firewall = new ShorewallFirewall(me);
		this.dhcpServer = new ISCDHCPServer(me);
		this.dnsServer = new UnboundDNSServer(me);
	}

	private void masqueradeWANIfaces() {
		getMachineModel().getNetworkInterfaces()
				.stream()
				.filter(nic ->
					Direction.WAN.equals(nic.getDirection())
				)
				.collect(Collectors.toSet())
				.forEach(nic ->
					nic.setIsIPMasquerading(true)
				);
	}

	private void buildLANIfaces() throws InvalidNetworkInterfaceException {
		Set<NetworkInterfaceModel> nics = getMachineModel().getNetworkInterfaces()
			.stream()
			.filter(nic -> Direction.LAN.equals(nic.getDirection()))
			.collect(Collectors.toSet());

		if (nics.isEmpty()) {
			throw new InvalidNetworkInterfaceException(getMachineModel().getLabel() + " needs a LAN-facing NIC");
		}
		else if (nics.size() > 1) {
			//TODO: Bonding ifaces is broken.
			throw new InvalidNetworkInterfaceException("We currently only support one LAN-facing NIC per Router");
		}
	}

	/**
	 * Builds our various VLANs, but only if they're required.
	 * @return a collection of the VLANs built in this method
	 * @throws InvalidIPAddressException if an IP address is invalid
	 * @throws InvalidNetworkInterfaceException
	 */
	private final MACVLANTrunkModel buildTrunk() throws InvalidNetworkInterfaceException, InvalidIPAddressException {
		NetworkInterfaceModel lanNIC = getMachineModel().getNetworkInterfaces()
				.stream()
				.filter(nic -> Direction.LAN.equals(nic.getDirection()))
				.collect(Collectors.toSet())
				.iterator()
				.next();

		lanNIC.setDirection(Direction.NONE); //You're not LAN facing any more!

		final MACVLANTrunkModel trunk = new MACVLANTrunkModel(lanNIC.getData(), getNetworkModel());
		getMachineModel().addNetworkInterface(trunk);

		this.vlanTrunk = trunk;

		return trunk;
	}

	private final void buildVLANs() throws InvalidNetworkInterfaceException, InvalidIPAddressException {
		List<AMachineType> toBuild = getNetworkModel().getMachines()
				.stream()
				.map(AMachineModel::getType)
				.filter(distinctByKey(t -> t.getVLAN()))
				.filter(t -> null != t.getVLANSubnet())
				.collect(Collectors.toList());

		for (AMachineType type : toBuild) {
			MACVLANModel vlan = new MACVLANModel(vlanTrunk.getData(), getNetworkModel());
			vlan.setIface(type.getVLAN());
			vlan.setSubnet(type.getVLANSubnet());
			vlan.addAddress(type.getVLANSubnet().getLowerNonZeroHost());
			vlan.setType(type);
			this.vlanTrunk.addVLAN(vlan);

			getMachineModel().addNetworkInterface(vlan);
		}
	}

	public ADHCPServerProfile getDHCPServer() {
		return this.dhcpServer;
	}

	public ADNSServerProfile getDNSServer() {
		return this.dnsServer;
	}

	public AFirewallProfile getFirewall() {
		return firewall;
	}

	@Override
	public Collection<IUnit> getInstalled() throws AThornSecException {
		final Collection<IUnit> units = new ArrayList<>();

		// Add useful tools for Routers here
		units.add(new InstalledUnit("traceroute", "proceed", "traceroute"));
		units.add(new InstalledUnit("speedtest_cli", "proceed", "speedtest-cli"));

		units.addAll(getDHCPServer().getInstalled());
		units.addAll(getDNSServer().getInstalled());
		units.addAll(getFirewall().getInstalled());

		return units;
	}

	@Override
	public Collection<IUnit> getLiveConfig() throws AThornSecException {
		final Collection<IUnit> units = new ArrayList<>();

		units.addAll(getDHCPServer().getLiveConfig());
		units.addAll(getDNSServer().getLiveConfig());
		units.addAll(getFirewall().getLiveConfig());

		return units;
	}

	@Override
	public Collection<IUnit> getLiveFirewall() throws AThornSecException {
		final Collection<IUnit> units = new ArrayList<>();

		units.addAll(getDHCPServer().getLiveFirewall());
		units.addAll(getDNSServer().getLiveFirewall());
		units.addAll(getFirewall().getLiveFirewall());

		return units;
	}

	@Override
	public Collection<IUnit> getPersistentConfig() throws AThornSecException {
		final Collection<IUnit> units = new ArrayList<>();

		buildVLANs();

		units.addAll(super.getNetworkInterfaceUnits());

		final FileUnit resolvConf = new FileUnit("leave_my_resolv_conf_alone", "proceed",
				"/etc/dhcp/dhclient-enter-hooks.d/leave_my_resolv_conf_alone", 
				"I couldn't stop various systemd services deciding to override your DNS settings."
						+ " This will cause you intermittent, difficult to diagnose problems as it randomly"
						+ " sets your DNS to wherever it decides. Great for laptops/desktops, atrocious for servers...");
		units.add(resolvConf);

		resolvConf.appendLine("make_resolv_conf() { :; }");

		// The trunk device needs to be set to Promiscuous mode, or else the Kernel can't see anything running over it.
		// As per https://wiki.archlinux.org/index.php/Network_configuration#Promiscuous_mode
		final FileUnit promiscuousService = new FileUnit("promiscuous_service", "proceed",
				"/etc/systemd/system/promiscuous@.service",
				"I failed at creating a SystemD service to set the trunk (LAN)"
				+ "Network Interface card to promiscuous mode. Your Router will"
				+ "not be able to route any internal traffic.");
		units.add(promiscuousService);

		promiscuousService.appendLine("[Unit]");
		promiscuousService.appendLine("Description=Set %i interface in promiscuous mode");
		promiscuousService.appendLine("After=network.target");
		promiscuousService.appendCarriageReturn();
		promiscuousService.appendLine("[Service]");
		promiscuousService.appendLine("Type=oneshot");
		promiscuousService.appendLine("ExecStart=/usr/bin/ip link set dev %i promisc on");
		promiscuousService.appendLine("RemainAfterExit=yes");
		promiscuousService.appendCarriageReturn();
		promiscuousService.appendLine("[Install]");
		promiscuousService.appendLine("WantedBy=multi-user.target");

		units.add(new SimpleUnit("promiscuous_mode_enabled_lan", "promiscuous_service",
				"sudo systemctl enable promiscuous@" + this.vlanTrunk.getIface() + ".service",
				"sudo systemctl is-enabled promiscuous@" + this.vlanTrunk.getIface() + ".service", "enabled", "pass",
				"I was unable to set " + this.vlanTrunk.getIface() + " to "
					+ "promiscuous mode. Your Router will not be able to route "
					+ "any internal traffic."));

		final FileUnit sysctl = new FileUnit("sysctl_conf", "proceed", "/etc/sysctl.conf");
		units.add(sysctl);

		sysctl.appendLine("net.ipv4.ip_forward=1");
		sysctl.appendLine("net.ipv6.conf.all.disable_ipv6=1");
		sysctl.appendLine("net.ipv6.conf.default.disable_ipv6=1");
		sysctl.appendLine("net.ipv6.conf.lo.disable_ipv6=1");
		// Stop our machine from spamming internal ARP requests on our external interface
		// See https://git.kernel.org/pub/scm/linux/kernel/git/davem/net.git/tree/Documentation/networking/ip-sysctl.txt#n1247
		sysctl.appendLine("net.ipv4.conf.all.arp_filter=1");
		sysctl.appendLine("net.ipv4.conf.default.arp_filter=1");
		// Set Reverse Path filtering to "strict"
		// See https://git.kernel.org/pub/scm/linux/kernel/git/davem/net.git/tree/Documentation/networking/ip-sysctl.txt#n1226
		sysctl.appendLine("net.ipv4.conf.all.rp_filter=1");
		sysctl.appendLine("net.ipv4.conf.default.rp_filter=1");

		// Switch systemd-networkd on...
		units.add(new EnabledServiceUnit("systemd_networkd", "proceed", "systemd-networkd", "I was unable to enable the networking service. This is bad!"));

		units.addAll(getDHCPServer().getPersistentConfig());
		units.addAll(getDNSServer().getPersistentConfig());
		units.addAll(getFirewall().getPersistentConfig());

		units.addAll(super.getPersistentConfig());

		return units;
	}

	@Override
	public Collection<IUnit> getPersistentFirewall() throws AThornSecException {
		final Collection<IUnit> units = new ArrayList<>();

		units.addAll(getDHCPServer().getPersistentFirewall());
		units.addAll(getDNSServer().getPersistentFirewall());
		units.addAll(getFirewall().getPersistentFirewall());

		units.addAll(super.getPersistentFirewall());

		return units;
	}

	@Override
	public String getVLAN() {
		return "";
	}

	@Override
	public IPAddress getVLANSubnet() {
		return null;
	}

	static <T> Predicate<T> distinctByKey(Function<? super T, ?> keyExtractor) {
		Map<Object,Boolean> seen = new ConcurrentHashMap<>();
		return t -> seen.putIfAbsent(keyExtractor.apply(t), Boolean.TRUE) == null;
	}
}
