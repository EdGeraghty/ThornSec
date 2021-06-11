/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.core.model.machine.configuration.networking;

import inet.ipaddr.IPAddress;
import inet.ipaddr.mac.MACAddress;
import org.privacyinternational.thornsec.core.data.machine.configuration.NetworkInterfaceData;
import org.privacyinternational.thornsec.core.data.machine.configuration.NetworkInterfaceData.Direction;
import org.privacyinternational.thornsec.core.data.machine.configuration.NetworkInterfaceData.Inet;
import org.privacyinternational.thornsec.core.exception.data.InvalidIPAddressException;
import org.privacyinternational.thornsec.core.exception.data.machine.configuration.InvalidNetworkInterfaceException;
import org.privacyinternational.thornsec.core.iface.IUnit;
import org.privacyinternational.thornsec.core.model.AModel;
import org.privacyinternational.thornsec.core.model.network.NetworkModel;
import org.privacyinternational.thornsec.core.unit.fs.FileUnit;

import java.util.*;

/**
 * This model represents a Network Interface Card (NIC) attached to our network.
 *
 * Whilst originally based on the traditional "SysVinit" /etc/network/interfaces
 * file, with Debian's continued march towards its successor Systemd, we have
 * migrated to utilise systemd-networkd.
 *
 * This provides portability to other GNU/Linux distributions, but was not a
 * decision which was taken lightly.
 *
 * For more information, see https://wiki.debian.org/Debate/initsystem/sysvinit
 */
public abstract class NetworkInterfaceModel extends AModel implements ISystemdNetworkd {

	protected enum Section {
		MATCH("Match"),
		LINK("Link"),
		NETWORK("Network"),
		ROUTE("Route"),
		ROUTINGPOLICYRULE("RoutingPolicyRule"),
		NETDEV("NetDev"),
		ADDRESS("Address"),
		MACVLAN("MACVLAN"),
		BOND("Bond");

		private final String section;

		Section(String section) {
			this.section = section;
		}

		@Override
		public String toString() {
			return this.section;
		}
	}

	private final NetworkModel networkModel;

	private String comment;
	private String iface;
	private Inet inet;
	private Direction direction;
	private Integer weighting;

	private Map<Section, Map<String, String>> netDevSettings;
	private Map<Section, Map<String, String>> networkSettings;

	private MACAddress mac;

	private Collection<IPAddress> addresses;
	private IPAddress subnet;
	private IPAddress netmask;
	private IPAddress broadcast;
	private IPAddress gateway;

	/**
	 * Creates a new NetworkInterfaceModel from the provided data
	 *
	 * Don't invoke me directly.
	 * @throws InvalidNetworkInterfaceException 
	 */
	protected NetworkInterfaceModel(NetworkInterfaceData ifaceData, NetworkModel networkModel) throws InvalidNetworkInterfaceException, InvalidIPAddressException {
		super(ifaceData);

		this.networkModel = networkModel;

		this.setIface(getLabel());

		this.setDirection(ifaceData.getDirection());
		this.setIface(ifaceData.getIface());
		this.setInet(ifaceData.getInet());

		if (ifaceData.getAddresses().isPresent()) {
			this.addAddress(ifaceData.getAddresses().get().toArray(IPAddress[]::new));
		}

		ifaceData.getBroadcast().ifPresent(this::setBroadcast);
		ifaceData.getComment().ifPresent(this::setComment);
		ifaceData.getGateway().ifPresent(this::setGateway);
		ifaceData.getMAC().ifPresent(this::setMac);
		ifaceData.getNetmask().ifPresent(this::setNetmask);
		ifaceData.getSubnet().ifPresent(this::setSubnet);
	}

	public NetworkModel getNetworkModel() {
		return networkModel;
	}

	/**
	 * Creates a new NetworkInterfaceModel, bringing 
	 *
	 * Don't invoke me directly.
	 * @throws InvalidNetworkInterfaceException 
	 */
	protected NetworkInterfaceModel(NetworkInterfaceModel nic) throws InvalidNetworkInterfaceException, InvalidIPAddressException {
		this(nic.getData(), nic.getNetworkModel());

		this.netDevSettings = nic.getNetDevSettings();
		this.networkSettings = nic.getNetworkSettings();
	}

	protected Map<Section, Map<String, String>> getNetDevSettings() {
		return this.netDevSettings;
	}

	protected Map<Section, Map<String, String>> getNetworkSettings() {
		return this.networkSettings;
	}

	@Override
	public NetworkInterfaceData getData() {
		return (NetworkInterfaceData) super.getData();
	}

	/**
	 * Files in systemd drop-in directories are loaded in lexicographic order
	 * by adding a double-digit weighting to the file, we can control the order
	 * in which they're read in.
	 * @return
	 */
	public String getWeighting() {
		return String.format("%02d", this.weighting);
	}

	/**
	 * Files in systemd drop-in directories are loaded in lexicographic order
	 * by adding a double-digit weighting to the file, we can control the order
	 * in which they're read in.
	 * @return
	 */
	public void setWeighting(Integer weighting) {
		this.weighting = weighting;
	}

	@Override
	public final Optional<Collection<IPAddress>> getAddresses() {
		return Optional.ofNullable(this.addresses);
	}

	public final Optional<IPAddress> getBroadcast() {
		return Optional.ofNullable(this.broadcast);
	}

	protected final Optional<String> getComment() {
		return Optional.ofNullable(this.comment);
	}

	@Override
	public final Optional<IPAddress> getGateway() {
		return Optional.ofNullable(this.gateway);
	}

	/**
	 * Get the interface's name
	 *
	 * @return interface's name
	 */
	public final String getIface() {
		return this.iface;
	}

	@Override
	public final Optional<MACAddress> getMac() {
		return Optional.ofNullable(this.mac);
	}

	public final IPAddress getSubnet() {
		return this.subnet;
	}

	public Inet getInet() {
		return this.inet;
	}

	/**
	 * Add (an) IP Address(es) to this Network Interface
	 * 
	 * @param addresses The address(es) to add
	 * @throws InvalidIPAddressException if attempting to set a null IP address
	 */
	public final void addAddress(IPAddress... addresses) throws InvalidIPAddressException {
		if (this.addresses == null) {
			this.addresses = new ArrayList<>();
		}

		for (final IPAddress address : addresses) {
			if (address == null) {
				throw new InvalidIPAddressException("One of your IP addresses "
						+ "for NIC " + getIface() + " is null");
			}

			this.addresses.add(address);
		}
	}

	public final void setBroadcast(IPAddress broadcast) {
		this.broadcast = broadcast;

//		addToNetwork(Section.ADDRESS, "Broadcast", broadcast.toCompressedString());
	}

	protected final void setComment(String comment) {
		this.comment = comment;
	}

	/**
	 * The gateway for this NIC
	 * @param gateway
	 */
	public final void setGateway(IPAddress gateway) {
		this.gateway = gateway;

		addToNetwork(Section.NETWORK, "Gateway", gateway.toCompressedString());
	}

	public void setIface(String iface) throws InvalidNetworkInterfaceException {
		if (null == iface || iface.isBlank()) {
			throw new InvalidNetworkInterfaceException("Your interface cannot be null or empty!");
		}

		this.iface = iface;

		addToNetDev(Section.NETDEV, "Name", iface);
		addToNetwork(Section.MATCH, "Name", iface);
	}

	protected void addToNetwork(Section section, String key, String value) {
		Map<String, String> sectionSettings = getNetworkSection(section);

		sectionSettings.put(key, value);

		setNetworkSection(section, sectionSettings);
	}

	protected void addToNetDev(Section section, String key, String value) {
		Map<String, String> sectionSettings = getNetDevSection(section);

		sectionSettings.put(key, value);

		setNetDevSection(section, sectionSettings);
	}

	/**
	 * If set true, the ARP (low-level Address Resolution Protocol) for this
	 * interface is enabled. When unset, the kernel's default will be used.
	 * 
	 * Disabling ARP is useful when creating multiple MACVLAN or VLAN virtual
	 * interfaces atop a single lower-level physical interface, which will then
	 * only serve as a link/"bridge" device aggregating traffic to the same
	 * physical link and not participate in the network otherwise.
	 * 
	 * https://www.freedesktop.org/software/systemd/man/systemd.network.html#ARP=
	 * @param value whether or not ARP is enabled for this interface
	 */
	public final void setARP(Boolean value) {
		addToNetwork(Section.LINK, "ARP", value);
	}

	protected void addToNetwork(Section section, String key, Boolean value) {
		addToNetwork(section, key, value ? "yes" : "no");
	}

	protected void addToNetDev(Section section, String key, Boolean value) {
		addToNetDev(section, key, value ? "yes" : "no");
	}

	/**
	 * Configures IP packet forwarding for the system.
	 * 
	 * If enabled, incoming packets on any network interface will be forwarded
	 * to any other interfaces according to the routing table.
	 * 
	 * This controls the net.ipv4.ip_forward and net.ipv6.conf.all.forwarding
	 * sysctl options of the network interface
	 * 
	 * Defaults to "no".
	 * 
	 * Note: this setting controls a global kernel option, and does so one way
	 * only: if a network that has this setting enabled is set up the global
	 * setting is turned on. However, it is never turned off again, even after
	 * all networks with this setting enabled are shut down again.
	 * https://www.freedesktop.org/software/systemd/man/systemd.network.html#IPForward=
	 * @param value
	 */
	public final void setIsIPForwarding(Boolean value) {
		addToNetwork(Section.NETWORK, "IPForward", value);
	}

	/**
	 * Configures IP masquerading for the network interface.
	 * 
	 * If enabled, packets forwarded from this network interface will be appear
	 * as coming from the local host.
	 * 
	 * Implies IPForward=ipv4.
	 * 
	 * Defaults to "no".
	 * @param ipMasquerading
	 */
	public final void setIsIPMasquerading(Boolean ipMasquerading) {
		addToNetwork(Section.NETWORK, "IPMasquerade", ipMasquerading);
	}

	public final void setMac(MACAddress mac) {
		this.mac = mac;
	}

	public final void setInet(Inet inet) {
		if (null == inet) {
			return;
		}

		this.inet = inet;

		addToNetDev(Section.NETDEV, "Kind", inet.toString());
	}

	protected final void setNetmask(IPAddress netmask) {
		this.netmask = netmask;
	}

	public void setSubnet(IPAddress subnet) {
		this.subnet = subnet;
	}

	public void setDirection(Direction direction) {
		this.direction = direction;
	}
	
	public Direction getDirection() {
		return this.direction;
	}

	public void setRoutingPolicyRuleFrom(IPAddress from) {
		addToNetwork(Section.ROUTINGPOLICYRULE, "From", from.toCompressedString());
	}

	public void setRoutingPolicyRuleTo(IPAddress to) {
		addToNetwork(Section.ROUTINGPOLICYRULE, "To", to.toCompressedString());
	}

	public void setGatewayOnLink(Boolean onLink) {
		addToNetwork(Section.ROUTE, "GatewayOnLink", onLink);
	}

	/**
	 * Get our Network File,
	 * <a href="https://www.freedesktop.org/software/systemd/man/systemd.network.html">
	 *     as described in the documentation</a>
	 */
	public Optional<FileUnit> getNetworkFile() {
		final FileUnit networkFile = new FileUnit(getIface() + "_network", "proceed",
				"/etc/systemd/network/" + getWeighting() + "-" + getIface() + ".network");

		if ( !this.networkSettings.isEmpty() ) {
			networkSettings.forEach((section, settings) -> {
				if ( ! networkFile.getLines().isEmpty() ) {
					networkFile.appendCarriageReturn();
				}

				networkFile.appendLine("[" + section.toString() + "]");

				//This is a special case, so handle it.
				if (section.equals(Section.NETWORK)) {
					getAddresses().ifPresent((addresses) ->	
						addresses.forEach((address) ->
							networkFile.appendLine("Address=" + address.toCompressedString())
						)
					);
				}

				settings.forEach((key, value) ->
					networkFile.appendLine(key + "=" + value)
				);
			});
		}
		return Optional.of(networkFile);
	}
	
	public Optional<FileUnit> getNetDevFile() {
		final FileUnit netDevFile = new FileUnit(getIface() + "_netdev", "proceed",
				"/etc/systemd/network/" + getWeighting() + "-" + getIface() + ".netdev");

		if ( !this.netDevSettings.isEmpty() ) {
			netDevSettings.forEach((section, settings) -> {
				if ( ! netDevFile.getLines().isEmpty() ) {
					netDevFile.appendCarriageReturn();
				}

				netDevFile.appendLine("[" + section.toString() + "]");

				settings.forEach((key, value) ->
					netDevFile.appendLine(key + "=" + value));
			});
		}
		return Optional.of(netDevFile);
	}

	private Map<String, String> getNetworkSection(Section section) {
		if (null == this.networkSettings) {
			this.networkSettings = new LinkedHashMap<>();
		}

		return this.networkSettings.getOrDefault(section, new LinkedHashMap<>());
	}

	private Map<String, String> getNetDevSection(Section section) {
		if (null == this.netDevSettings) {
			this.netDevSettings = new LinkedHashMap<>();
		}

		return this.netDevSettings.getOrDefault(section, new LinkedHashMap<>());
	}

	private boolean setNetworkSection(Section section, Map<String, String> settings) {
		return ( null == this.networkSettings.put(section, settings) );
	}

	private boolean setNetDevSection(Section section, Map<String, String> settings) {
		return ( null == this.netDevSettings.put(section, settings) );
	}

	protected boolean putNetworkSetting(Section section, String key, String value) {
		if (null == value) {
			return false;
		}

		Map<String, String> settings = getNetworkSection(section);
		settings.put(key, value);
		return setNetworkSection(section, settings);
	}

	protected boolean putNetDevSetting(Section section, String key, String value) {
		Map<String, String> settings = getNetDevSection(section);
		settings.put(key, value);
		return setNetDevSection(section, settings);
	}

	/**
	 * When true, this network will be deemed required when determining whether
	 * the system is online when running systemd-networkd-wait-online.
	 * 
	 * When false, this network is ignored when checking for online state.
	 * 
	 * The network will be brought up normally in either case, but in the event
	 * no address is assigned by DHCP or the cable is not plugged in, the link
	 * will simply remain offline and be skipped automatically when set false
	 * 
	 * Defaults to true if not explicitly set.
	 * 
	 * https://www.freedesktop.org/software/systemd/man/systemd.network.html#RequiredForOnline=
	 * @param reqdForOnline Sets whether link is required for its host to come
	 * "online". Defaults true.
	 */
	public void setReqdForOnline(Boolean reqdForOnline) {
		addToNetwork(Section.LINK, "RequiredForOnline", reqdForOnline);
	}

	/**
	 * Tell networkd to configure a specific link even if it has no carrier.
	 * 
	 * Defaults to false.
	 * If IgnoreCarrierLoss= is not explicitly set, it will default to this value
	 * 
	 * https://www.freedesktop.org/software/systemd/man/systemd.network.html#ConfigureWithoutCarrier=
	 * @param configureWithoutCarrier
	 */
	public void setConfigureWithoutCarrier(Boolean configureWithoutCarrier) {
		addToNetwork(Section.NETWORK, "ConfigureWithoutCarrier", configureWithoutCarrier);
	}

	@Override
	public Collection<IUnit> getUnits() {
		return new ArrayList<>();
	}
}
