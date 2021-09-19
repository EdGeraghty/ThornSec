/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.core.data.machine.configuration;

//import static org.junit.jupiter.api.Assertions.assertNotNull;

import inet.ipaddr.*;
import inet.ipaddr.IPAddress.IPVersion;
import inet.ipaddr.mac.MACAddress;
import org.privacyinternational.thornsec.core.data.AData;
import org.privacyinternational.thornsec.core.exception.data.ADataException;
import org.privacyinternational.thornsec.core.exception.data.InvalidIPAddressException;

import javax.json.JsonObject;
import java.nio.file.Path;
import java.util.Collection;
import java.util.HashSet;
import java.util.Optional;

/**
 * Represents a network interface. Its internal data represents
 * https://wiki.debian.org/NetworkConfiguration#iproute2_method which means we
 * can allow our admins to have fine-grained control over their ifaces!
 */
public class NetworkInterfaceData extends AData {
	public enum Direction {
		LAN, WAN, NONE
	}

	public enum Inet {
		MANUAL("manual"),
		STATIC("static"),
		DHCP("dhcp"),
		MACVLAN("macvlan"),
		BOND("bond"),
		PPP("PPPoE"),
		DUMMY("dummy"),
		WIREGUARD("wireguard");

		private final String inet;

		Inet(String inet) {
			this.inet = inet;
		}

		public String toString() {
			return this.inet;
		}
	}

	private String iface;
	private String comment;

	private Direction direction;
	private Inet inet;
	private MACAddress mac;

	private Collection<IPAddress> addresses;
	private IPAddress gateway;
	private IPAddress subnet;
	private IPAddress netmask;
	private IPAddress broadcast;

	public NetworkInterfaceData(String label, Path filePath, JsonObject data) throws ADataException {
		super(label, filePath, data);

		if (null == this.iface) {
			this.iface = label;
		}
	}

	@Override
	public NetworkInterfaceData read(JsonObject data) throws ADataException {
		super.read(data);

		readIface(data);
		readInet(data);
		readDirection(data);
		readAddress(data);
		readSubnet(data);
		readBroadcast(data);
		readNetmask(data);
		readGateway(data);
		readMAC(data);
		readComment(data);

		return this;
	}

	private void readIface(JsonObject data) {
		if (!data.containsKey("iface")) {
			return;
		}

		this.iface = data.getString("iface");
	}

	private void readNetmask(JsonObject data) throws InvalidIPAddressException {
		if (!data.containsKey("netmask")) {
			return;
		}

		try {
			setNetmask(new IPAddressString(data.getString("netmask")).toAddress(IPVersion.IPV4));
		} catch (AddressStringException | IncompatibleAddressException e) {
			throw new InvalidIPAddressException(data.getString("netmask"));
		}
	}

	/**
	 * @param data
	 */
	private void readComment(JsonObject data) {
		if (!data.containsKey("comment")) {
			return;
		}

		setComment(data.getString("comment"));
	}

	/**
	 * @param data
	 */
	private void readMAC(JsonObject data) {
		if (!data.containsKey("mac")) {
			return;
		}

		setMAC(new MACAddressString(data.getString("mac")).getAddress());
	}

	/**
	 * @param data
	 * @throws AddressStringException
	 * @throws IncompatibleAddressException
	 */
	private void readGateway(JsonObject data) throws InvalidIPAddressException {
		if (!data.containsKey("gateway")) {
			return;
		}

		try {
			setGateway(new IPAddressString(data.getString("gateway")).toAddress(IPVersion.IPV4));
		} catch (AddressStringException | IncompatibleAddressException e) {
			throw new InvalidIPAddressException(data.getString("gateway"));
		}
	}

	/**
	 * @param data
	 * @throws AddressStringException
	 * @throws IncompatibleAddressException
	 */
	private void readBroadcast(JsonObject data) throws InvalidIPAddressException {
		if (!data.containsKey("broadcast")) {
			return;
		}

		try {
			setBroadcast(new IPAddressString(data.getString("broadcast")).toAddress(IPVersion.IPV4));
		} catch (AddressStringException | IncompatibleAddressException e) {
			throw new InvalidIPAddressException(data.getString("broadcast"));
		}
	}

	/**
	 * @param data
	 * @throws AddressStringException
	 * @throws IncompatibleAddressException
	 */
	private void readSubnet(JsonObject data) throws InvalidIPAddressException {
		if (!data.containsKey("subnet")) {
			return;
		}

		try {
			setSubnet(new IPAddressString(data.getString("subnet")).toAddress(IPVersion.IPV4));
		} catch (AddressStringException | IncompatibleAddressException e) {
			throw new InvalidIPAddressException(data.getString("subnet"));
		}
	}

	/**
	 * @param data
	 */
	private void readAddress(JsonObject data) throws InvalidIPAddressException {
		if (!data.containsKey("address")) {
			return;
		}

		try {
			addAddress(new IPAddressString(data.getString("address")).toAddress(IPVersion.IPV4));
		} catch (AddressStringException | IncompatibleAddressException e) {
			throw new InvalidIPAddressException(data.getString("address"));
		}
	}

	/**
	 * @param data
	 */
	private void readDirection(JsonObject data) {
		if (!data.containsKey("direction")) {
			return;
		}

		setDirection(Direction.valueOf(data.getString("direction").toUpperCase()));
	}

	/**
	 * @param data
	 */
	private void readInet(JsonObject data) {
		if (!data.containsKey("inet")) {
			return;
		}

		setInet(Inet.valueOf(data.getString("inet").toUpperCase()));
	}

	final public void setDirection(Direction direction) {
		this.direction = direction;
	}

	final public Optional<Collection<IPAddress>> getAddresses() {
		return Optional.ofNullable(this.addresses);
	}

	final public Optional<IPAddress> getBroadcast() {
		return Optional.ofNullable(this.broadcast);
	}

	final public Optional<String> getComment() {
		return Optional.ofNullable(this.comment);
	}

	final public Optional<IPAddress> getGateway() {
		return Optional.ofNullable(this.gateway);
	}

	final public String getIface() {
		return this.iface;
	}
	
	final public Direction getDirection() {
		return this.direction;
	}

	final public Inet getInet() {
		return this.inet;
	}

	final public Optional<MACAddress> getMAC() {
		return Optional.ofNullable(this.mac);
	}

	final public Optional<IPAddress> getNetmask() {
		return Optional.ofNullable(this.netmask);
	}

	final public Optional<IPAddress> getSubnet() {
		return Optional.ofNullable(this.subnet);
	}

	/**
	 * 
	 * @param address
	 * @return true if the IP address was successfully added,
	 * 		  false if IP already exists on this interface 
	 */
	protected final Boolean addAddress(IPAddress address) {
		if (this.addresses == null) {
			this.addresses = new HashSet<>();
		}
		
		return this.addresses.add(address);
	}

	public final void addAddress(IPAddress... addresses) {
		for (IPAddress address : addresses) {
			addAddress(address);
		}
	}

	protected final void setBroadcast(IPAddress broadcast) {
		this.broadcast = broadcast;
	}

	protected final void setComment(String comment) {
		this.comment = comment;
	}

	protected final void setGateway(IPAddress gateway) {
		this.gateway = gateway;
	}

	public final void setIface(String iface) {
		this.iface = iface;
	}

	protected final void setInet(Inet inet) {
		this.inet = inet;
	}

	public final void setMAC(MACAddress mac) {
		this.mac = mac;
	}

	protected final void setNetmask(IPAddress netmask) {
		this.netmask = netmask;
	}

	protected final void setSubnet(IPAddress subnet) {
		this.subnet = subnet;
	}
}
