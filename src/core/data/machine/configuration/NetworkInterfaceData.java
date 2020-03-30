/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package core.data.machine.configuration;

import java.io.IOException;

import javax.json.JsonObject;
import javax.json.stream.JsonParsingException;

import core.data.AData;
import core.exception.data.ADataException;
import core.exception.data.InvalidIPAddressException;
import inet.ipaddr.AddressStringException;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddress.IPVersion;
import inet.ipaddr.IPAddressString;
import inet.ipaddr.MACAddressString;
import inet.ipaddr.mac.MACAddress;

/**
 * Represents a network interface. Its internal data represents
 * https://wiki.debian.org/NetworkConfiguration#iproute2_method which means we
 * can allow our admins to have fine-grained control over their ifaces!
 */
public class NetworkInterfaceData extends AData {
	public enum Direction {
		LAN, WAN;
	}

	public enum Inet {
		MANUAL("manual"), STATIC("static"), DHCP("dhcp"), MACVLAN("macvlan"), BOND("802.3ad"), PPP("PPPoE"),
		DUMMY("dummy");

		private String inet;

		Inet(String inet) {
			this.inet = inet;
		}

		public String getInet() {
			return this.inet;
		}
	}

	private String iface;
	private String comment;

	private Inet inet;
	private MACAddress mac;

	private IPAddress address;
	private IPAddress gateway;
	private IPAddress subnet;
	private IPAddress netmask;
	private IPAddress broadcast;

	public NetworkInterfaceData(String label) {
		super(label);

		this.iface = null;
		this.inet = Inet.STATIC;
		this.address = null;
		this.gateway = null;
		this.subnet = null;
		this.broadcast = null;
		this.mac = null;
		this.comment = null;
	}

	final public IPAddress getAddress() {
		return this.address;
	}

	final public IPAddress getBroadcast() {
		return this.broadcast;
	}

	final public String getComment() {
		return this.comment;
	}

	final public IPAddress getGateway() {
		return this.gateway;
	}

	final public String getIface() {
		return this.iface;
	}

	final public Inet getInet() {
		return this.inet;
	}

	final public MACAddress getMAC() {
		return this.mac;
	}

	final public IPAddress getNetmask() {
		return this.netmask;
	}

	final public IPAddress getSubnet() {
		return this.subnet;
	}

	@Override
	public void read(JsonObject data) throws ADataException, JsonParsingException, IOException {
		this.iface = data.getString("iface", null);

		if (data.containsKey("inet")) {
			setInet(Inet.valueOf(data.getString("inet").toUpperCase()));
		} else {
			setInet(Inet.STATIC);
		}

		try {
			if (data.containsKey("address")) {
				setAddress(new IPAddressString(data.getString("address")).toAddress(IPVersion.IPV4));
			}
			if (data.containsKey("subnet")) {
				setSubnet(new IPAddressString(data.getString("subnet")).toAddress(IPVersion.IPV4));
			}
			if (data.containsKey("broadcast")) {
				setBroadcast(new IPAddressString(data.getString("broadcast")).toAddress(IPVersion.IPV4));
			}
			if (data.containsKey("gateway")) {
				setGateway(new IPAddressString(data.getString("gateway")).toAddress(IPVersion.IPV4));
			}
		} catch (final AddressStringException e) {
			throw new InvalidIPAddressException(e.getMessage() + " is an invalid IP address");
		}
		if (data.containsKey("mac")) {
			setMAC(new MACAddressString(data.getString("mac")).getAddress());
		}
		if (data.containsKey("comment")) {
			setComment(data.getString("comment"));
		}
	}

	protected final void setAddress(IPAddress address) {
		this.address = address;
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

	protected final void setIface(String iface) {
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
