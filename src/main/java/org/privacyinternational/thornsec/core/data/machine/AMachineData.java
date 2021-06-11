/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package org.privacyinternational.thornsec.core.data.machine;

import inet.ipaddr.AddressStringException;
import inet.ipaddr.HostName;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressString;
import org.privacyinternational.thornsec.core.data.AData;
import org.privacyinternational.thornsec.core.data.machine.configuration.NetworkInterfaceData;
import org.privacyinternational.thornsec.core.data.machine.configuration.TrafficRule;
import org.privacyinternational.thornsec.core.data.machine.configuration.TrafficRule.Encapsulation;
import org.privacyinternational.thornsec.core.data.machine.configuration.TrafficRule.Table;
import org.privacyinternational.thornsec.core.exception.data.ADataException;
import org.privacyinternational.thornsec.core.exception.data.InvalidIPAddressException;
import org.privacyinternational.thornsec.core.exception.data.InvalidPortException;
import org.privacyinternational.thornsec.core.exception.data.machine.InvalidEmailAddressException;
import org.privacyinternational.thornsec.core.exception.data.machine.configuration.InvalidNetworkInterfaceException;

import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonString;
import javax.json.JsonValue;
import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Abstract class for something representing a "Machine" on our network.
 *
 * A machine, at its most basic, is something with network interfaces. This
 * means it can also talk TCP and UDP, can be throttled, and has a name
 * somewhere in DNS-world.
 */
public abstract class AMachineData extends AData {
	protected String type;
	protected Set<String> profiles;

	private Map<String, NetworkInterfaceData> networkInterfaces;
	private Set<IPAddress> externalIPAddresses;
	private Set<String> cnames;

	// Alerting
	private InternetAddress emailAddress;

	private Boolean throttled;

	private Set<TrafficRule> trafficRules;

	private HostName domain;

	protected AMachineData(String label, Path filePath, JsonObject data) throws ADataException {
		super(label, filePath, data);
	}

	@Override
	public AMachineData read(JsonObject data) throws ADataException {
		super.read(data);

		readEmailAddress(data);
		readDomain(data);
		readCNAMEs(data);
		readFirewallRules(data);
		readProfiles(data);
		readType(data);

		return this;
	}

	private void readType(JsonObject data) {
		if (!data.containsKey("type")) {
			return;
		}

		setType(data.getString("type"));
	}

	public void setType(String type) {
		this.type = type;
	}
	/**
	 * Read in any firewall-related data
	 *
	 * @throws InvalidPortException if a requested port is outside the valid range
	 * @throws InvalidIPAddressException if a requested IP address isn't valid
	 */
	private void readFirewallRules(JsonObject data) throws InvalidPortException, InvalidIPAddressException {
		if (!data.containsKey("firewall")) {
			return;
		}

		readFirewallData(data.getJsonObject("firewall"));
	}

	/**
	 * Read in any CNAMEs which have been set in the data
	 */
	private void readCNAMEs(JsonObject data) {
		if (!data.containsKey("cnames")) {
			return;
		}

		if (null == this.cnames) {
			this.cnames = new HashSet<>();
		}

		data.getJsonArray("cnames").stream()
				.map(cname -> ((JsonString) cname).getString())
				.forEach(this::putCNAME);
	}

	/**
	 * Read in this machine's domain, as it may be different to the network's
	 */
	private void readDomain(JsonObject data) {
		if (!data.containsKey("domain")) {
			return;
		}

		setDomain(new HostName(data.getString("domain")));
	}

	/**
	 * Read in this machine's email address, if set
	 *
	 * @throws InvalidEmailAddressException if the email address is invalid
	 */
	private void readEmailAddress(JsonObject data) throws InvalidEmailAddressException {
		if (!data.containsKey("email")) {
			return;
		}

		setEmailAddress(data.getString("email"));
	}

	/**
	 * Set this machine's email address.
	 *
	 * @param address The email address for this machine
	 * @throws InvalidEmailAddressException if the email address isn't valid
	 */
	private void setEmailAddress(String address) throws InvalidEmailAddressException {
		try {
			setEmailAddress(new InternetAddress(address));
		} catch (AddressException e) {
			throw new InvalidEmailAddressException(getData().getString("email")
					+ " is an invalid email address");
		}
	}

	/**
	 * Set the email address for this Machine
	 *
	 * @param emailAddress The email address for this machine
	 */
	private void setEmailAddress(InternetAddress emailAddress) {
		this.emailAddress = emailAddress;
	}

	/**
	 * Read in listen rules for this machine. This punches holes in our Ingress
	 * table, allowing traffic to come into this machine on the requested port(s)
	 * in a given Encapsulation.
	 *
	 * @param encapsulation The packet encapsulation
	 * @param ports The port(s) on which to listen
	 * @throws InvalidPortException if a port is outside of the valid range
	 */
	private void readListenRules(Encapsulation encapsulation, JsonArray ports) throws InvalidPortException {
		Integer[] _ports = ports.stream()
				.map(port -> Integer.parseInt(port.toString()))
				.collect(Collectors.toList())
				.toArray(Integer[]::new);

		this.addTrafficRule(
			new TrafficRule.Builder()
					.withEncapsulation(encapsulation)
					.withDestination(new HostName(getLabel()))
					.withSource("*")
					.withPorts(_ports)
					.withTable(Table.INGRESS)
				.build()
		);
	}

	/**
	 * Read in firewall-related data
	 *
	 * @param firewallData The data object "firewall" associated with this machine
	 * @throws InvalidPortException
	 * @throws InvalidIPAddressException
	 */
	private void readFirewallData(JsonObject firewallData) throws InvalidPortException, InvalidIPAddressException {
		readThrottled(firewallData);
		readListens(firewallData);
		readForwards(firewallData);
		readDnats(firewallData);
		readIngresses(firewallData);
		readEgresses(firewallData);
		readExternalIPs(firewallData);
	}

	/**
	 * Read in any external IP addresses assigned to this machine
	 * @param firewallData the
	 * @throws InvalidIPAddressException
	 */
	private void readExternalIPs(JsonObject firewallData) throws InvalidIPAddressException {
		if (firewallData.containsKey("external_ip")) {
			putExternalIP(firewallData.getString("external_ip"));
		}
	}

	private void readEgresses(JsonObject firewallData) throws InvalidPortException {
		if (!firewallData.containsKey("allow_egress_to")) {
			return;
		}

		final JsonArray destinations = firewallData.getJsonArray("allow_egress_to");

		for (final JsonValue destination : destinations) {
			TrafficRule egressRule = new TrafficRule();
			egressRule.addDestination(new HostName(((JsonString) destination).getString()));
			egressRule.setSource(getLabel());

			this.addTrafficRule(egressRule);
		}
	}

	private void readIngresses(JsonObject firewallData) throws InvalidPortException {
		if (!firewallData.containsKey("allow_ingress_from")) {
			return;
		}
		final JsonArray sources = firewallData.getJsonArray("allow_ingress_from");

		for (final JsonValue source : sources) {
			TrafficRule ingressRule = new TrafficRule();
			ingressRule.setSource(((JsonString) source).getString());
			ingressRule.addDestination(new HostName(getLabel()));
			ingressRule.setTable(Table.INGRESS);

			this.addTrafficRule(ingressRule);
		}
	}

	private void readDnats(JsonObject firewallData) throws InvalidPortException {
		if (!firewallData.containsKey("dnat_to")) {
			return;
		}

		final JsonArray destinations = firewallData.getJsonArray("dnat_to");

		for (final JsonValue destination : destinations) {
			TrafficRule dnatRule = new TrafficRule();
			dnatRule.addDestination(new HostName(((JsonString) destination).getString()));
			dnatRule.setSource(getLabel());
			dnatRule.setTable(Table.DNAT);

			addTrafficRule(dnatRule);
		}
	}

	private void readForwards(JsonObject firewallData) throws InvalidPortException {
		if (firewallData.containsKey("allow_forward_to")) {
			final JsonArray forwards = firewallData.getJsonArray("allow_forward_to");

			for (final JsonValue forward : forwards) {
				TrafficRule forwardRule = new TrafficRule();
				forwardRule.addDestination(new HostName(((JsonString) forward).getString()));
				forwardRule.setTable(Table.FORWARD);

				this.addTrafficRule(forwardRule);
			}
		}
	}

	private void readListens(JsonObject firewallData) throws InvalidPortException {
		if (!firewallData.containsKey("listen")) {
			return;
		}

		final JsonObject listens = firewallData.getJsonObject("listen");

		if (listens.containsKey("tcp")) {
			readListenRules(Encapsulation.TCP, listens.getJsonArray("tcp"));
		}
		if (listens.containsKey("udp")) {
			readListenRules(Encapsulation.UDP, listens.getJsonArray("udp"));
		}
	}

	private void readThrottled(JsonObject firewallData) {
		if (!firewallData.containsKey("throttle")) {
			return;
		}

		this.throttled = firewallData.getBoolean("throttle");
	}

	public final Optional<Set<String>> getCNAMEs() {
		return Optional.ofNullable(this.cnames);
	}

	public Optional<HostName> getDomain() {
		return Optional.ofNullable(this.domain);
	}

	public final Set<TrafficRule> getTrafficRules() {
		return this.trafficRules;
	}

	public final Optional<InternetAddress> getEmailAddress() {
		return Optional.ofNullable(this.emailAddress);
	}

	public final Set<IPAddress> getExternalIPs() {
		return this.externalIPAddresses;
	}

	public final Optional<Map<String, NetworkInterfaceData>> getNetworkInterfaces() {
		return Optional.ofNullable(this.networkInterfaces);
	}

	public final Boolean isThrottled() {
		return this.throttled;
	}

	private void putCNAME(String cname) {
		this.cnames.add(cname);
	}

	/**
	 *
	 * @param ifaces
	 * @throws InvalidNetworkInterfaceException
	 */
	protected void putNetworkInterface(NetworkInterfaceData... ifaces) throws InvalidNetworkInterfaceException {
		if (this.networkInterfaces == null) {
			this.networkInterfaces = new LinkedHashMap<>();
		}

		for (final NetworkInterfaceData iface : ifaces) {
			if (this.networkInterfaces.containsKey(iface.getIface())) {
				throw new InvalidNetworkInterfaceException("Interfaces can only be declared once");
			}

			this.networkInterfaces.put(iface.getIface(), iface);
		}
	}

	private void addTrafficRule(TrafficRule rule) {
		if (null == this.trafficRules) {
			this.trafficRules = new HashSet<>();
		}

		this.trafficRules.add(rule);
	}

	private void putExternalIP(String address) throws InvalidIPAddressException {
		if (this.externalIPAddresses == null) {
			this.externalIPAddresses = new LinkedHashSet<>();
		}

		try {
			this.externalIPAddresses.add(new IPAddressString(address).toAddress());
		}
		catch (final AddressStringException e) {
			throw new InvalidIPAddressException(address + " on machine "
					+ getLabel() + " is not a valid IP Address");
		}
	}

	private void setDomain(HostName domain) {
		this.domain = domain;
	}

	/**
	 */
	protected void readProfiles(JsonObject data) {
		if (!data.containsKey("profiles")) {
			return;
		}

		data.getJsonArray("profiles").forEach(profile ->
			putProfile(((JsonString)profile).getString())
		);
	}

	public void putProfile(String... profiles) {
		if (this.profiles == null) {
			this.profiles = new LinkedHashSet<>();
		}

		this.profiles.addAll(Arrays.asList(profiles));
	}

	public final String getType() {
		return this.type;
	}

	public final Optional<Set<String>> getProfiles() {
		return Optional.ofNullable(this.profiles);
	}
}
