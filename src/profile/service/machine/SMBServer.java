/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package profile.service.machine;

import java.util.ArrayList;
import java.util.Collection;

import core.data.machine.AMachineData.Encapsulation;
import core.exception.data.InvalidPortException;
import core.exception.runtime.InvalidServerModelException;
import core.iface.IUnit;
import core.model.machine.ServerModel;
import core.profile.AStructuredProfile;

public class SMBServer extends AStructuredProfile {

	public SMBServer(ServerModel me) {
		super(me);
	}

	@Override
	public Collection<IUnit> getPersistentFirewall() throws InvalidServerModelException, InvalidPortException {
		final Collection<IUnit> units = new ArrayList<>();

		getNetworkModel().getServerModel(getLabel()).addListen(Encapsulation.TCP, 137, 138, 139, 445);

		/*
		 * for (ServerModel router : getNetworkModel().getRouterServers()) {
		 *
		 * FirewallModel fm = router.getFirewallModel();
		 *
		 * fm.addFilter(getLabel() + "_fwd_ports_allow", me.getForwardChain(), "-p tcp"
		 * + " -m state --state NEW,ESTABLISHED,RELATED" +
		 * " -m tcp -m multiport --dports 139,445" + " -j ACCEPT", "Comment");
		 * fm.addFilter(getLabel() + "_fwd_ports_udp_allow", me.getForwardChain(),
		 * "-p udp" + " -m udp -m multiport --dports 137,138" + " -j ACCEPT",
		 * "Ccccomment");
		 *
		 * //Allow users to resolve/use internally for (DeviceModel device :
		 * getNetworkModel().getAllDevices()) { if (!device.getType().equals("user") &&
		 * !device.getType().equals("superuser")) { continue; }
		 *
		 * fm.addFilter("allow_int_resolve_" + getLabel(), device.getForwardChain(),
		 * " -d " + me.getSubnets() + "/30" + " -p tcp" + " -m state --state NEW" +
		 * " -m tcp -m multiport --dports 139,445" + " -j ACCEPT", "omment");
		 * fm.addFilter("allow_int_resolve_udp_" + getLabel(), device.getForwardChain(),
		 * " -d " + me.getSubnets() + "/30" + " -p udp" +
		 * " -m udp -m multiport --dports 137,138" + " -j ACCEPT", "Comment"); } }
		 */

		return units;
	}
}
