/*
 * This code is part of the ThornSec project.
 *
 * To learn more, please head to its GitHub repo: @privacyint
 *
 * Pull requests encouraged.
 */
package profile.machine.configuration;

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;

import core.iface.IUnit;
import core.model.network.NetworkModel;
import core.profile.AProfile;
import core.unit.SimpleUnit;

public class ConfigFiles extends AProfile {

	private final Collection<File> configFiles;

	public ConfigFiles(String label, NetworkModel networkModel) {
		super(label, networkModel);

		this.configFiles = new HashSet<>();
	}

	@Override
	public Collection<IUnit> getUnits() {
		String grepString = "sudo dpkg -V";
		final Collection<IUnit> units = new ArrayList<>();

		for (final File file : this.configFiles) {
			grepString += " | grep -Ev \"" + file.getPath() + "\"";
		}

		units.add(new SimpleUnit("no_config_file_tampering", "proceed", "", grepString, "", "pass",
				"There are unexpected config file edits on this machine.  This is a sign that someone has been configuring this machine by hand..."));

		return units;
	}

	public void addConfigFilePath(String path) {
		this.configFiles.add(new File(path));
	}
}
