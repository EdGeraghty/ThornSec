package core.unit.fs;

import core.unit.SimpleUnit;

public class GitCloneUnit extends SimpleUnit {

	/**
	 * Unit test for cloning a git repository, with custom fail message
	 * @param name         Name of unit test (with _cloned appended)
	 * @param precondition Precondiiton unit test name
	 * @param url          Git repo url
	 * @param path         Path to clone to
	 * @param message      Custom fail message
	 */
	public GitCloneUnit(String name, String precondition, String url, String path, String message) {
		super(name + "_cloned", precondition,
				"sudo git config --global http.lowSpeedLimit 1000;"
				+ "sudo git config --global http.lowSpeedTime 10;"
				+ "sudo git clone " + url + " " + path,
				"sudo [ -d " + path + "/.git ] && echo pass || echo fail", "pass", "pass",
				message);
	}

	/**
	 * Unit test for cloning a git repository, with default fail message
	 * @param name         Name of unit test (with _cloned appended)
	 * @param precondition Precondiiton unit test name
	 * @param url          Git repo url
	 * @param path         Path to clone to
	 */
	public GitCloneUnit(String name, String precondition, String url, String path) {
		this(name, precondition, url, path, "Couldn't clone the repository " + url);
	}
	
}
