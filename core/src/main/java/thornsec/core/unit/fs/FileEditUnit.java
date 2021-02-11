package core.unit.fs;

import core.unit.SimpleUnit;

public class FileEditUnit extends SimpleUnit {


	/**
	 * Unit test for in-place editing of a file, with custom fail message
	 * @param name            Name of the unit test (with _edited appended)
	 * @param precondition    Precondition unit test
	 * @param needleText      Text to search for
	 * @param replacementText Replacement text
	 * @param path            File to edit
	 * @param message         Custom fail message
	 */
	public FileEditUnit(String name, String precondition, String needleText, String replacementText, String path, String message) {
		super(name + "_edited", precondition,
				"sudo sed -i \"s|" + needleText + "|" + replacementText + "|g\" " + path,
				"grep \"" + replacementText + "\" " + path + ";", "", "fail",
				message);
	}

	/**
	 * Unit test for in-place editing of a file, with default fail message
	 * @param name            Name of the unit test (with _edited appended)
	 * @param precondition    Precondition unit test
	 * @param needleText      Text to search for
	 * @param replacementText Replacement text
	 * @param path            File to edit
	 */
	public FileEditUnit(String name, String precondition, String needleText, String replacementText, String path) {
		this(name, precondition, needleText, replacementText, path, "Couldn't replace " + needleText + " with " + replacementText + " in file " + path);
	}
}
