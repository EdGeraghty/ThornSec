package profile;

import java.util.Vector;

import core.iface.IUnit;
import core.model.NetworkModel;
import core.model.ServerModel;
import core.profile.AStructuredProfile;
import core.unit.SimpleUnit;
import core.unit.fs.DirUnit;
import core.unit.fs.FileAppendUnit;
import core.unit.fs.FileChecksumUnit;
import core.unit.fs.FileDownloadUnit;
import core.unit.fs.FileEditUnit;
import core.unit.fs.FileUnit;
import core.unit.pkg.InstalledUnit;
import core.unit.pkg.RunningUnit;

public class SVN extends AStructuredProfile {

	private PHP php;
	
	public SVN(ServerModel me, NetworkModel networkModel) {
		super("svn", me, networkModel);

		php = new PHP(me, networkModel);
	}

	protected Vector<IUnit> getInstalled() {
		Vector<IUnit> units = new Vector<IUnit>();
		
		units.addAll(php.getInstalled());
		
		units.addElement(new InstalledUnit("apache", "apache2"));
		units.addElement(new RunningUnit("apache", "apache2", "apache2"));
		((ServerModel)me).getProcessModel().addProcess("/usr/sbin/apache2 -k start$");
		
		units.addElement(new InstalledUnit("svn", "proceed", "subversion"));
		units.addElement(new InstalledUnit("ca_certificates", "proceed", "ca-certificates"));
		units.addElement(new InstalledUnit("libapache2_svn", "apache_installed", "libapache2-mod-svn"));
		units.addElement(new InstalledUnit("unzip", "proceed", "unzip"));
		units.addElement(new InstalledUnit("php_apache", "apache_installed", "libapache2-mod-php7.0"));

		return units;
	}
	
	protected Vector<IUnit> getPersistentConfig() {
		Vector<IUnit> units =  new Vector<IUnit>();
		
		units.addAll(php.getPersistentConfig());
		
		units.addAll(((ServerModel)me).getBindFsModel().addDataBindPoint("www", "proceed", "www-data", "www-data", "0750"));
		
		units.addElement(new SimpleUnit("apache_mod_headers_enabled", "apache_installed",
				"sudo a2enmod headers;",
				"sudo apache2ctl -M | grep headers", "", "fail"));
		
		units.addElement(new SimpleUnit("apache_mod_dav_enabled", "libapache2_svn_installed",
				"sudo a2enmod dav;",
				"sudo apache2ctl -M | grep dav", "", "fail"));

		units.addElement(new SimpleUnit("apache_mod_dav_fs_enabled", "libapache2_svn_installed",
				"sudo a2enmod dav_fs;",
				"sudo apache2ctl -M | grep dav_fs", "", "fail"));

		units.addElement(new SimpleUnit("apache_mod_auth_digest_enabled", "apache_installed",
				"sudo a2enmod auth_digest;",
				"sudo apache2ctl -M | grep auth_digest", "", "fail"));

		units.addElement(new SimpleUnit("apache_mod_dav_svn_enabled", "libapache2_svn_installed",
				"sudo a2enmod dav_svn;",
				"sudo apache2ctl -M | grep dav_svn", "", "fail"));
		
		//Turn off Apache version on error pages
		units.addElement(new FileAppendUnit("hide_apache_version_errors", "apache_installed",
				"ServerSignature Off",
				"/etc/apache2/apache2.conf",
				"Couldn't hide the Apache version on any potential error pages.  No real problem."));

		//Turn off Apache version in headers
		units.addElement(new FileAppendUnit("hide_apache_version_headers", "apache_installed",
				"ServerTokens Prod",
				"/etc/apache2/apache2.conf",
				"Couldn't hide the Apache version in its headers.  No real problem."));
		
		units.addAll(((ServerModel)me).getBindFsModel().addDataBindPoint("svn", "proceed", "www-data", "www-data", "0750"));

		units.addElement(new DirUnit("svn_repo_dir", "svn_data_mounted", "/media/data/svn/repos"));
		units.addElement(new DirUnit("svn_credentials_dir", "svn_data_mounted", "/media/data/svn/credentials"));
		
		units.addElement(new FileDownloadUnit("svn_admin", "apache_installed",
				"https://kent.dl.sourceforge.net/project/ifsvnadmin/svnadmin-1.6.2.zip",
				"/root/svnadmin.zip"));

		units.addElement(new FileChecksumUnit("svn_admin", "svn_admin_downloaded",
				"/root/svnadmin.zip",
				"065666dcddb96990b4bef37b5d6bf1689811eb3916a8107105935d9e6f8e05b9f99e6fdd8b4522dffab0ae8b17cfade80db891bd2a7ba7f49758f2133e4d26fa", "pass"));

		units.addElement(new SimpleUnit("svn_admin_unzipped", "svn_admin_checksum",
				"sudo unzip /root/svnadmin.zip -d /media/data/www/;"
				+ "sudo mv /media/data/www/iF.SVNAdmin-stable-1.6.2 /media/data/www/admin;",
				"[ -d /media/data/www/admin ] && echo pass;", "pass", "pass"));
		
		units.addElement(new FileEditUnit("svn_admin_php_version", "svn_admin_unzipped",
				"// Check PHP version.\n"
				+ "if (!checkPHPVersion(\"5.3\")) {",
				"if (false) { /* removed php version check */",
				"/media/data/www/admin/include/config.inc.php",
				"I couldn't change the expected PHP version in svnadmin. This means svnadmin will not work."));
		
		return units;
	}

	protected Vector<IUnit> getLiveConfig() {
		Vector<IUnit> units = new Vector<IUnit>();
		
		String apacheConf = "";
		apacheConf += "<VirtualHost *:80>\n";
		apacheConf += "    DocumentRoot /media/data/www\n";
		apacheConf += "    EnableSendfile off\n";
        apacheConf += "    <Directory \"/media/data/www\">\n";
        apacheConf += "        AllowOverride All\n";
        apacheConf += "        Require all granted\n";
        apacheConf += "    </Directory>\n";
        apacheConf += "</VirtualHost>";
        
		units.addElement(new FileUnit("default_apache_conf", "apache_installed", apacheConf, "/etc/apache2/sites-available/000-default.conf"));
		
		String davConf = "";
		davConf = "<Location /repos >\n";
		davConf += "	DAV svn\n";
		davConf += "	SVNListParentPath On\n";
		davConf += "	SVNParentPath /media/data/svn/repos\n";
		davConf += "	AuthType Digest\n";
		davConf += "	AuthName thornsecsvn\n";
		davConf += "	AuthUserFile /media/data/svn/credentials/svn.pass\n";
		davConf += "	AuthzSVNAccessFile /media/data/svn/credentials/svn.auth\n";
		davConf += "	Require valid-user\n";
		davConf += "</Location>";

		units.addElement(new FileUnit("apache_svn_conf", "apache_mod_dav_svn_enabled", davConf, "/etc/apache2/mods-available/dav_svn.conf"));
	
		units.addElement(new SimpleUnit("svn_admin_password", "apache_installed",
				"SVN_ADMIN_PASSWORD=`openssl rand -hex 32`;"
				+ "SVN_DIGEST=`echo -n \"admin:thornsecsvn:\" && echo -n \"admin:thornsecsvn:${SVN_ADMIN_PASSWORD}\" | md5sum | awk '{print $1}'`;" //Can't pass to htdigest so do it like this
				+ "echo 'SVN Admin password is:' ${SVN_ADMIN_PASSWORD};"
				+ "echo ${SVN_DIGEST} | sudo tee /media/data/svn/credentials/svn.pass > /dev/null;",
				"[ -f /media/data/svn/credentials/svn.pass ] && echo pass;", "pass", "pass"));

		String svnConf = "";
		svnConf += "[Common]\n";
		svnConf += "FirstStart=0\n";
		svnConf += "BackupFolder=./data/backup/\n";
		svnConf += "\n";
		svnConf += "[Translation]\n";
		svnConf += "Directory=./translations/\n";
		svnConf += "\n";
		svnConf += "[Engine:Providers]\n";
		svnConf += "AuthenticationStatus=basic\n";
		svnConf += "UserViewProviderType=digest\n";
		svnConf += "UserEditProviderType=digest\n";
		svnConf += "GroupViewProviderType=svnauthfile\n";
		svnConf += "GroupEditProviderType=svnauthfile\n";
		svnConf += "AccessPathViewProviderType=svnauthfile\n";
		svnConf += "AccessPathEditProviderType=svnauthfile\n";
		svnConf += "RepositoryViewProviderType=svnclient\n";
		svnConf += "RepositoryEditProviderType=svnclient\n";
		svnConf += "\n";
		svnConf += "[ACLManager]\n";
		svnConf += "UserRoleAssignmentFile=./data/userroleassignments.ini\n";
		svnConf += "\n";
		svnConf += "[Subversion]\n";
		svnConf += "SVNAuthFile=/media/data/svn/credentials/svn.auth\n";
		svnConf += "\n";
		svnConf += "[Repositories:svnclient]\n";
		svnConf += "SVNParentPath=/media/data/svn/repos\n";
		svnConf += "SvnExecutable=/usr/bin/svn\n";
		svnConf += "SvnAdminExecutable=/usr/bin/svnadmin\n";
		svnConf += "\n";
		svnConf += "[Users:digest]\n";
		svnConf += "SVNUserDigestFile=/media/data/svn/credentials/svn.pass\n";
		svnConf += "SVNDigestRealm=thornsecsvn\n";
		svnConf += "\n";
		svnConf += "[GUI]\n";
		svnConf += "RepositoryDeleteEnabled=false\n";
		svnConf += "RepositoryDumpEnabled=false\n";
		svnConf += "AllowUpdateByGui=true";

		units.addElement(new DirUnit("svn_admin_config_dir", "svn_admin_unzipped", "/media/data/www/admin/data/"));
		units.addElement(new FileUnit("svn_admin_config_file", "svn_admin_dir_created", svnConf, "/media/data/www/admin/data/config.ini"));
		
		units.addElement(new FileUnit("svn_auth_file", "svn_data_mounted", "", "/media/data/svn/credentials/svn.auth"));
		
		return units;
	}
	
	public Vector<IUnit> getNetworking() {
		Vector<IUnit> units = new Vector<IUnit>();

		me.addRequiredEgress("kent.dl.sourceforge.net", new Integer[]{443});
		
		return units;
	}

}
