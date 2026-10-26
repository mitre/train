require "helper"
require "train/transports/mock"

class OsDetectTester
  include Train::Platforms::Detect::Helpers::OSCommon
end

describe "os_detect" do
  let(:detector) { OsDetectTester.new }

  def scan_with_files(uname, files)
    mock = Train::Transports::Mock::Connection.new
    mock.mock_command("uname -s", uname)
    mock.mock_command("uname -r", "test-release")

    yield mock if block_given?

    files.each do |path, data|
      mock.mock_command("test -f #{path}")
      mock.mock_command("test -f #{path} && cat #{path}", data)
    end

    Train::Platforms::Detect.scan(mock)
  end

  def scan_with_windows
    mock = Train::Transports::Mock::Connection.new
    mock.mock_command("cmd.exe /c ver", "Microsoft Windows [Version 6.3.9600]")
    Train::Platforms::Detect.scan(mock)
  end

  ## Detect all linux distros
  describe "/etc/enterprise-release" do
    it "sets the correct family/release for oracle" do
      path = "/etc/enterprise-release"
      platform = scan_with_files("linux", { path => "release 7" })

      _(platform[:name]).must_equal("oracle")
      _(platform[:family]).must_equal("redhat")
      _(platform[:release]).must_equal("7")
    end
  end

  describe "/etc/redhat-release" do
    describe "and /etc/os-release" do
      it "sets the correct family, name, and release on centos" do
        files = {
          "/etc/redhat-release" => "CentOS Linux release 7.2.1511 (Core) \n",
          "/etc/os-release" => "NAME=\"CentOS Linux\"\nVERSION=\"7 (Core)\"\nID=\"centos\"\nID_LIKE=\"rhel fedora\"\n",
        }
        platform = scan_with_files("linux", files)
        _(platform[:name]).must_equal("centos")
        _(platform[:family]).must_equal("redhat")
        _(platform[:release]).must_equal("7.2.1511")
      end
      it "sets the correct family, name, and release on scientific linux" do
        files = {
          "/etc/redhat-release" => "Scientific Linux release 7.4 (Nitrogen)\n",
          "/etc/os-release" => "NAME=\"Scientific Linux\"\nVERSION=\"7.4 (Nitrogen)\"\nID=\"rhel\"\nID_LIKE=\"scientific centos fedora\"\nVERSION_ID=\"7.4\"\nPRETTY_NAME=\"Scientific Linux 7.4 (Nitrogen)\"\nANSI_COLOR=\"0;31\"\nCPE_NAME=\"cpe:/o:scientificlinux:scientificlinux:7.4:GA\"\nHOME_URL=\"http://www.scientificlinux.org//\"\nBUG_REPORT_URL=\"mailto:scientific-linux-devel@listserv.fnal.gov\"\n\nREDHAT_BUGZILLA_PRODUCT=\"Scientific Linux 7\"\nREDHAT_BUGZILLA_PRODUCT_VERSION=7.4\nREDHAT_SUPPORT_PRODUCT=\"Scientific Linux\"\nREDHAT_SUPPORT_PRODUCT_VERSION=\"7.4\"\n",
        }
        platform = scan_with_files("linux", files)
        _(platform[:name]).must_equal("scientific")
        _(platform[:family]).must_equal("redhat")
        _(platform[:release]).must_equal("7.4")
      end
      it "sets the correct family, name, and release on CloudLinux" do
        files = {
          "/etc/redhat-release" => "CloudLinux release 7.4 (Georgy Grechko)\n",
          "/etc/os-release" => "NAME=\"CloudLinux\"\nVERSION=\"7.4 (Georgy Grechko)\"\nID=\"cloudlinux\"\nID_LIKE=\"rhel fedora centos\"\nVERSION_ID=\"7.4\"\nPRETTY_NAME=\"CloudLinux 7.4 (Georgy Grechko)\"\nANSI_COLOR=\"0;31\"\nCPE_NAME=\"cpe:/o:cloudlinux:cloudlinux:7.4:GA:server\"\nHOME_URL=\"https://www.cloudlinux.com//\"\nBUG_REPORT_URL=\"https://www.cloudlinux.com/support\"\n",
        }
        platform = scan_with_files("linux", files)
        _(platform[:name]).must_equal("cloudlinux")
        _(platform[:family]).must_equal("redhat")
        _(platform[:release]).must_equal("7.4")
      end
      it "sets the correct family, name, and release on SLES ESR RHEL" do
        files = {
          "/etc/redhat-release" => "Red Hat Enterprise Linux Server release 7.4 (Maipo)\n# This is a \"SLES Expanded Support platform release 7.4\"\n# The above \"Red Hat Enterprise Linux Server\" string is only used to \n# keep software compatibility.\n",
          "/etc/os-release" => "NAME=\"Red Hat Enterprise Linux Server\"\nVERSION=\"7.4 (Maipo)\"\nID=\"rhel\"\nID_LIKE=\"fedora\"\nVERSION_ID=\"7.4\"\nPRETTY_NAME=\"Red Hat Enterprise Linux Server 7.4\"\nANSI_COLOR=\"0;31\"\nCPE_NAME=\"cpe:/o:redhat:enterprise_linux:7.4:GA:server\"\nHOME_URL=\"https://www.redhat.com/\"\nBUG_REPORT_URL=\"https://bugzilla.redhat.com/\"\n\nREDHAT_BUGZILLA_PRODUCT=\"Red Hat Enterprise Linux 7\"\nREDHAT_BUGZILLA_PRODUCT_VERSION=7.4\nREDHAT_SUPPORT_PRODUCT=\"Red Hat Enterprise Linux\"\nREDHAT_SUPPORT_PRODUCT_VERSION=7.4\n# This is a \"SLES Expanded Support platform release 7.4\"\n# The above \"Red Hat Enterprise Linux Server\" string is only used to\n# keep software compatibility.\n",
        }
        platform = scan_with_files("linux", files)
        _(platform[:name]).must_equal("redhat")
        _(platform[:family]).must_equal("redhat")
        _(platform[:release]).must_equal("7.4")
      end
    end
  end

  describe "darwin" do
    describe "mac_os_x" do
      it "sets the correct family, name, and release on macOS < 11" do
        files = {
          "/System/Library/CoreServices/SystemVersion.plist" => "<string>Mac OS X</string>",
        }
        platform = scan_with_files("darwin", files)
        _(platform[:name]).must_equal("mac_os_x")
        _(platform[:family]).must_equal("darwin")
        _(platform[:release]).must_equal("test-release")
      end

      it "sets the correct family, name, and release on macOS >= 11" do
        files = {
          "/System/Library/CoreServices/SystemVersion.plist" => "<string>macOS</string>",
        }
        platform = scan_with_files("darwin", files)
        _(platform[:name]).must_equal("mac_os_x")
        _(platform[:family]).must_equal("darwin")
        _(platform[:release]).must_equal("test-release")
      end
    end

    describe "generic darwin" do
      it "sets the correct family, name, and release on darwin" do
        files = {
          "/usr/bin/sw_vers" => "ProductVersion: 17.0.1\nBuildVersion: alpha.x1",
        }
        platform = scan_with_files("darwin", files) do |mock|
          mock.mock_command("sw_vers -buildVersion", "12345\n")
        end
        _(platform[:name]).must_equal("darwin")
        _(platform[:family]).must_equal("darwin")
        _(platform[:release]).must_equal("test-release")
        _(platform[:build]).must_equal("12345")
      end
    end
  end

  describe "/etc/debian_version" do
    def debian_scan(id, version)
      lsb_release = "DISTRIB_ID=#{id}\nDISTRIB_RELEASE=#{version}"
      files = {
        "/etc/lsb-release" => lsb_release,
        "/etc/debian_version" => "11",
      }
      scan_with_files("linux", files)
    end

    describe "ubuntu" do
      it "sets the correct family/release for ubuntu" do
        platform = debian_scan("ubuntu", "16.04")

        _(platform[:name]).must_equal("ubuntu")
        _(platform[:family]).must_equal("debian")
        _(platform[:release]).must_equal("16.04")
      end
    end

    describe "linuxmint" do
      it "sets the correct family/release for linuxmint" do
        platform = debian_scan("linuxmint", "12")

        _(platform[:name]).must_equal("linuxmint")
        _(platform[:family]).must_equal("debian")
        _(platform[:release]).must_equal("12")
      end
    end

    describe "kali" do
      it "sets the correct family/release for kali" do
        os_release = "PRETTY_NAME=\"Kali GNU/Linux Rolling\"\nNAME=\"Kali GNU/Linux\"\nID=kali\nVERSION=\"2019.4\"\nVERSION_ID=\"2019.4\"\nVERSION_CODENAME=\"kali-rolling\"\nID_LIKE=debian\nANSI_COLOR=\"1;31\"\nHOME_URL=\"https://www.kali.org/\"\nSUPPORT_URL=\"https://forums.kali.org/\"\nBUG_REPORT_URL=\"https://bugs.kali.org/\"\n"
        files = {
          "/etc/os-release" => os_release,
          "/etc/debian_version" => "kali-rolling",
        }
        platform = scan_with_files("linux", files)
        _(platform[:name]).must_equal("kali")
        _(platform[:family]).must_equal("debian")
        _(platform[:release]).must_equal("2019.4")
      end
    end

    describe "raspbian" do
      it "sets the correct family/release for raspbian " do
        files = {
          "/usr/bin/raspi-config" => "data",
          "/etc/debian_version" => "13.6",
        }
        platform = scan_with_files("linux", files)

        _(platform[:name]).must_equal("raspbian")
        _(platform[:family]).must_equal("debian")
        _(platform[:release]).must_equal("13.6")
      end
    end

    describe "windows" do
      it "sets the correct family/release for windows " do
        platform = scan_with_windows

        _(platform[:name]).must_equal("windows_6.3.9600")
        _(platform[:family]).must_equal("windows")
        _(platform[:release]).must_equal("6.3.9600")
      end
    end

    describe "everything else" do
      it "sets the correct family/release for debian " do
        platform = debian_scan("some_debian", "12.99")

        _(platform[:name]).must_equal("debian")
        _(platform[:family]).must_equal("debian")
        _(platform[:release]).must_equal("11")
      end
    end
  end

  describe "windows" do
    it "sets the correct family/release for windows " do
      platform = scan_with_windows

      _(platform[:name]).must_equal("windows_6.3.9600")
      _(platform[:family]).must_equal("windows")
      _(platform[:release]).must_equal("6.3.9600")
    end
  end

  describe "/etc/coreos/update.conf" do
    it "sets the correct family/release for coreos" do
      lsb_release = "DISTRIB_ID=Container Linux by CoreOS\nDISTRIB_RELEASE=27.9"
      files = {
        "/etc/lsb-release" => lsb_release,
        "/etc/coreos/update.conf" => "data",
      }
      platform = scan_with_files("linux", files)

      _(platform[:name]).must_equal("coreos")
      _(platform[:family]).must_equal("linux")
      _(platform[:release]).must_equal("27.9")
    end
  end

  describe "/etc/os-release" do
    describe "when not on a wrlinux build" do
      it "fail back to generic linux" do
        os_release = "ID_LIKE=cisco-unkwown\nVERSION=unknown"
        files = {
          "/etc/os-release" => os_release,
        }
        platform = scan_with_files("linux", files)

        _(platform[:name]).must_equal("linux")
        _(platform[:family]).must_equal("linux")
      end
    end

    describe "when on a wrlinux build" do
      it "sets the correct family/release for wrlinux" do
        os_release = "ID_LIKE=cisco-wrlinux\nVERSION=cisco123"
        files = {
          "/etc/os-release" => os_release,
        }
        platform = scan_with_files("linux", files)

        _(platform[:name]).must_equal("wrlinux")
        _(platform[:family]).must_equal("redhat")
        _(platform[:release]).must_equal("cisco123")
      end
    end

    describe "when on a suse build" do
      describe "when /etc/os-release is present" do
        it "sets the correct family/release for SLES" do
          files = {
            "/etc/os-release" => "NAME=\"SLES\"\nVERSION=\"15.1\"\nID=\"sles\"\nID_LIKE=\"suse\"\n",
          }
          platform = scan_with_files("linux", files)

          _(platform[:name]).must_equal("suse")
          _(platform[:family]).must_equal("suse")
          _(platform[:release]).must_equal("15.1")
        end

        it "sets the correct family/release for openSUSE" do
          files = {
            "/etc/os-release" => "NAME=\"openSUSE Leap\"\nVERSION=\"15.1\"\nID=\"opensuse-leap\"\nID_LIKE=\"suse opensuse\"\n",
          }
          platform = scan_with_files("linux", files)

          _(platform[:name]).must_equal("opensuse")
          _(platform[:family]).must_equal("suse")
          _(platform[:release]).must_equal("15.1")
        end
      end
      describe "when /etc/os-release is not present" do
        it "sets the correct family/release for SLES" do
          files = {
            "/etc/SuSE-release" => "SUSE Linux Enterprise Server 11 (x86_64)\nVERSION = 11\nPATCHLEVEL = 2",
          }
          platform = scan_with_files("linux", files)

          _(platform[:name]).must_equal("suse")
          _(platform[:family]).must_equal("suse")
          _(platform[:release]).must_equal("11.2")
        end

        it "sets the correct family/release for openSUSE" do
          files = {
            "/etc/SuSE-release" => "openSUSE 10.2 (x86_64)\nVERSION = 10.2",
          }
          platform = scan_with_files("linux", files)

          _(platform[:name]).must_equal("opensuse")
          _(platform[:family]).must_equal("suse")
          _(platform[:release]).must_equal("10.2")
        end
      end
    end

    describe "when on a Wolfi build" do
      it "sets the correct family/release for Wolfi OS" do
        os_release = "ID=wolfi\nVERSION_ID=20230201"
        files = {
          "/etc/os-release" => os_release,
        }
        platform = scan_with_files("linux", files)

        _(platform[:name]).must_equal("wolfi")
        _(platform[:family]).must_equal("chainguard")
        _(platform[:release]).must_equal("20230201")
      end
    end

    describe "when on a Chainguard build" do
      it "sets the correct family/release for Chainguard OS" do
        os_release = "ID=chainguard\nVERSION_ID=20230214"
        files = {
          "/etc/os-release" => os_release,
        }
        platform = scan_with_files("linux", files)

        _(platform[:name]).must_equal("chainguard")
        _(platform[:family]).must_equal("chainguard")
        _(platform[:release]).must_equal("20230214")
      end
    end
  end

  describe "yocto" do
    it "sets the correct family, name, and release on yocto" do
      files = {
        "/etc/issue" => "Poky (Yocto Project Reference Distro) 2.7 \\n \\l",
      }
      platform = scan_with_files("linux", files)
      _(platform[:name]).must_equal("yocto")
      _(platform[:family]).must_equal("yocto")
      _(platform[:release]).must_equal("2.7")
    end
  end

  describe "balenaos" do
    it "sets the correct family, name, and release on balenaos" do
      files = {
        "/etc/issue" => "balenaOS 2.46.1 \n \l",
        "/etc/os-release" => "ID=\"balena-os\"\nNAME=\"balenaOS\"\nVERSION=\"2.46.1+rev1\"\nVERSION_ID=\"2.46.1+rev1\"\nPRETTY_NAME=\"balenaOS 2.46.1+rev1\"\nMACHINE=\"raspberrypi3\"\nVARIANT=\"Development\"\nVARIANT_ID=\"dev\"\nMETA_BALENA_VERSION=\"2.46.1\"\nRESIN_BOARD_REV=\"e194600\"\nMETA_RESIN_REV=\"f2295d2\"\nSLUG=\"raspberrypi3\"\n",
      }
      platform = scan_with_files("linux", files)
      _(platform[:name]).must_equal("balenaos")
      _(platform[:family]).must_equal("yocto")
      _(platform[:release]).must_equal("2.46.1")
    end
  end

  describe "qnx" do
    it "sets the correct info for qnx platform" do
      platform = scan_with_files("qnx", {})

      _(platform[:name]).must_equal("qnx")
      _(platform[:family]).must_equal("qnx")
      _(platform[:release]).must_equal("test-release")
    end
  end

  describe "cisco" do
    it "recognizes Cisco IOS12" do
      mock = Train::Transports::Mock::Connection.new
      mock.mock_command("show version", "Cisco IOS Software, C3750E Software (C3750E-UNIVERSALK9-M), Version 12.2(58)SE")
      platform = Train::Platforms::Detect.scan(mock)

      _(platform[:name]).must_equal("cisco_ios")
      _(platform[:family]).must_equal("cisco")
      _(platform[:release]).must_equal("12.2")
    end

    it "recognizes Cisco IOS XE" do
      mock = Train::Transports::Mock::Connection.new
      mock.mock_command("show version", "Cisco IOS Software, IOS-XE Software, Catalyst L3 Switch Software (CAT3K_CAA-UNIVERSALK9-M), Version 03.03.03SE RELEASE SOFTWARE (fc2)")
      platform = Train::Platforms::Detect.scan(mock)

      _(platform[:name]).must_equal("cisco_ios_xe")
      _(platform[:family]).must_equal("cisco")
      _(platform[:release]).must_equal("03.03.03SE")
    end

    # Real `show version` lines and the platform each should give. Rows marked "genie" are
    # from Cisco's genieparser golden ShowVersion outputs (Apache-2.0,
    # https://github.com/CiscoTestAutomation/genieparser, src/genie/libs/parser/{ios,iosxe}/
    # tests/ShowVersion/cli/equal/<file>); the Catalyst 9300 rows are from Cisco's 17.14
    # release notes; the IOL rows are from Cisco Modeling Labs IOL nodes.
    cisco_banners = [
      # Not captured banners. Cisco names the SD-WAN image "Cisco IOS XE SD-WAN Software" in
      # its advisories, and genieparser's ShowVersion parser reads any words between "Cisco"
      # and "Software, Version"; the release comes from that line as on other IOS XE.
      ["IOS XE SD-WAN version line (synthetic)", "Cisco IOS XE SD-WAN Software, Version 16.12.01d.0.27\nCisco IOS Software [Gibraltar], ISR Software (X86_64_LINUX_IOSD-UCMK9-M), Version 16.12.1d, RELEASE SOFTWARE (fc2)", "cisco_ios_xe", "16.12.01"],
      # Classic IOS whose login banner mentions IOS XE: an IOS XE line only counts directly
      # above the IOS line, where IOS XE prints it.
      ["classic IOS with IOS XE named in its banner (synthetic)", "Moving to Cisco IOS XE Software, Version 17.9.4 on Monday\r\n\r\nCisco IOS Software, C3750E Software (C3750E-UNIVERSALK9-M), Version 12.2(58)SE, RELEASE SOFTWARE (fc1)", "cisco_ios", "12.2"],
      ["IOS XE with IOS XE named in its banner (synthetic)", "Moving to Cisco IOS XE Software, Version 17.9.4 on Monday\r\n\r\nCisco IOS XE Software, Version 17.13.01\r\nCisco IOS Software [Dublin], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.13.1, RELEASE SOFTWARE (fc1)", "cisco_ios_xe", "17.13.01"],
      ["IOL with an IOS XE version named in its banner (synthetic)", "Moving to Cisco IOS XE Software, Version 17.9.4 on Monday\r\nWelcome\r\n\r\nCisco IOS Software [IOSXE], Linux Software (X86_64BI_LINUX-ADVENTERPRISEK9-M), Version 17.15.1, RELEASE SOFTWARE (fc4)", "cisco_ios_xe", "17.15.1"],
      ["IOS XE line above a blank line and the IOS line (synthetic)", "Cisco IOS XE Software, Version 17.13.01\r\n\r\nCisco IOS Software [Dublin], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.13.1, RELEASE SOFTWARE (fc1)", "cisco_ios_xe", "17.13.01"],
      ["classic IOS followed by text naming IOS XE (synthetic)", "Cisco IOS Software, C3750E Software (C3750E-UNIVERSALK9-M), Version 12.2(58)SE, RELEASE SOFTWARE (fc1)\r\nCisco IOS XE Software, Version 17.9.4", "cisco_ios", "12.2"],
      # As 3.16.5 did, uppercase train letters joined to the third number of the IOS XE line
      # are kept.
      ["IOS XE line with train letters (synthetic)", "Cisco IOS XE Software, Version 16.09.04SE\r\nCisco IOS Software [Fuji], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 16.9.4SE, RELEASE SOFTWARE (fc1)", "cisco_ios_xe", "16.09.04SE"],
      ["IOL router (17.15)", "Cisco IOS Software [IOSXE], Linux Software (X86_64BI_LINUX-ADVENTERPRISEK9-M), Version 17.15.1, RELEASE SOFTWARE (fc4)", "cisco_ios_xe", "17.15.1"],
      ["IOL switch (17.15)", "Cisco IOS Software [IOSXE], Linux Software (X86_64BI_LINUX_L2-ADVENTERPRISEK9-M), Version 17.15.1, RELEASE SOFTWARE (fc4)", "cisco_ios_xe", "17.15.1"],
      ["Catalyst 9300 17.13 (release notes)", "Cisco IOS XE Software, Version 17.13.01\nCisco IOS Software [Dublin], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.13.1, RELEASE SOFTWARE (fc1)", "cisco_ios_xe", "17.13.01"],
      ["Catalyst 9300 17.14 (release notes)", "Cisco IOS XE Software, Version 17.14.01\nCisco IOS Software, Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.14.1, RELEASE SOFTWARE (fc1)", "cisco_ios_xe", "17.14.01"],
      ["C8000V dev build (genie golden_output_c8000v)", "Cisco IOS XE Software, Version BLD_POLARIS_DEV_LATEST_20240326_003112\nCisco IOS Software [IOSXE], Virtual XE Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), Experimental Version 17.15.20240326:010319 [BLD_POLARIS_DEV_LATEST_20240326_003112:/nobackup/mcpre/s2c-build-ws 101]\nCisco IOS-XE software, Copyright (c) 2005-2024 by cisco Systems, Inc.", "cisco_ios_xe", "17.15.20240326"],
      ["C3850 [Everest], no IOS XE line (genie golden_output_c3850)", "Cisco IOS Software [Everest], Catalyst L3 Switch Software (CAT3K_CAA-UNIVERSALK9-M), Experimental Version 16.4.20170410:165034 [v164_throttle-BLD-BLD_V164_THROTTLE_LATEST_20170410_174845 105]\nCisco IOS-XE software, Copyright (c) 2005-2017 by cisco Systems, Inc.", "cisco_ios_xe", "16.4.20170410"],
      ["empty release tag (genie golden_output_8)", "Cisco IOS XE Software, Version BLD_POLARIS_DEV_LATEST_20211003_004933\nCisco IOS Software [], Catalyst L3 Switch Software (CAT9K_IOSXE), Experimental Version 17.8.20211003:014100 [BLD_POLARIS_DEV_LATEST_20211003_004933:/nobackup/mcpre/s2c-build-ws 100]\nCisco IOS-XE software, Copyright (c) 2005-2021 by cisco Systems, Inc.", "cisco_ios_xe", "17.8.20211003"],
      ["ISR4k 16.6 (genie golden_output_isr4k)", "Cisco IOS XE Software, Version 16.06.05\nCisco IOS Software [Everest], ISR Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), Version 16.6.5, RELEASE SOFTWARE (fc3)\nCisco IOS-XE software, Copyright (c) 2005-2018 by cisco Systems, Inc.", "cisco_ios_xe", "16.06.05"],
      ["Catalyst 17.18 [IOSXE] (genie golden_output_standby)", "Cisco IOS XE Software, Version 17.18.01prd21\nCisco IOS Software [IOSXE], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.18.1prd21, RELEASE SOFTWARE (fc1)\nCisco IOS-XE software, Copyright (c) 2005-2025 by cisco Systems, Inc.", "cisco_ios_xe", "17.18.01"],
      # IOS XE 2.x on ASR 1000 names IOS-XE on the IOS line and reports the IOSd release
      # (Cisco tech note 110739, "ASR 1000 Series Router Memory Troubleshoot Guide").
      ["IOS XE 2.x ASR 1000 (tech note 110739)", "Cisco IOS Software, IOS-XE Software (PPC_LINUX_IOSD-ADVIPSERVICESK9-M), Version 12.2(33)XNB, RELEASE SOFTWARE (fc1)", "cisco_ios_xe", "12.2"],
      ["IOS XE 3.x Catalyst 4500 (genie golden_output_1)", "Cisco IOS Software, IOS-XE Software, Catalyst 4500 L3 Switch  Software (cat4500e-UNIVERSALK9-M), Version 03.04.06.SG RELEASE SOFTWARE (fc1)\nCisco IOS-XE software, Copyright (c) 2005-2010, 2012 by cisco Systems, Inc.", "cisco_ios_xe", "03.04.06"],
      ["ASR901 15.6 (genie golden_output_asr901)", "Cisco IOS Software, 901 Software (ASR901-UNIVERSALK9-M), Version 15.6(2)SP4, RELEASE SOFTWARE (fc3)", "cisco_ios", "15.6"],
      ["IOSv 15.6 (genie golden_output_iosv)", "Cisco IOS Software, IOSv Software (VIOS-ADVENTERPRISEK9-M), Version 15.6(3)M2, RELEASE SOFTWARE (fc2)", "cisco_ios", "15.6"],
      ["IOS 12.1 IOS (tm) (genie golden_output_2)", "Cisco Internetwork Operating System Software \nIOS (tm) C2940 Software (C2940-I6K2L2Q4-M), Version 12.1(22)EA12, RELEASE SOFTWARE (fc1)", "cisco_ios", "12.1"],
      ["IOS 12.3 IOS (tm) only (genie golden_output_ios_c2600)", "IOS (tm) C2600 Software (C2600-IPBASE-M), Version 12.3(6f), RELEASE SOFTWARE (fc1)", "cisco_ios", "12.3"],
      # Not a captured banner: an IOS XE whose IOS line carries no tag and that prints no
      # IOS XE Software line still prints the IOS-XE copyright notice.
      ["IOS XE line without a tag, notice only (synthetic)", "Cisco IOS Software, Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.20.1, RELEASE SOFTWARE (fc1)\nCisco IOS-XE software, Copyright (c) 2005-2026 by cisco Systems, Inc.", "cisco_ios_xe", "17.20.1"],
      # Not a captured banner: an empty release tag with no other IOS XE marker.
      ["empty release tag alone (synthetic)", "Cisco IOS Software [], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.8.1, RELEASE SOFTWARE (fc1)", "cisco_ios_xe", "17.8.1"],
      # IOS XE 3.x routers pair the IOS XE release with an IOSd 15.x IOS line; the IOS XE
      # release is the one reported. Line format as printed by a CSR1000V on 3.16.
      ["CSR1000V IOS XE 3.16 (line format from Netshot's CSR1000V simulator)", "Cisco IOS XE Software, Version 03.16.07b.S - Extended Support Release\r\nCisco IOS Software, CSR1000V Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), Version 15.5(3)S7b, RELEASE SOFTWARE (fc1)\r\nCopyright (c) 1986-2018 by Cisco Systems, Inc.", "cisco_ios_xe", "03.16.07"],
      # Over SSH, lines end in CRLF and the version can end the line.
      ["IOS line ending in CRLF right after the version", "Cisco IOS Software, C3750E Software (C3750E-UNIVERSALK9-M), Version 12.2(58)SE\r\nCopyright (c) 1986-2011 by Cisco Systems, Inc.", "cisco_ios", "12.2"],
      # The first command of a session can carry a MOTD or exec banner configured without
      # a trailing newline, glued to the start of the first line.
      ["IOS line glued to a MOTD banner", "A MOTD BannerCisco IOS Software, C3750E Software (C3750E-UNIVERSALK9-M), Version 12.2(58)SE", "cisco_ios", "12.2"],
      ["IOS XE line glued to a MOTD banner", "A MOTD BannerCisco IOS XE Software, Version 17.13.01\nCisco IOS Software [Dublin], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.13.1, RELEASE SOFTWARE (fc1)", "cisco_ios_xe", "17.13.01"],
    ]

    # What an IOS XE 17.15 IOL node prints for `uname -s` on an SSH exec channel while
    # IOS.sh is off (the default), captured from a Cisco Modeling Labs node.
    ios_uname = "\r\n\r\n\r\nThe command you have entered is available in the IOS.sh.\r\nHowever, the shell is currently disabled. You can enable\r\nit on this terminal by typing\r\n   'term shell'\r\nYou can also enable it for all terminals by configuring the\r\n   'shell processing full'\r\ncommand. There is additional information in the man command.\r\nFor more information, enable shell, and then enter:\r\n'man IOS.sh'"

    cisco_banners.each do |label, show_version, name, release|
      it "recognizes #{label} as #{name} #{release}" do
        mock = Train::Transports::Mock::Connection.new
        mock.mock_command("uname -s", ios_uname, "", 0)
        mock.mock_command("show version", show_version)
        platform = Train::Platforms::Detect.scan(mock)

        _(platform[:name]).must_equal(name)
        _(platform[:family]).must_equal("cisco")
        _(platform[:release]).must_equal(release)
      end
    end

    it "does not report a Cisco platform without a numeric release" do
      without_release = [
        "Cisco IOS XE Software, Version BLD_POLARIS_DEV_LATEST_20240326_003112\n",
        "Cisco IOS Software, C3750E Software (C3750E-UNIVERSALK9-M), Version BLD_V122_LATEST\n",
      ]
      without_release.each do |show_version|
        mock = Train::Transports::Mock::Connection.new
        mock.mock_command("uname -s", ios_uname, "", 0)
        mock.mock_command("show version", show_version)

        _ { Train::Platforms::Detect.scan(mock) }.must_raise(Train::PlatformDetectionFailed)
      end
    end

    it "does not take other vendors' show version for Cisco" do
      not_cisco = [
        "Arista DCS-7050TX-64-R\nSoftware image version: 4.22.1F\n",
        "This is not IOS (tm) Software (X), Version 1.2 from Cisco\n",
      ]
      not_cisco.each do |show_version|
        mock = Train::Transports::Mock::Connection.new
        mock.mock_command("uname -s", ios_uname, "", 0)
        mock.mock_command("show version", show_version)

        _ { Train::Platforms::Detect.scan(mock) }.must_raise(Train::PlatformDetectionFailed)
      end
    end

    it "takes NX-OS over an IOS line in the same output" do
      mock = Train::Transports::Mock::Connection.new
      mock.mock_command("show version", "Cisco Nexus Operating System (NX-OS) Software\n  system:      version 5.2(1)N1(8b)\nCisco IOS Software, C3750E Software (C3750E-UNIVERSALK9-M), Version 12.2(58)SE, RELEASE SOFTWARE (fc1)\n")
      platform = Train::Platforms::Detect.scan(mock)

      _(platform[:name]).must_equal("cisco_nexus")
    end

    it "recognizes Cisco Nexus" do
      mock = Train::Transports::Mock::Connection.new
      mock.mock_command("show version", "Cisco Nexus Operating System (NX-OS) Software\n  system:      version 5.2(1)N1(8b)\n")
      platform = Train::Platforms::Detect.scan(mock)

      _(platform[:name]).must_equal("cisco_nexus")
      _(platform[:family]).must_equal("cisco")
      _(platform[:release]).must_equal("5.2")
    end
  end

  describe "brocade" do
    it "recognizes Brocade FOS-based SAN switches" do
      mock = Train::Transports::Mock::Connection.new
      mock.mock_command("version", "Kernel:     2.6.14.2\nFabric OS:  v7.4.2a\nMade on:    Thu Jun 29 19:22:14 2017\nFlash:      Sat Sep 9 17:30:42 2017\nBootProm:   1.0.11")
      platform = Train::Platforms::Detect.scan(mock)

      _(platform[:name]).must_equal("brocade_fos")
      _(platform[:family]).must_equal("brocade")
      _(platform[:release]).must_equal("7.4.2a")
    end
  end
end
