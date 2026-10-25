require "helper"

class OsDetectLinuxTester
  attr_reader :platform
  include Train::Platforms::Detect::Helpers::OSCommon

  def initialize
    @platform = {}
  end
end

describe "os_common" do
  let(:detector) { OsDetectLinuxTester.new }

  describe "winrm? check" do
    it "return winrm? true" do
      OsDetectLinuxTester.any_instance.stubs(:backend_name).returns("TrainPlugins::WinRM::Connection")
      _(detector.winrm?).must_equal(true)
    end

    it "return winrm? false when winrm is not loaded" do
      OsDetectLinuxTester.any_instance.stubs(:backend_name).returns("Something::Else")
      _(detector.winrm?).must_equal(false)
    end
  end

  describe "unix file contents" do
    it "return new file contents" do
      be = mock("Backend")
      output = mock("Output", exit_status: 0)
      output.expects(:stdout).returns("test")
      be.stubs(:run_command).with("test -f /etc/fstab && cat /etc/fstab").returns(output)
      detector.instance_variable_set(:@backend, be)
      detector.instance_variable_set(:@files, {})
      _(detector.unix_file_contents("/etc/fstab")).must_equal("test")
    end

    it "return new file contents cached" do
      be = mock("Backend")
      detector.instance_variable_set(:@backend, be)
      detector.instance_variable_set(:@files, { "/etc/profile" => "test" })
      _(detector.unix_file_contents("/etc/profile")).must_equal("test")
    end
  end

  describe "unix file exist?" do
    it "file does exist" do
      be = mock("Backend")
      be.stubs(:run_command).with("test -f /etc/test").returns(mock("Output", exit_status: 0))
      detector.instance_variable_set(:@backend, be)
      _(detector.unix_file_exist?("/etc/test")).must_equal(true)
    end
  end

  describe "#detect_linux_arch" do
    it "uname m call" do
      be = mock("Backend")
      be.stubs(:run_command).with("uname -m").returns(mock("Output", stdout: "x86_64\n", stderr: ""))
      detector.instance_variable_set(:@backend, be)
      detector.instance_variable_set(:@uname, {})
      _(detector.unix_uname_m).must_equal("x86_64")
    end

    it "uname s call" do
      be = mock("Backend")
      be.stubs(:run_command).with("uname -s").returns(mock("Output", stdout: "linux", stderr: ""))
      detector.instance_variable_set(:@backend, be)
      detector.instance_variable_set(:@uname, {})
      _(detector.unix_uname_s).must_equal("linux")
    end

    it "uname r call" do
      be = mock("Backend")
      be.stubs(:run_command).with("uname -r").returns(mock("Output", stdout: "17.0.0\n", stderr: ""))
      detector.instance_variable_set(:@backend, be)
      detector.instance_variable_set(:@uname, {})
      _(detector.unix_uname_r).must_equal("17.0.0")
    end
  end

  describe "#cisco_show_version" do
    def show_version(output)
      be = mock("Backend")
      be.stubs(:run_command).with("show version").returns(mock("Output", stdout: output, stderr: ""))
      detector.instance_variable_set(:@backend, be)
      detector.instance_variable_set(:@cache, {})
      detector.cisco_show_version
    end

    it "reports the IOS image as the model" do
      v = show_version("Cisco IOS Software, C3750E Software (C3750E-UNIVERSALK9-M), Version 12.2(58)SE")
      _(v).must_equal(version: "12.2", model: "C3750E-UNIVERSALK9-M", type: "ios")
    end

    it "reports the IOS (tm) image as the model" do
      v = show_version("IOS (tm) C2600 Software (C2600-IPBASE-M), Version 12.3(6f), RELEASE SOFTWARE (fc1)")
      _(v).must_equal(version: "12.3", model: "C2600-IPBASE-M", type: "ios")
    end

    it "reports the image on the IOS line of IOS XE as the model" do
      v = show_version("Cisco IOS XE Software, Version 17.13.01\nCisco IOS Software [Dublin], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.13.1, RELEASE SOFTWARE (fc1)")
      _(v).must_equal(version: "17.13.01", model: "CAT9K_IOSXE", type: "ios-xe")
    end

    it "reports no model when IOS XE prints no IOS line" do
      v = show_version("Cisco IOS XE Software, Version 17.13.01")
      _(v).must_equal(version: "17.13.01", model: nil, type: "ios-xe")
    end
  end
end
