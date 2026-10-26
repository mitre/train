require "helper"
require "train/transports/ssh"

# An IOS exec shell on the far end of the SSH channel, as an IOL router answers over SSH:
# every carriage return or line feed is an Enter, each Enter's reply arrives as its own
# chunk, and the connection only sees a chunk when it processes the channel. A secret of
# nil is a router with no enable secret (a vty refuses enable); :none is an enable that
# asks for no password. split: sends each reply's last line end and prompt as separate
# chunks, as a device may packetize them; password_prompt: is the text enable asks with
# (`aaa authentication password-prompt` changes it); username_prompt: is an AAA enable
# that asks for a username first; stall_on: is a line the device never answers, so
# processing the channel then returns nothing; line_delay: sends replies a line at a
# time, that many seconds apart, as a long command streams its output.
class FakeIOSShell
  attr_reader :lines

  def initialize(connection, privilege:, secret:, split: false, password_prompt: "Password: ",
                 username_prompt: false, stall_on: nil, line_delay: nil)
    @connection = connection
    @username_prompt = username_prompt
    @line_delay = line_delay
    @closed = false
    @privilege = privilege
    @secret = secret
    @split = split
    @password_prompt = password_prompt
    @stall_on = stall_on
    @stalled = false
    @password_attempts = nil
    @line = +""
    @lines = []
    @chunks = ["\r\n\r\n\r\n#{prompt}"]
  end

  def send_data(data)
    data.each_char do |char|
      if ["\r", "\n"].include?(char)
        enter
      else
        @line << char
      end
    end
  end

  def connection
    self
  end

  def close
    @closed = true
  end

  def closed?
    @closed
  end

  def unread_replies
    @chunks.size
  end

  def asking_for_password?
    !@password_attempts.nil?
  end

  def process(_timeout)
    return if @chunks.empty? && @stalled
    raise "the device has nothing more to send" if @chunks.empty?

    sleep @line_delay if @line_delay

    @connection.instance_variable_set(:@buf, @connection.instance_variable_get(:@buf) + @chunks.shift)
  end

  private

  def prompt
    @privilege == 15 ? "R1#" : "R1>"
  end

  def enter
    line = @line
    @line = +""
    @lines << line
    return @stalled = true if line == @stall_on

    reply = @password_attempts ? password(line) : command(line)
    cut = reply.rindex("\r\n")
    if @line_delay
      @chunks.concat(reply.scan(/.*?\r\n|.+\z/))
    elsif @split && cut
      @chunks << reply[0, cut + 2] << reply[(cut + 2)..-1]
    else
      @chunks << reply
    end
  end

  # Passwords are not echoed. Three wrong tries return to user EXEC.
  def password(line)
    if line == @secret
      @password_attempts = nil
      @privilege = 15
      return "\r\n#{prompt}"
    end

    @password_attempts += 1
    return "\r\n#{@password_prompt}" if @password_attempts < 3

    @password_attempts = nil
    "\r\n% Bad secrets\r\n\r\n#{prompt}"
  end

  def command(line)
    case line
    when "enable"
      return "enable\r\n% No password set\r\n#{prompt}" if @secret.nil?
      return "enable\r\n\r\nUsername: " if @username_prompt && @privilege != 15

      @privilege = 15 if @secret == :none
      return "enable\r\n#{prompt}" if @privilege == 15

      @password_attempts = 0
      "enable\r\n#{@password_prompt}"
    when "show privilege"
      "#{line}\r\nCurrent privilege level is #{@privilege}\r\n#{prompt}"
    when "show clock"
      "#{line}\r\n16:26:00.000 UTC Sun Oct 25 2026\r\n#{prompt}"
    when "show running-config"
      config = ["Building configuration...", "", "hostname R1", "!"] + (1..8).map { |n| "interface Ethernet0/#{n}" } + ["end"]
      "#{line}\r\n#{config.join("\r\n")}\r\n#{prompt}"
    else
      "#{line}\r\n#{prompt}"
    end
  end
end

describe "CiscoIOSConnection" do
  before do
    # This is to skip the test on windows as bundle exec rake is giving eror ArgumentError: non-absolute home
    skip "not on windows" if windows?
  end

  let(:cls) do
    plat = Train::Platforms.name("mock").in_family("cisco_ios")
    plat.add_platform_methods
    def plat.cisco_ios?
      true
    end

    Train::Platforms::Detect.stubs(:scan).returns(plat)
    Train::Transports::SSH
  end

  let(:opts) do
    {
      host: "fakehost",
      user: "fakeuser",
      password: "fakepassword",
    }
  end

  let(:connection) do
    cls.new(opts).connection
  end

  describe "#initialize" do
    it "provides a uri" do
      _(connection.uri).must_equal "ssh://fakeuser@fakehost:22"
    end
  end

  describe "enable mode" do
    def connect(privilege:, enable_password: "s3cret", secret: "s3cret", timeout: 15, **shell_options)
      conn = cls.new(opts.merge(enable_password: enable_password, connection_timeout: timeout)).connection
      shell = FakeIOSShell.new(conn, privilege: privilege, secret: secret, **shell_options)
      conn.stubs(:establish_connection)
      conn.stubs(:open_channel).returns(shell)
      [conn, shell]
    end

    it "enters enable mode and gives each command its own reply" do
      conn, = connect(privilege: 1)

      _(conn.run_command("show privilege").stdout).must_equal "Current privilege level is 15"
      _(conn.run_command("show clock").stdout).must_equal "16:26:00.000 UTC Sun Oct 25 2026"
      _(conn.run_command("show privilege").stdout).must_equal "Current privilege level is 15"
    end

    it "enters enable mode when the device sends a line end and the prompt apart" do
      conn, = connect(privilege: 1, split: true)

      _(conn.run_command("show privilege").stdout).must_equal "Current privilege level is 15"
      _(conn.run_command("show clock").stdout).must_equal "16:26:00.000 UTC Sun Oct 25 2026"
    end

    it "answers an enable password prompt set by AAA" do
      conn, = connect(privilege: 1, password_prompt: "Enter enable secret: ")

      _(conn.run_command("show privilege").stdout).must_equal "Current privilege level is 15"
    end

    it "gives up after the connection timeout when the device does not answer enable" do
      conn, = connect(privilege: 1, stall_on: "enable", timeout: 0.2)
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)

      error = _ { conn.run_command("show privilege") }.must_raise Train::Transports::SSHFailed
      _(error.message).must_include "enable"
      _(Process.clock_gettime(Process::CLOCK_MONOTONIC) - started).must_be :<, 5
    end

    it "closes the session when enable fails, so no later command is typed into it" do
      conn, shell = connect(privilege: 1, enable_password: "wrong")
      fresh = FakeIOSShell.new(conn, privilege: 15, secret: "s3cret")
      conn.stubs(:open_channel).returns(shell).then.returns(fresh)

      _ { conn.run_command("show privilege") }.must_raise Train::Transports::SSH::CiscoIOSConnection::BadEnablePassword
      _(shell.closed?).must_equal true
      typed = shell.lines.dup

      _(conn.run_command("show clock").stdout).must_equal "16:26:00.000 UTC Sun Oct 25 2026"
      _(shell.lines).must_equal typed
    end

    it "closes the SSH session on close" do
      conn, shell = connect(privilege: 15)
      conn.run_command("show clock")

      conn.close
      _(shell.closed?).must_equal true
    end

    it "gives up on a command the device does not answer within the connection timeout" do
      conn, = connect(privilege: 15, stall_on: "show clock", timeout: 0.2)
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)

      error = _ { conn.run_command("show clock") }.must_raise Train::Transports::SSHFailed
      _(error.message).must_include "show clock"
      _(Process.clock_gettime(Process::CLOCK_MONOTONIC) - started).must_be :<, 5
    end

    it "waits for a command whose output streams for longer than the connection timeout" do
      conn, = connect(privilege: 15, line_delay: 0.05, timeout: 0.3)

      config = conn.run_command("show running-config").stdout
      _(config).must_include "hostname R1"
      _(config.lines.last).must_equal "end"
    end

    it "does not type the enable password as a username" do
      conn, shell = connect(privilege: 1, username_prompt: true)

      error = _ { conn.run_command("show privilege") }.must_raise Train::Transports::SSH::CiscoIOSConnection::BadEnablePassword
      _(error.message).must_include "Username"
      _(shell.lines).wont_include "s3cret"
    end

    it "does not type enable when the session is already privileged" do
      conn, shell = connect(privilege: 15)

      _(conn.run_command("show privilege").stdout).must_equal "Current privilege level is 15"
      _(shell.lines).wont_include "enable"
    end

    it "enters enable mode without typing the password when enable asks for none" do
      conn, shell = connect(privilege: 1, secret: :none)

      _(conn.run_command("show privilege").stdout).must_equal "Current privilege level is 15"
      _(shell.lines).wont_include "s3cret"
    end

    it "raises with the router's answer when it refuses enable" do
      conn, shell = connect(privilege: 1, secret: nil)

      error = _ { conn.run_command("show privilege") }.must_raise Train::Transports::SSH::CiscoIOSConnection::BadEnablePassword
      _(error.message).must_include "% No password set"
      _(shell.lines).wont_include "s3cret"
    end

    it "raises on a wrong enable password and leaves the session at user EXEC with nothing unread" do
      conn, shell = connect(privilege: 1, enable_password: "wrong")

      _ { conn.run_command("show privilege") }.must_raise Train::Transports::SSH::CiscoIOSConnection::BadEnablePassword
      _(shell.asking_for_password?).must_equal false
      _(shell.unread_replies).must_equal 0
    end
  end

  describe "#unique_identifier" do
    it "returns the correct identifier" do
      output = "\r\nProcessor board ID 1111111111\r\n"
      Train::Transports::SSH::CiscoIOSConnection.any_instance
        .expects(:run_command_via_connection)
        .with("show version | include Processor")
        .returns(Train::Extras::CommandResult.new(output, "", 0))
      _(connection.unique_identifier).must_equal("1111111111")
    end
  end

  describe "#format_result" do
    it "returns correctly when result is 'good'" do
      exp = Train::Extras::CommandResult.new("good", "", 0)
      assert_equal exp, connection.send(:format_result, "good")
    end

    it "returns correctly when result matches /Bad IP address/" do
      output = "Translating \"nope\"\r\n\r\nTranslating \"nope\"\r\n\r\n% Bad IP address or host name\r\n% Unknown command or computer name, or unable to find computer address\r\n"
      Train::Extras::CommandResult.expects(:new).with("", output, 1)
      connection.send(:format_result, output)
    end

    it "returns correctly when result matches /Incomplete command/" do
      output = "% Incomplete command.\r\n\r\n"
      Train::Extras::CommandResult.expects(:new).with("", output, 1)
      connection.send(:format_result, output)
    end

    it "returns correctly when result matches /Invalid input detected/" do
      output = "             ^\r\n% Invalid input detected at '^' marker.\r\n\r\n"
      Train::Extras::CommandResult.expects(:new).with("", output, 1)
      connection.send(:format_result, output)
    end

    it "returns correctly when result matches /Unrecognized host/" do
      output = "Translating \"nope\"\r\n% Unrecognized host or address, or protocol not running.\r\n\r\n"
      Train::Extras::CommandResult.expects(:new).with("", output, 1)
      connection.send(:format_result, output)
    end
  end

  describe "#format_output" do
    it "returns the correct output" do
      cmd = "show calendar"
      output = "show calendar\r\n10:35:50 UTC Fri Mar 23 2018\r\n7200_ios_12#\r\n7200_ios_12#"
      result = connection.send(:format_output, output, cmd)
      _(result).must_equal "10:35:50 UTC Fri Mar 23 2018"
    end

    it "returns the correct output when a pipe is used" do
      cmd = "show running-config | section line con 0"
      output = "show running-config | section line con 0\r\nline con 0\r\n exec-timeout 0 0\r\n privilege level 15\r\n logging synchronous\r\n stopbits 1\r\n7200_ios_12#\r\n7200_ios_12#"
      result = connection.send(:format_output, output, cmd)
      _(result).must_equal "line con 0\r\n exec-timeout 0 0\r\n privilege level 15\r\n logging synchronous\r\n stopbits 1"
    end
  end
end
