require "helper"
require "train/transports/ssh"

# The SSH channel the connection types into: a stand-in for Net::SSH::Connection::Channel.
class FakeIOSChannel
  def initialize(shell)
    @shell = shell
  end

  def send_data(data)
    @shell.type(data)
  end

  def connection
    @shell
  end

  def close
    @shell.request_channel_close
  end
end

# An IOS exec shell on the far end of the SSH channel, as an IOL router answers over SSH,
# and the Net::SSH session that carries it. Every carriage return or line feed is an
# Enter; each Enter's reply arrives as its own chunk, and the connection only sees a chunk
# when it processes the session. Processing with nothing to deliver waits and returns, as
# Net::SSH does. Like Net::SSH, Session#close blocks until the device confirms the channel
# close, and shutdown! drops the connection at once.
#
# Options: secret nil is a router with no enable secret (a vty refuses enable), :none an
# enable that asks for no password. split: sends each reply's last line end and prompt as
# separate chunks, as a device may packetize them. password_prompt: is the text enable asks
# with (`aaa authentication password-prompt` changes it); username_prompt: is the text of
# an AAA enable that asks for a username first. stall_on: is a line the device never
# answers. line_delay: sends replies a line at a time, that many seconds apart, as a long
# command streams its output. confirm_close: false is a device that never confirms a
# channel close; drop_on: is a line after which the path to the device is gone, before
# its reply; drop_after: one whose reply arrives and then the path is gone.
class FakeIOSShell
  attr_reader :lines, :channel

  def initialize(connection, privilege:, secret:, split: false, password_prompt: "Password: ",
                 username_prompt: nil, stall_on: nil, line_delay: nil, confirm_close: true, drop_on: nil,
                 drop_after: nil)
    @connection = connection
    @privilege = privilege
    @secret = secret
    @split = split
    @password_prompt = password_prompt
    @username_prompt = username_prompt
    @stall_on = stall_on
    @line_delay = line_delay
    @confirm_close = confirm_close
    @drop_on = drop_on
    @drop_after = drop_after
    @drop_when_read = false
    @channel = FakeIOSChannel.new(self)
    @channel_open = true
    @close_requested = false
    @closed = false
    @shut_down = false
    @dropped = false
    @stalled = false
    @next_chunk_at = nil
    @password_attempts = nil
    @line = +""
    @lines = []
    @chunks = ["\r\n\r\n\r\n#{prompt}"]
  end

  def type(data)
    raise Net::SSH::Disconnect, "connection closed by remote host" if @dropped

    data.each_char do |char|
      if ["\r", "\n"].include?(char)
        enter
      else
        @line << char
      end
    end
  end

  def request_channel_close
    @close_requested = true
  end

  def channels
    @channel_open ? { 0 => @channel } : {}
  end

  def process(wait = nil)
    raise Net::SSH::Disconnect, "connection closed by remote host" if @dropped

    if @close_requested
      @channel_open = false if @confirm_close
      return wait_for(wait)
    end
    return wait_for(wait) if @chunks.empty? && @stalled
    raise "the device has nothing more to send" if @chunks.empty?

    now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    if @line_delay
      @next_chunk_at ||= now + @line_delay
      return wait_for([wait.to_f, @next_chunk_at - now].min) if now < @next_chunk_at

      @next_chunk_at = now + @line_delay
    end
    @connection.instance_variable_set(:@buf, @connection.instance_variable_get(:@buf) + @chunks.shift)
    @dropped = true if @drop_when_read && @chunks.empty?
  end

  def close
    request_channel_close
    raise Net::SSH::Disconnect, "connection closed by remote host" if @dropped
    raise "Session#close would wait forever: the device never confirms the channel close" unless @confirm_close

    @channel_open = false
    @closed = true
  end

  def shutdown!
    @shut_down = true
    @closed = true
  end

  def closed?
    @closed
  end

  def shut_down?
    @shut_down
  end

  def unread_replies
    @chunks.size
  end

  def asking_for_password?
    !@password_attempts.nil?
  end

  private

  def wait_for(seconds)
    sleep seconds if seconds&.positive?
    nil
  end

  def prompt
    @privilege == 15 ? "R1#" : "R1>"
  end

  def enter
    line = @line
    @line = +""
    @lines << line
    return @stalled = true if line == @stall_on
    return @dropped = true if line == @drop_on

    @drop_when_read = true if line == @drop_after

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
      return "enable\r\n\r\n#{@username_prompt}" if @username_prompt && @privilege != 15

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
      conn.stubs(:open_channel).returns(shell.channel)
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
      conn.stubs(:open_channel).returns(shell.channel).then.returns(fresh.channel)

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

    it "waits for a command whose output streams, with pauses, for longer than the connection timeout" do
      conn, = connect(privilege: 15, line_delay: 0.15, timeout: 0.4)

      config = conn.run_command("show running-config").stdout
      _(config).must_include "hostname R1"
      _(config.lines.last).must_equal "end"
    end

    it "closes the session when a command times out, so its late output never answers a later command" do
      conn, shell = connect(privilege: 15, stall_on: "show running-config", timeout: 0.2)
      fresh = FakeIOSShell.new(conn, privilege: 15, secret: "s3cret")
      conn.stubs(:open_channel).returns(shell.channel).then.returns(fresh.channel)

      _ { conn.run_command("show running-config") }.must_raise Train::Transports::SSHFailed
      _(shell.closed? || shell.shut_down?).must_equal true
      _(conn.run_command("show clock").stdout).must_equal "16:26:00.000 UTC Sun Oct 25 2026"
    end

    it "closes within the connection timeout when the device never confirms the channel close" do
      conn, shell = connect(privilege: 15, confirm_close: false, timeout: 0.2)
      conn.run_command("show clock")
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)

      conn.close
      _(Process.clock_gettime(Process::CLOCK_MONOTONIC) - started).must_be :<, 5
      _(shell.shut_down?).must_equal true
    end

    it "raises the dropped connection, not a close error, and shuts the session down" do
      conn, shell = connect(privilege: 15, drop_on: "show clock")

      _ { conn.run_command("show clock") }.must_raise Net::SSH::Disconnect
      _(shell.shut_down?).must_equal true
      conn.close
    end

    it "shuts the session down when the connection is gone before the next command is sent" do
      conn, shell = connect(privilege: 15, drop_after: "show clock")
      conn.run_command("show clock")

      _ { conn.run_command("show privilege") }.must_raise Net::SSH::Disconnect
      _(shell.shut_down?).must_equal true
    end

    it "shuts the session down when the connection is gone before enable is sent" do
      conn, shell = connect(privilege: 1, drop_after: "show privilege")

      _ { conn.run_command("show clock") }.must_raise Net::SSH::Disconnect
      _(shell.shut_down?).must_equal true
    end

    it "keeps the original error when the connection drops during enable" do
      conn, shell = connect(privilege: 1, drop_on: "enable")

      _ { conn.run_command("show privilege") }.must_raise Net::SSH::Disconnect
      _(shell.shut_down?).must_equal true
    end

    it "does not type the enable password at a username prompt AAA renamed" do
      conn, shell = connect(privilege: 1, username_prompt: "Login: ")

      error = _ { conn.run_command("show privilege") }.must_raise Train::Transports::SSH::CiscoIOSConnection::BadEnablePassword
      _(error.message).must_include "Login"
      _(shell.lines).wont_include "s3cret"
    end

    it "does not type the enable password as a username" do
      conn, shell = connect(privilege: 1, username_prompt: "Username: ")

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
