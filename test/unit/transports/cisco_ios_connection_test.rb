require "helper"
require "train/transports/ssh"

# The SSH channel the connection types into: a stand-in for Net::SSH::Connection::Channel.
class FakeIOSChannel
  def initialize(shell)
    @shell = shell
  end

  # As Net::SSH, data goes out when the session is processed, not when it is sent.
  def send_data(data)
    @shell.pending << data
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
# close, and shutdown! drops the connection at once. The prompt ends in > at privilege 0
# and 1 and in # from 2 up, as on IOS. Output longer than the terminal length (24 lines
# until `terminal length 0`) stops at --More-- and waits for a key. A reply over 8 KB
# arrives in 4 KB chunks.
#
# Options: secret nil is a router with no enable secret (a vty refuses enable), :none an
# enable that asks for no password. split: sends each reply's last line end and prompt as
# separate chunks, as a device may packetize them. password_prompt: is the text enable asks
# with (`aaa authentication password-prompt` changes it); username_prompt: is the text of
# an AAA enable that asks for a username first. stall_on: is a line the device never
# answers. line_delay: sends replies a line at a time, that many seconds apart, as a long
# command streams its output. late: maps a line to the seconds its reply is held back.
# login_banner: is text the device prints before its first prompt, with no line end;
# login_chunks: gives the login output instead as [text, seconds] pieces, as packets.
# log_after: maps a line to the seconds after its reply at which a syslog message arrives
# and IOS reprints the prompt (`terminal monitor` with `logging synchronous`).
# `exit` ends the exec session: the device closes the channel. confirm_close: false is a
# device that never confirms a
# channel close; drop_on: is a line after which the path to the device is gone, before
# its reply; drop_after: one whose reply arrives and then the path is gone; drop_during:
# one whose reply is cut off by the path going after its first chunk. drop_as: is the error
# a lost path raises (a reset shows as Errno::ECONNRESET). With the default, a clean close by
# the device, the first process after it returns with the session marked closed and only a
# later one raises Net::SSH::Disconnect, as Net::SSH behaves.
class FakeIOSShell
  attr_reader :lines, :channel, :pending

  def initialize(connection, privilege:, secret:, split: false, password_prompt: "Password: ",
                 username_prompt: nil, stall_on: nil, line_delay: nil, confirm_close: true, drop_on: nil,
                 drop_after: nil, drop_during: nil, drop_as: Net::SSH::Disconnect, late: {}, login_banner: "",
                 login_chunks: nil, log_after: {})
    @connection = connection
    @pending = +""
    @terminal_length = 24
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
    @drop_during = drop_during
    @drop_as = drop_as
    @late = late
    @log_after = log_after
    @drop_when_read = false
    @channel = FakeIOSChannel.new(self)
    @channel_open = true
    @close_requested = false
    @closed = false
    @shut_down = false
    @dropped = false
    @next_chunk_at = nil
    @password_attempts = nil
    @line = +""
    @lines = []
    login = "\r\n\r\n\r\n#{login_banner}#{prompt}"
    at = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    @chunks = if login_chunks
                login_chunks.map { |piece, delay| [piece, at += delay] }
              else
                (line_delay ? login.scan(/.*?\r\n|.+\z/) : [login]).map { |piece| [piece, at += line_delay.to_f] }
              end
  end

  def type(data)
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
    if @dropped && @drop_as == Net::SSH::Disconnect && !@closed
      @closed = true
      return nil
    end
    dropped!

    unless @pending.empty?
      typed = @pending
      @pending = +""
      type(typed)
      dropped!
    end
    if @close_requested
      @channel_open = false if @confirm_close
      return wait_for(wait)
    end
    return wait_for(wait) if @chunks.empty?

    now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    ready_at = @chunks.first[1]
    return wait_for([wait.to_f, ready_at - now].min) if now < ready_at

    @connection.instance_variable_get(:@buf) << @chunks.shift[0]
    @dropped = true if @drop_when_read && @chunks.empty?
    @dropped = true if @drop_during_read
  end

  def close
    request_channel_close
    dropped!
    raise "Session#close would wait forever: the device never confirms the channel close" if @channel_open && !@confirm_close

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

  private

  def dropped!
    return unless @dropped

    raise @drop_as, "connection closed by remote host" if @drop_as == Net::SSH::Disconnect

    raise @drop_as
  end

  def wait_for(seconds)
    sleep seconds if seconds&.positive?
    nil
  end

  def prompt
    @privilege >= 2 ? "R1#" : "R1>"
  end

  def enter
    line = @line
    @line = +""
    @lines << line
    return if line == @stall_on
    return @dropped = true if line == @drop_on

    @drop_when_read = true if line == @drop_after
    @drop_during_read = true if line == @drop_during

    reply = @password_attempts ? password(line) : command(line)
    reply = page(reply)
    cut = reply.rindex("\r\n")
    pieces = if @line_delay
               reply.scan(/.*?\r\n|.+\z/)
             elsif @split && cut
               [reply[0, cut + 2], reply[(cut + 2)..-1]]
             elsif reply.size > 8192
               reply.scan(/.{1,4096}/m)
             else
               [reply]
             end
    # Replies come out in order: one held back delays the ones typed after it.
    at = [Process.clock_gettime(Process::CLOCK_MONOTONIC), @chunks.last&.last.to_f].max + @late.fetch(line, 0)
    pieces.each do |piece|
      at += @line_delay if @line_delay
      @chunks << [piece, at]
    end
    if @log_after.key?(line)
      @chunks << ["\r\n*Oct 25 16:26:01.001: %SYS-5-CONFIG_I: Configured from console by console\r\n#{prompt}", at + @log_after[line]]
    end
    @channel_open = false if line == "exit" && @confirm_close
  end

  # Stops long output at --More--, as IOS does until `terminal length 0`.
  def page(reply)
    lines = reply.split(/(?<=\r\n)/)
    return reply if @terminal_length == 0 || lines.size <= @terminal_length

    lines.first(@terminal_length - 1).join + " --More-- "
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
    when "show running-config | include ^snmp-server community"
      "#{line}\r\n#{prompt}"
    when "exit"
      "#{line}\r\n"
    when /\Aterminal length (\d+)\z/
      @terminal_length = Regexp.last_match(1).to_i
      "#{line}\r\n#{prompt}"
    when "show tech-support"
      "#{line}\r\n#{"#{"x" * 62}\r\n" * 120_000}end\r\n#{prompt}"
    when "show running-config"
      config = ["Building configuration...", "", "hostname R1", "!", "banner motd ^C", "##########",
                "Authorized access only", "Access denied to unauthorized users", "##########", "^C"] + (1..24).map { |n| "interface Ethernet0/#{n}" } + ["end"]
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
    def connect(privilege:, enable_password: "s3cret", secret: "s3cret", timeout: 2, **shell_options)
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

    it "finds the prompt when a login banner ends without a line end" do
      conn, = connect(privilege: 15, login_banner: "Authorized access only")

      _(conn.run_command("show clock").stdout).must_equal "16:26:00.000 UTC Sun Oct 25 2026"
    end

    it "finds the prompt past a login banner with border lines that arrives line by line" do
      border = "##########\r\n"
      notice = "You are accessing a U.S. Government (USG) Information System (IS)\r\n"
      banner = border + notice + border + notice * 3 + border + notice * 3 + border
      conn, = connect(privilege: 15, login_banner: banner, line_delay: 0.03)

      _(conn.run_command("show clock").stdout).must_equal "16:26:00.000 UTC Sun Oct 25 2026"
    end

    it "gives a command its own output when IOS reprints the prompt after a log message" do
      conn, = connect(privilege: 15, log_after: { "show clock" => 0.05 })
      conn.run_command("show clock")

      _(conn.run_command("show privilege").stdout).must_equal "Current privilege level is 15"
    end

    it "enters enable mode when IOS reprints the prompt after a log message" do
      conn, = connect(privilege: 1, log_after: { "" => 0.3 })

      _(conn.run_command("show privilege").stdout).must_equal "Current privilege level is 15"
    end

    it "finds the prompt past a bordered login banner with pauses longer than the quiet time" do
      border = "##########\r\n"
      notice = "You are accessing a U.S. Government (USG) Information System (IS)\r\n"
      conn, = connect(privilege: 15, login_banner: border + notice + border, line_delay: 0.15)

      _(conn.run_command("show clock").stdout).must_equal "16:26:00.000 UTC Sun Oct 25 2026"
    end

    it "does not take a banner border line for the prompt when its line break arrives later" do
      chunks = [["\r\n##########", 0], ["\r\nAuthorized access only\r\n##########", 0.15], ["\r\nR1#", 0.15]]
      conn, = connect(privilege: 15, login_chunks: chunks)

      _(conn.run_command("show clock").stdout).must_equal "16:26:00.000 UTC Sun Oct 25 2026"
    end

    it "finds the prompt when a login banner is glued to it and the reply to Enter is late" do
      conn, = connect(privilege: 15, login_banner: "Authorized access only", late: { "" => 0.3 })

      _(conn.run_command("show clock").stdout).must_equal "16:26:00.000 UTC Sun Oct 25 2026"
    end

    it "enters enable mode when the login lands at a privilege level between 2 and 14" do
      conn, = connect(privilege: 5)

      _(conn.run_command("show privilege").stdout).must_equal "Current privilege level is 15"
    end

    it "does not type exit at a pending password prompt when enable fails" do
      conn, shell = connect(privilege: 1, enable_password: "wrong")

      _ { conn.run_command("show privilege") }.must_raise Train::Transports::SSH::CiscoIOSConnection::BadEnablePassword
      _(shell.lines).wont_include "exit"
      _(shell.closed?).must_equal true
    end

    it "drops the session at once after a command timeout instead of waiting for the device" do
      conn, = connect(privilege: 15, stall_on: "show clock", confirm_close: false)
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)

      _ { conn.run_command("show clock", timeout: 0.2) }.must_raise Train::CommandTimeoutReached
      _(Process.clock_gettime(Process::CLOCK_MONOTONIC) - started).must_be :<, 1
    end

    it "reads a 7 MB output in well under the default timeout" do
      conn, = connect(privilege: 15)
      conn.run_command("show clock")
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)

      output = conn.run_command("show tech-support").stdout
      _(Process.clock_gettime(Process::CLOCK_MONOTONIC) - started).must_be :<, 1
      _(output.lines.last).must_equal "end"
      _(output.size).must_be :>, 7_000_000
    end

    it "waits for a slow command as long as it takes when no timeout is given, as the SSH connection does" do
      conn, = connect(privilege: 15, late: { "show clock" => 0.3 })
      conn.run_command("show privilege")
      # Each look at the clock is a day later than the last, so any default limit would fire.
      conn.stubs(:monotonic_now).returns(0, *(1..400).map { |n| n * 86_400.0 })

      _(conn.run_command("show clock").stdout).must_equal "16:26:00.000 UTC Sun Oct 25 2026"
    end

    it "turns paging off so long output is not cut at --More--" do
      conn, = connect(privilege: 15)

      _(conn.run_command("show running-config").stdout.lines.last).must_equal "end"
    end

    it "closes the SSH session gracefully when the device confirms the channel close" do
      conn, shell = connect(privilege: 15)
      conn.run_command("show clock")

      conn.close
      _(shell.closed?).must_equal true
      _(shell.shut_down?).must_equal false
    end

    it "raises SSHFailed, as the SSH connection does, when the connection drops during a command" do
      conn, shell = connect(privilege: 15, drop_during: "show clock", line_delay: 0.01)
      fresh = FakeIOSShell.new(conn, privilege: 15, secret: "s3cret")
      conn.stubs(:open_channel).returns(shell.channel).then.returns(fresh.channel)
      conn.run_command("show privilege")

      error = _ { conn.run_command("show clock") }.must_raise Train::Transports::SSHFailed
      _(error.message).must_include "SSH command failed"
      _(fresh.lines).must_be_empty
      _(shell.closed?).must_equal true
    end

    it "returns empty output, not the prompt, for a command that prints nothing" do
      conn, = connect(privilege: 15)

      _(conn.run_command("show running-config | include ^snmp-server community").stdout).must_equal ""
    end

    it "returns empty output for a command that prints nothing at user EXEC" do
      conn, = connect(privilege: 1, enable_password: nil)

      _(conn.run_command("show running-config | include ^snmp-server community").stdout).must_equal ""
    end

    it "raises when the device has no enable secret and the login is below privilege 15" do
      conn, = connect(privilege: 5, secret: nil)

      error = _ { conn.run_command("show privilege") }.must_raise Train::Transports::SSH::CiscoIOSConnection::BadEnablePassword
      _(error.message).must_include "No password set"
    end

    it "opens a new session when the dropped connection shows as a reset" do
      conn, shell = connect(privilege: 15, drop_after: "show clock", drop_as: Errno::ECONNRESET)
      fresh = FakeIOSShell.new(conn, privilege: 15, secret: "s3cret")
      conn.stubs(:open_channel).returns(shell.channel).then.returns(fresh.channel)
      conn.run_command("show clock")

      _(conn.run_command("show privilege").stdout).must_equal "Current privilege level is 15"
      _(shell.shut_down?).must_equal true
    end

    it "opens a new session when the closed session shows as an IOError" do
      conn, shell = connect(privilege: 15, drop_after: "show clock", drop_as: IOError)
      fresh = FakeIOSShell.new(conn, privilege: 15, secret: "s3cret")
      conn.stubs(:open_channel).returns(shell.channel).then.returns(fresh.channel)
      conn.run_command("show clock")

      _(conn.run_command("show privilege").stdout).must_equal "Current privilege level is 15"
    end

    it "raises SSHFailed when the connection resets during a command" do
      conn, shell = connect(privilege: 15, drop_on: "show clock", drop_as: Errno::ECONNRESET)

      _ { conn.run_command("show clock") }.must_raise Train::Transports::SSHFailed
      _(shell.shut_down?).must_equal true
    end

    it "tries to reopen a closed session once, not twice, when the new session fails" do
      conn, shell = connect(privilege: 15, drop_after: "show clock")
      conn.unstub(:open_channel)
      conn.expects(:open_channel).twice.returns(shell.channel).then.raises(Net::SSH::ConnectionTimeout, "timed out")
      conn.run_command("show clock")

      _ { conn.run_command("show privilege") }.must_raise Train::Transports::SSHFailed
    end

    it "drops the connection when closing it fails" do
      conn, shell = connect(privilege: 15, drop_after: "show clock")
      conn.run_command("show clock")

      conn.close
      _(shell.shut_down?).must_equal true
    end

    it "types each command with one Enter" do
      conn, shell = connect(privilege: 15)
      conn.run_command("show clock")
      typed = shell.lines.dup

      conn.run_command("show privilege")
      _(shell.lines.drop(typed.size)).must_equal ["show privilege"]
    end

    it "sets the terminal width so long lines are not wrapped" do
      conn, shell = connect(privilege: 15)
      conn.run_command("show clock")

      _(shell.lines).must_include "terminal width 511"
    end

    it "reads a command's output to the device's own prompt, past lines that look like a prompt" do
      conn, = connect(privilege: 15, line_delay: 0.001)

      config = conn.run_command("show running-config").stdout
      _(config).must_include "Authorized access only"
      _(config.lines.count { |line| line.chomp == "##########" }).must_equal 2
      _(config.lines.last).must_equal "end"
    end

    it "raises a command timeout when a command runs past the timeout it is given" do
      conn, = connect(privilege: 15, stall_on: "show clock")
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)

      error = _ { conn.run_command("show clock", timeout: 0.2) }.must_raise Train::CommandTimeoutReached
      _(error.message).must_include "show clock"
      _(Process.clock_gettime(Process::CLOCK_MONOTONIC) - started).must_be :<, 5
    end

    it "times out on total time even while output keeps arriving" do
      conn, = connect(privilege: 15, line_delay: 0.05)

      _ { conn.run_command("show running-config", timeout: 0.3) }.must_raise Train::CommandTimeoutReached
    end

    it "gives a later command its own output when an earlier one timed out" do
      conn, shell = connect(privilege: 15, late: { "show running-config" => 0.5 })
      fresh = FakeIOSShell.new(conn, privilege: 15, secret: "s3cret")
      conn.stubs(:open_channel).returns(shell.channel).then.returns(fresh.channel)

      _ { conn.run_command("show running-config", timeout: 0.2) }.must_raise Train::CommandTimeoutReached
      _(shell.closed? || shell.shut_down?).must_equal true
      _(conn.run_command("show running-config").stdout).must_include "hostname R1"
      _(conn.run_command("show clock").stdout).must_equal "16:26:00.000 UTC Sun Oct 25 2026"
    end

    it "logs out with exit before closing the SSH session" do
      conn, shell = connect(privilege: 15)
      conn.run_command("show clock")

      conn.close
      _(shell.lines.last).must_equal "exit"
      _(shell.closed?).must_equal true
    end

    it "closes within the connection timeout when the device never confirms the channel close" do
      conn, shell = connect(privilege: 15, confirm_close: false, timeout: 0.2)
      conn.run_command("show clock")
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)

      conn.close
      _(Process.clock_gettime(Process::CLOCK_MONOTONIC) - started).must_be :<, 5
      _(shell.shut_down?).must_equal true
    end

    it "raises SSHFailed, not a close error, when the path is gone as a command is typed" do
      conn, shell = connect(privilege: 15, drop_on: "show clock")

      _ { conn.run_command("show clock") }.must_raise Train::Transports::SSHFailed
      _(shell.shut_down?).must_equal true
      conn.close
    end

    it "opens a new session when the device closed the old one while it was idle, before typing the command" do
      conn, shell = connect(privilege: 15, drop_after: "show clock")
      fresh = FakeIOSShell.new(conn, privilege: 15, secret: "s3cret")
      conn.stubs(:open_channel).returns(shell.channel).then.returns(fresh.channel)
      conn.run_command("show clock")

      _(conn.run_command("show version").stdout).must_equal ""
      _(shell.closed?).must_equal true
      _(fresh.lines).must_include "show version"
      _(shell.lines).wont_include "show version"
    end

    it "drops the session when the connection is gone during session setup" do
      conn, shell = connect(privilege: 1, drop_after: "")

      _ { conn.run_command("show clock") }.must_raise Train::Transports::SSHFailed
      _(shell.closed?).must_equal true
    end

    it "reports the dropped connection when it drops during enable" do
      conn, shell = connect(privilege: 1, drop_on: "enable")

      _ { conn.run_command("show privilege") }.must_raise Train::Transports::SSHFailed
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

    it "raises on a wrong enable password and drops the session" do
      conn, shell = connect(privilege: 1, enable_password: "wrong")

      error = _ { conn.run_command("show privilege") }.must_raise Train::Transports::SSH::CiscoIOSConnection::BadEnablePassword
      _(error.message).must_include "rejected"
      _(shell.closed?).must_equal true
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
      result = connection.send(:format_output, output, cmd, "7200_ios_12")
      _(result).must_equal "10:35:50 UTC Fri Mar 23 2018"
    end

    it "returns the correct output when a pipe is used" do
      cmd = "show running-config | section line con 0"
      output = "show running-config | section line con 0\r\nline con 0\r\n exec-timeout 0 0\r\n privilege level 15\r\n logging synchronous\r\n stopbits 1\r\n7200_ios_12#\r\n7200_ios_12#"
      result = connection.send(:format_output, output, cmd, "7200_ios_12")
      _(result).must_equal "line con 0\r\n exec-timeout 0 0\r\n privilege level 15\r\n logging synchronous\r\n stopbits 1"
    end
  end
end
