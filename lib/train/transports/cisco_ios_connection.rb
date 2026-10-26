class Train::Transports::SSH
  class CiscoIOSConnection < BaseConnection
    class BadEnablePassword < Train::TransportError; end

    def initialize(options)
      super(options)

      # Extract options to avoid passing them in to `Net::SSH.start` later
      @host = options.delete(:host)
      @user = options.delete(:user)
      @port = options[:port] # kept for `Net::SSH.start`
      @enable_password = options.delete(:enable_password)
      @platform = options.delete(:platform)
      @platform.backend = self if @platform

      # Use all options left that are not `nil` for `Net::SSH.start` later
      @ssh_options = options.reject { |_key, value| value.nil? }

      # Allow older algorithms
      @ssh_options[:append_all_supported_algorithms] = true

      @buf = ""
    end

    def uri
      "ssh://#{@user}@#{@host}:#{@port}"
    end

    def unique_identifier
      result = run_command_via_connection("show version | include Processor")
      result.stdout.split(" ")[-1]
    end

    def upload(locals, remote)
      raise NotImplementedError, "#{self.class} does not implement #upload()"
    end

    def download(remotes, local)
      raise NotImplementedError, "#{self.class} does not implement #download()"
    end

    # Ends the exec session with `exit`, as Netmiko's disconnect does, and closes the SSH
    # session. Net::SSH's Session#close waits, with no limit, for the device to confirm the
    # channel close; this waits at most the connection timeout, then drops the connection, as
    # it does when the path to the device is already gone.
    def close
      return if @session.nil?

      channel = @session
      @session = nil
      ssh = channel.connection
      return if ssh.closed?

      channel.send_data("exit\n")
      channel.close
      deadline = monotonic_now + setup_timeout
      ssh.process(0.1) until ssh.channels.empty? || monotonic_now > deadline
      ssh.channels.empty? ? ssh.close : ssh.shutdown!
    rescue Net::SSH::Exception, IOError, SystemCallError => e
      logger.debug("[SSH] dropping the connection to #{self}: #{e.message}")
      ssh&.shutdown!
    end

    private

    # Seconds a command may take in total, as Netmiko's read_timeout; run_command's :timeout
    # (InSpec's --command-timeout) overrides it.
    READ_TIMEOUT = 10
    # A prompt at the end of what the device sent.
    PROMPT_END = /[>#]\s*\z/.freeze
    # Seconds without new data after which the login output (a banner, say) counts as done;
    # Netmiko's clear_buffer starts at the same 0.1.
    QUIET = 0.1
    # IOS ends a question with a colon. The enable password is typed only at a question that
    # asks for a password or secret: IOS's own "Password: " or one set with
    # `aaa authentication password-prompt`. AAA can ask for a username first, under any text
    # (`aaa authentication username-prompt`), and a password typed there would echo.
    QUESTION_PROMPT = /:\s?\z/.freeze
    PASSWORD_PROMPT = /(?:password|secret|passcode)[^\r\n]*:\s?\z/i.freeze

    def establish_connection
      logger.debug("[SSH] opening connection to #{self}")

      Net::SSH.start(@host, @user, @ssh_options)
    end

    def session
      return @session unless @session.nil?

      @session = open_channel(establish_connection)
      prepare_session
      @session
    rescue StandardError
      # A session left mid-way (at a password prompt, say) would take the next command as
      # its answer; drop it, as Netmiko does when session preparation fails.
      close
      raise
    end

    # As Netmiko's session_preparation for IOS: find the device's prompt, enter enable mode
    # when a password is given and the session is not privileged, then turn off paging and
    # line wrapping.
    def prepare_session
      prompt = find_prompt
      enable_privileged_exec if @enable_password && prompt.end_with?(">")
      send_command("terminal length 0", setup_timeout, Train::Transports::SSHFailed)
      send_command("terminal width 511", setup_timeout, Train::Transports::SSHFailed)
    end

    # As Netmiko's find_prompt: press Enter, let the login output (a banner whose border
    # lines can end in # or >, say) finish, and take the last line as the prompt. Its text
    # before > or # is the base prompt that ends every command's output from now on.
    def find_prompt
      @session.send_data("\n")
      read_until_quiet
      prompt = @buf.strip.split(/\r?\n/).last
      @base_prompt = prompt.chop
      prompt
    end

    # Processes the channel until what arrived ends at a prompt and nothing more has come for
    # QUIET seconds, for at most the connection timeout.
    def read_until_quiet
      received = @buf.size
      quiet_since = monotonic_now
      read_until(setup_timeout, "the prompt", Train::Transports::SSHFailed) do
        if @buf.size != received
          received = @buf.size
          quiet_since = monotonic_now
        end
        @buf.match?(PROMPT_END) && monotonic_now - quiet_since >= QUIET
      end
    end

    # As Netmiko's enable: type `enable`, read its echo, then read to the prompt or a question;
    # answer only a password question, then check the prompt ends in #. Anything else (IOS
    # asking again after a wrong password, say) raises, and the session is dropped.
    def enable_privileged_exec
      reply = enable_step("enable\n", echo: "enable")
      return if reply.match?(/#{Regexp.escape(@base_prompt)}#\z/)
      raise BadEnablePassword, "enable refused: #{reply.strip}" if reply.match?(/#{Regexp.escape(@base_prompt)}>\z/)
      unless reply.match?(PASSWORD_PROMPT)
        raise BadEnablePassword, "enable asks #{reply.strip.lines.last.inspect}, which is not a password prompt"
      end

      reply = enable_step("#{@enable_password}\n")
      return if reply.match?(/#{Regexp.escape(@base_prompt)}#\z/)

      raise BadEnablePassword, "enable password rejected"
    end

    # One line of the enable exchange: what follows the echo (when one is given) up to the
    # prompt or a question.
    def enable_step(line, echo: nil)
      @buf = ""
      @session.send_data(line)
      reply = nil
      read_until(setup_timeout, "enable", Train::Transports::SSHFailed) do
        reply = echo ? @buf[/#{Regexp.quote(echo)}\r?\n(.*)\z/m, 1] : @buf
        reply && (reply.match?(PROMPT_END) || reply.match?(QUESTION_PROMPT))
      end
      reply
    end

    def run_command_via_connection(cmd, opts = {}, &_data_handler)
      logger.debug("[SSH] Running `#{cmd}` on #{self}")
      session
      format_result(send_command(cmd, opts[:timeout] || READ_TIMEOUT, Train::CommandTimeoutReached))
    end

    # As Netmiko's send_command: type the command with one Enter, read its echo, then read to
    # the device's own prompt at the end of the output. Anything before the echo, such as a
    # prompt still in flight from the previous command, is not part of the output. A command
    # that does not finish within `timeout` seconds raises `error` and drops the session, so
    # its late output cannot answer a later command; so does losing the connection.
    def send_command(cmd, timeout, error)
      @buf = ""
      @session.send_data("#{cmd}\n")
      prompt = /\r?\n#{Regexp.escape(@base_prompt)}[>#]\s*\z/
      echo = /#{Regexp.quote(cmd)}\r?\n/
      read_until(timeout, "`#{cmd}`", error) do
        start = @buf.index(echo)
        start && @buf[start..-1].match?(prompt)
      end
      format_output(@buf, cmd, @base_prompt)
    rescue error, Net::SSH::Exception, IOError, SystemCallError
      close
      raise
    end

    # Processes the channel until the block is true, for at most `timeout` seconds in total.
    # `what` names the step in the error and must not hold a secret.
    def read_until(timeout, what, error)
      deadline = monotonic_now + timeout
      until yield
        raise error, "#{what} reached timeout (#{timeout}s)" if monotonic_now > deadline

        @session.connection.process(0.1)
      end
    end

    def setup_timeout
      @ssh_options.fetch(:timeout, 15)
    end

    def monotonic_now
      Process.clock_gettime(Process::CLOCK_MONOTONIC)
    end

    ERROR_MATCHERS = [
      "Bad IP address",
      "Incomplete command",
      "Invalid input detected",
      "Unrecognized host",
    ].freeze

    # IOS commands do not have an exit code so we must compare the command
    # output with partial segments of known errors. Then, we return a
    # `CommandResult` with arguments in the correct position based on the
    # result.
    def format_result(result)
      if ERROR_MATCHERS.none? { |e| result.include?(e) }
        CommandResult.new(result, "", 0)
      else
        CommandResult.new("", result, 1)
      end
    end

    # The output of `cmd` in what the channel received: the lines after its echo, without the
    # device's trailing prompt (`base_prompt` followed by > or #) and line ends. Lines that
    # only look like a prompt, such as a banner's "#####", stay.
    def format_output(output, cmd, base_prompt)
      echo = output.index(/#{Regexp.quote(cmd)}\r?\n/)
      body = echo ? output[echo..-1].sub(/\A#{Regexp.quote(cmd)}\r?\n/, "") : output
      body
        .sub(/(?:\r?\n#{Regexp.escape(base_prompt)}[>#])+\s*\z/, "")
        .sub(/(?:\r\n)+\z/, "")
    end

    # Create an SSH channel that writes to @buf when data is received
    def open_channel(ssh)
      logger.debug("[SSH] opening SSH channel to #{self}")
      ssh.open_channel do |ch|
        ch.on_data do |_, data|
          @buf += data
        end

        ch.send_channel_request("shell") do |_, success|
          raise "Failed to open SSH shell" unless success

          logger.debug("[SSH] shell opened")
        end
      end
    end
  end
end
