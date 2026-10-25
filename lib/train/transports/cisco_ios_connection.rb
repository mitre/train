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

      @prompt = /^\S+[>#]\r\n.*$/
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

    private

    def establish_connection
      logger.debug("[SSH] opening connection to #{self}")

      Net::SSH.start(@host, @user, @ssh_options)
    end

    def session
      return @session unless @session.nil?

      @session = open_channel(establish_connection)

      # Escalate privilege to enable mode if password is given
      if @enable_password
        # This verifies we are not in privileged exec mode before running the
        # enable command. Otherwise, the password will be in history.
        if run_command_via_connection("show privilege").stdout.split[-1] != "15"
          enable_privileged_exec
        end
      end

      # Prevent `--MORE--` by removing terminal length limit
      run_command_via_connection("terminal length 0")

      @session
    end

    # IOS ends the enable password prompt with a colon, whether its own "Password: " or one
    # set with `aaa authentication password-prompt`.
    PASSWORD_PROMPT = /:\s?\z/.freeze
    PRIVILEGED_PROMPT = /\S+#\z/.freeze
    USER_EXEC_PROMPT = /\S+>\z/.freeze
    # IOS asks for the enable password three times before it gives up; this many empty
    # answers return to user EXEC after a wrong one.
    ENABLE_ATTEMPTS = 3

    # Types `enable` and the password one line at a time, reading each reply before sending
    # the next line, so no reply is left on the channel for the next command. Only what
    # follows the echo of `enable` counts as its reply: a prompt still in flight from the
    # previous command can arrive first. A wrong password is asked for again; empty answers
    # use up the remaining tries and return the session to user EXEC.
    def enable_privileged_exec
      reply = exchange("enable\n", PRIVILEGED_PROMPT, PASSWORD_PROMPT, USER_EXEC_PROMPT, echo: "enable")
      return if reply.match?(PRIVILEGED_PROMPT)
      raise BadEnablePassword, "enable refused: #{reply.strip}" if reply.match?(USER_EXEC_PROMPT)

      reply = exchange("#{@enable_password}\n", PRIVILEGED_PROMPT, PASSWORD_PROMPT, USER_EXEC_PROMPT)
      return if reply.match?(PRIVILEGED_PROMPT)

      ENABLE_ATTEMPTS.times do
        break unless reply.match?(PASSWORD_PROMPT)

        reply = exchange("\n", PASSWORD_PROMPT, USER_EXEC_PROMPT)
      end
      raise BadEnablePassword, "enable password rejected"
    end

    # Sends one line and reads the channel until the reply (what follows the echo, when one
    # is given) ends with one of the patterns, for at most the connection timeout.
    def exchange(line, *patterns, echo: nil)
      @buf = ""
      session.send_data(line)
      seconds = @ssh_options.fetch(:timeout, 15)
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + seconds
      loop do
        reply = echo ? @buf[/#{Regexp.quote(echo)}\r?\n(.*)\z/m, 1] : @buf
        return reply if reply && patterns.any? { |pattern| reply.match?(pattern) }
        if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
          raise Train::Transports::SSHFailed, "no answer to enable within #{seconds} seconds"
        end

        session.connection.process(0.1)
      end
    end

    def run_command_via_connection(cmd, &_data_handler)
      # Ensure buffer is empty before sending data
      @buf = ""

      logger.debug("[SSH] Running `#{cmd}` on #{self}")
      session.send_data(cmd + "\r\n")

      logger.debug("[SSH] waiting for prompt")
      until @buf =~ @prompt
        if @buf =~ /Bad (secrets|password)|Access denied/
          raise BadEnablePassword
        end

        session.connection.process(0)
      end

      # Save the buffer and clear it for the next command
      output = @buf.dup
      @buf = ""

      format_result(format_output(output, cmd))
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

    # The buffer (@buf) contains all data sent/received on the SSH channel so
    # we need to format the data to match what we would expect from Train
    def format_output(output, cmd)
      leading_prompt = /(\r\n|^)\S+[>#]/
      command_string = /#{Regexp.quote(cmd)}\r\n/
      trailing_prompt = /\S+[>#](\r\n|$)/
      trailing_line_endings = /(\r\n)+$/

      output
        .sub(leading_prompt, "")
        .sub(command_string, "")
        .gsub(trailing_prompt, "")
        .gsub(trailing_line_endings, "")
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
