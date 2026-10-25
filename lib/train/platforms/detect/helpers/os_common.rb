require_relative "os_linux"
require_relative "os_windows"
require "rbconfig" unless defined?(RbConfig)

module Train::Platforms::Detect::Helpers
  module OSCommon
    include Train::Platforms::Detect::Helpers::Linux
    include Train::Platforms::Detect::Helpers::Windows

    def ruby_host_os(regex)
      regex.match?(::RbConfig::CONFIG["host_os"])
    end

    def winrm?
      backend_name == "TrainPlugins::WinRM::Connection"
    end

    def backend_name
      @backend.class.name
    end

    def unix_file_contents(path)
      # keep a log of files incase multiple checks call the same one
      return @files[path] if @files.key?(path)

      res = @backend.run_command("test -f #{path} && cat #{path}")
      # ignore files that can't be read
      @files[path] = res.exit_status == 0 ? res.stdout : nil
      @files[path]
    end

    def unix_file_exist?(path)
      @backend.run_command("test -f #{path}").exit_status == 0
    end

    def command_output(cmd)
      res = @backend.run_command(cmd)
      # To suppress warning: literal string will be frozen in the future
      stdout = String.new(res.stdout)
      stderr = String.new(res.stderr)
      # When you try to execute command using ssh connection as root user and you have provided ssh user identity file
      # it gives standard output to login as authorized user other than root. To show this standard output as an error
      # to user we are matching the string of stdout and raising the error here so that user gets exact information.
      if @backend.class.to_s == "Train::Transports::SSH::Connection"
        if stdout =~ /Please login as the user/
          raise Train::UserError, "SSH failed: #{stdout}"
        end

        if stderr =~ /WARNING: Your password has expired/
          raise Train::UserError, "SSH failed: #{stderr}"
        end
      end

      stdout.strip! unless stdout.nil?
      stdout
    end

    def unix_uname_s
      return @uname[:s] if @uname.key?(:s)

      @uname[:s] = command_output("uname -s")
    end

    def unix_uname_r
      return @uname[:r] if @uname.key?(:r)

      @uname[:r] = command_output("uname -r")
    end

    def unix_uname_m
      return @uname[:m] if @uname.key?(:m)

      @uname[:m] = command_output("uname -m")
    end

    def brocade_version
      return @cache[:brocade] if @cache.key?(:brocade)

      res = command_output("version")

      m = res.match(/^Fabric OS:\s+v(\S+)$/)

      @cache[:brocade] = m && { version: m[1], type: "fos" }
    end

    # The IOS line of `show version`: "Cisco IOS Software, ...", with a release tag on IOS XE
    # 16 and later ("Cisco IOS Software [Everest], ...", "[IOSXE]", even "[]"), or the 12.x
    # form "IOS (tm) ...". It names the image in parentheses and then the version.
    # Neither pattern is anchored to the start of a line: the first command of a session can
    # carry a MOTD or exec banner that ends without a newline, glued to the line. The version
    # stops at a space, comma or line end (CRLF over SSH).
    CISCO_IOS_LINE = /(?:Cisco IOS Software(?: \[(?<tag>[^\]]*)\])?,|IOS \(tm\)) (?<description>.*?) ?\((?<image>[^)]+)\),? +(?:Experimental )?Version (?<version>[^\s,]+)/.freeze
    CISCO_IOS_XE_LINE = /Cisco IOS XE Software, Version (?<version>[^\s,]+)/.freeze
    CISCO_IOS_XE_NOTICE = /Cisco IOS-XE software, Copyright/.freeze

    # Decides the Cisco platform by markers rather than by the wording of one line, which
    # changes between products and releases: NX-OS first, then IOS XE if any IOS XE marker
    # is present (see cisco_ios_xe?), otherwise IOS.
    def cisco_show_version
      return @cache[:cisco] if @cache.key?(:cisco)

      res = command_output("show version")
      @cache[:cisco] = cisco_nexus_version(res) || cisco_ios_version(res)
    end

    def cisco_nexus_version(res)
      return unless res.match?(/Cisco Nexus Operating System \(NX-OS\) Software/)

      v = res[/^\s*system:\s+version (\d+\.\d+)/, 1]
      v ||= res[/NXOS: version (\d+\.\d+)/, 1]
      { version: v, type: "nexus" }
    end

    # Release: IOS XE takes the version of its "Cisco IOS XE Software, Version" line when that
    # is numeric (a development build shows a BLD_ label there), else the IOS line's; IOS
    # keeps major.minor. As before, an IOS XE release keeps uppercase train letters joined to
    # the third number (03.03.03SE) and drops anything else after it (".SG", "b.S", "a",
    # "prd21"). On a 3.x development build the IOS XE line carries a BLD_ label and the IOS
    # line an IOSd 15.x version, so the release reported is the IOSd one.
    # Without a numeric release there is no platform.
    def cisco_ios_version(res)
      ios = res.match(CISCO_IOS_LINE)
      xe = res.match(CISCO_IOS_XE_LINE)
      return if ios.nil? && xe.nil?

      model = ios && ios[:image]
      unless cisco_ios_xe?(res, ios, xe)
        version = ios[:version][/\A\d+\.\d+/]
        return version && { version: version, model: model, type: "ios" }
      end

      version = xe && xe[:version][/\A\d+\.\d+\.\d+[A-Z]*/]
      version ||= ios && ios[:version][/\A\d+\.\d+(?:\.\d+[A-Z]*)?/]
      version && { version: version, model: model, type: "ios-xe" }
    end

    # IOS XE markers: a "Cisco IOS XE Software" line (16.x and later); a release tag on the
    # IOS line, which classic IOS never prints; "IOS-XE Software" on the IOS line (3.x); the
    # "Cisco IOS-XE software, Copyright" notice (3.x and later).
    def cisco_ios_xe?(res, ios, xe)
      return true if xe
      return true if ios && (ios[:tag] || ios[:description].start_with?("IOS-XE Software"))

      res.match?(CISCO_IOS_XE_NOTICE)
    end
    private :cisco_nexus_version, :cisco_ios_version, :cisco_ios_xe?

    def unix_uuid
      (unix_uuid_from_chef         ||
       unix_uuid_from_machine_file ||
       uuid_from_command           ||
       uuid_from_containerized_system ||
       raise(Train::TransportError, "Cannot find a UUID for your node."))
    end

    def unix_uuid_from_chef
      file = @backend.file("/var/chef/cache/data_collector_metadata.json")
      if file.exist? && file.size != 0
        json = ::JSON.parse(file.content)
        return json["node_uuid"] if json["node_uuid"]
      end
    end

    def unix_uuid_from_machine_file
      %W{
        /etc/chef/chef_guid
        #{ENV["HOME"]}/.chef/chef_guid
        /etc/machine-id
        /var/lib/dbus/machine-id
        /var/db/dbus/machine-id
      }.each do |path|
        file = @backend.file(path)
        next unless file.exist? && file.size != 0
        return file.content.chomp if path =~ /guid/

        return uuid_from_string(file.content.chomp)
      end
      nil
    end

    # This takes a command from the platform detect block to run.
    # We expect the command to return a unique identifier which
    # we turn into a UUID.
    def uuid_from_command
      return unless @platform[:uuid_command]

      result = @backend.run_command(@platform[:uuid_command])
      uuid_from_string(result.stdout.chomp) if result.exit_status == 0 && !result.stdout.empty?
    end

    # This will run if anyone is running Train with local transport inside docker container
    # This is fallback plan, if other ways of getting uuid fails for local transport running inside docker container
    # TODO: This needs to be improved to support other container runtime
    def uuid_from_containerized_system
      uuid = nil

      if File.exist?("/proc/self/cgroup")
        cmd = @backend.run_command("head -1 /proc/self/cgroup|cut -d/ -f3")
        unless cmd.stdout.strip.empty?
          uuid = cmd.stdout.strip
        end
      end

      if uuid.nil? && File.exist?("/proc/self/mountinfo")
        cmd = @backend.run_command("cat /proc/self/mountinfo | grep -i /docker/containers/ | head -n 1 | awk '{print $4}' | awk NF=NF FS=/ | awk '{print $3}'")
        unless cmd.stdout.strip.empty?
          uuid = cmd.stdout.strip
        end
      end
      uuid
    end

    # This hashes the passed string into SHA1.
    # Then it downgrades the 160bit SHA1 to a 128bit
    # then we format it as a valid UUIDv5.
    def uuid_from_string(string)
      hash = Digest::SHA1.new
      hash.update(string)
      ary = hash.digest.unpack("NnnnnN")
      ary[2] = (ary[2] & 0x0FFF) | (5 << 12)
      ary[3] = (ary[3] & 0x3FFF) | 0x8000
      # rubocop:disable Style/FormatString
      "%08x-%04x-%04x-%04x-%04x%08x" % ary
    end

    def json_cmd(cmd)
      cmd = @backend.run_command(cmd)
      if cmd.exit_status == 0 && !cmd.stdout.empty?
        require "json" unless defined?(JSON)
        eos_ver = JSON.parse(cmd.stdout)
        @platform[:release] = eos_ver["version"]
        @platform[:arch] = eos_ver["architecture"]
        true
      end
    rescue JSON::ParserError
      nil
    end

    def set_from_uname
      @platform[:name]    = unix_uname_s.lines.first.chomp
      @platform[:release] = unix_uname_r.lines.first.chomp
      true
    end
  end
end
