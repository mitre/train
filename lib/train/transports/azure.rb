# encoding: utf-8

require "train/plugins"
require "ms_rest_azure"
require "azure_mgmt_resources"
require "azure_graph_rbac"
require "azure_mgmt_key_vault"
require "socket"
require "timeout"
require "train/transports/helpers/azure/file_credentials"
require "train/transports/clients/azure/graph_rbac"
require "train/transports/clients/azure/vault"
require "train/transports/clients/azure/management"

module Train::Transports

  class Azure < Train.plugin(1)
    name "azure"
    option :tenant_id, default: ENV["AZURE_TENANT_ID"]
    option :client_id, default: ENV["AZURE_CLIENT_ID"]
    option :client_secret, default: ENV["AZURE_CLIENT_SECRET"]
    option :subscription_id, default: ENV["AZURE_SUBSCRIPTION_ID"]
    option :msi_port, default: ENV["AZURE_MSI_PORT"] || "50342"

    option :api_profile, default: ENV["AZURE_API_PROFILE"] || "Latest"
    # NEW CLOUD CONFIG
    option :cloud_name, default: ENV["AZURE_CLOUD_NAME"]
    option :cloud_portal_url, default: ENV["AZURE_CLOUD_PORTAL_URL"]
    option :cloud_publishing_profile_url, default: ENV["AZURE_CLOUD_PUBLISHING_PROFILE_URL"]
    option :cloud_management_endpoint_url, default: ENV["AZURE_CLOUD_MANAGEMENT_ENDPOINT_URL"]
    option :cloud_resoruce_management_url, default: ENV["AZURE_CLOUD_RESOURCE_MANAGEMENT_URL"]
    option :cloud_sql_management_endpoint_url, default: ENV["AZURE_CLOUD_SQL_MANAGEMENT_ENDPOINT_URL"]
    option :cloud_sql_server_hostname_suffix, default: ENV["AZURE_CLOUD_SQL_SERVER_HOSTNAME_SUFFIX"]
    option :cloud_gallery_endpoint_url, default: ENV["AZURE_CLOUD_GALLERY_ENDPOINT_URL"]
    option :cloud_ad_endpoint_url, default: ENV["AZURE_CLOUD_AD_ENDPOINT_URL"]
    option :cloud_ad_resource_id, default: ENV["AZURE_CLOUD_AD_RESOURCE_ID"]
    option :cloud_ad_vault_resource_id, default: ENV["AZURE_CLOUD_AD_VAULT_RESOURCE_ID"]
    option :cloud_ad_graph_resource_id, default: ENV["AZURE_CLOUD_AD_GRAPH_RESOURCE_ID"]
    option :cloud_api_version, default: ENV["AZURE_CLOUD_GRAPH_API_VERSION"]
    option :cloud_storage_endpoint_suffix, default: ENV["AZURE_CLOUD_STORAGE_ENDPOINT_SUFFIX"]
    option :cloud_key_vault_dns_suffix, default: ENV["AZURE_CLOUD_KEY_VAULT_DNS_SUFFIX"]
    option :cloud_datalake_store_fs_endpoint_suffix, default: ENV["AZURE_CLOUD_DATALAKE_STORE_FS_ENDPOINT_SUFFIX"]
    option :cloud_datalake_analytics_catalog_and_job_endpoint_suffix, default: ENV["AZURE_CLOUD_DATALAKE_ANALYTICS_CATALOG_AND_JOB_ENDPOINT_SUFFIX"]
    # END NEW CLOUD CONFIG
    
    # This can provide the client id and secret
    option :credentials_file, default: ENV["AZURE_CRED_FILE"]

    def connection(_ = nil)
      @connection ||= Connection.new(@options, logger: logger)
    end

    class Connection < BaseConnection

      class ApiProfileError < Train::TransportError; end
      class ApiNameSpaceError < Train::TransportError; end
    
      attr_reader :options, :logger

      DEFAULT_FILE = ::File.join(Dir.home, ".azure", "credentials")

      def initialize(options, logger: nil)
        @logger = logger unless logger.nil?

        @apis = {}

        # Override for any cli options
        # azure://subscription_id
        options[:subscription_id] = options[:host] || options[:subscription_id]
        super(options)

        @cache_enabled[:api_call] = true
        @cache[:api_call] = {}

        if @options[:client_secret].nil? && @options[:client_id].nil?
          options[:credentials_file] = DEFAULT_FILE if options[:credentials_file].nil?
          @options.merge!(Helpers::Azure::FileCredentials.parse(**@options))
        end

        @options[:msi_port] = @options[:msi_port].to_i unless @options[:msi_port].nil?

        # additional platform details
        release = Gem.loaded_specs["azure_mgmt_resources"].version
        @platform_details = { release: "azure_mgmt_resources-v#{release}" }

        connect
      end


      def active_cloud
        @active_cloud_config = {
          :name => @options[:cloud_name],
          :portal_url => @options[:cloud_portal_url],
          :publishing_profile_url => @options[:cloud_publishing_profile_url],
          :management_endpoint_url => @options[:cloud_management_endpoint_url],
          :resource_manager_endpoint_url => @options[:cloud_resoruce_management_url],
          :sql_management_endpoint_url => @options[:cloud_sql_management_endpoint_url],
          :sql_server_hostname_suffix => @options[:cloud_sql_server_hostname_suffix],
          :gallery_endpoint_url => @options[:cloud_gallery_endpoint_url],
          :active_directory_endpoint_url => @options[:cloud_ad_endpoint_url],
          :active_directory_resource_id => @options[:cloud_ad_resource_id],
          :active_directory_graph_resource_id => @options[:cloud_ad_graph_resource_id],
          :active_directory_graph_api_version => @options[:cloud_api_version],
          :storage_endpoint_suffix => @options[:cloud_storage_endpoint_suffix],
          :key_vault_dns_suffix => @options[:cloud_key_vault_dns_suffix],
          :datalake_store_filesystem_endpoint_suffix => @options[:cloud_datalake_store_fs_endpoint_suffix],
          :datalake_analytics_catalog_and_job_endpoint_suffix => @options[:cloud_datalake_analytics_catalog_and_job_endpoint_suffix]
        }
        @active_cloud = ::MsRestAzure::AzureEnvironments::AzureEnvironment.new(@active_cloud_config)

        logger.debug "Using custom azure cloud configuration.\n#{@active_cloud_config}"

        @active_cloud
      rescue ArgumentError => e
        @active_cloud = ::MsRestAzure::AzureEnvironments::AzureCloud
        logger.debug "Custom cloud configuration not set. Using default cloud #{@active_cloud}"

        # if not configured, use default US cloud
        @active_cloud
      end

      def fetch_profile(azure_module = ::Azure::Resources)
        logger.debug "Fetching profile #{options[:api_profile]} for azure module #{azure_module}"
        return azure_module::Profiles.const_get(@options[:api_profile]) if azure_module::Profiles.const_defined? @options[:api_profile]
        
        raise ApiProfileError.new("Error fetching api profile #{@options[:api_profile]}. Profile does not exist. Available profiles #{azure_module::Profiles.constants}")
      end

      def platform
        force_platform!("azure", @platform_details)
      end

      def azure_client(azure_module = ::Azure::Resources, opts = {})
        if cache_enabled?(:api_call)
          return @cache[:api_call][azure_module.to_s.to_sym] unless @cache[:api_call][azure_module.to_s.to_sym].nil?
        end

        if azure_module == ::Azure::Resources
          @credentials[:base_url] = active_cloud.resource_manager_endpoint_url
          client = Management.client(@credentials, active_cloud, fetch_profile(azure_module))
        elsif azure_module == ::Azure::GraphRbac
          client = GraphRbac.client(@credentials, active_cloud, fetch_profile(azure_module))
        elsif azure_module == ::Azure::KeyVault
          @credentials[:token_audience] = @options[:cloud_ad_vault_resource_id]
          client = Vault.client(opts[:vault_name], @credentials, active_cloud, fetch_profile(azure_module))
        else
          raise ::Train::UserError, "Cannot create client for unknown Azure Resource '#{azure_module}'"
        end

        # Cache if enabled
        @cache[:api_call][azure_module.to_s.to_sym] ||= client if cache_enabled?(:api_call)

        client
      end
      
      def connect
        ad_settings = ::MsRestAzure::ActiveDirectoryServiceSettings.get_settings(active_cloud)
        if msi_auth?
          # this needs set for azure cloud to authenticate
          ENV["MSI_VM"] = "true"
          provider = ::MsRestAzure::MSITokenProvider.new(@options[:msi_port], ad_settings)
        else
          provider = ::MsRestAzure::ApplicationTokenProvider.new(
            @options[:tenant_id],
            @options[:client_id],
            @options[:client_secret],
            ad_settings
          )
        end

        @credentials = {
          credentials: ::MsRest::TokenCredentials.new(provider),
          subscription_id: @options[:subscription_id],
          tenant_id: @options[:tenant_id],
          active_directory_settings: ad_settings
        }
        @credentials[:client_id] = @options[:client_id] unless @options[:client_id].nil?
        @credentials[:client_secret] = @options[:client_secret] unless @options[:client_secret].nil?
      end

      def uri
        "azure://#{@options[:subscription_id]}"
      end

      # Returns the api version for the specified resource type
      #
      # If an api version has been specified in the options then the apis version table is updated
      # with that value and it is returned
      #
      # However if it is not specified, or multiple types are being interrogated then this method
      # will interrogate Azure for each of the types versions and pick the latest one. This is added
      # to the apis table so that it can be retrieved quickly again of another one of those resources
      # is encountered again in the resource collection.
      #
      # @param string resource_type The resource type for which the API is required
      # @param hash options Options have that have been passed to the resource during the test.
      # @option opts [String] :group_name Resource group name
      # @option opts [String] :type Azure resource type
      # @option opts [String] :name Name of specific resource to look for
      # @option opts [String] :apiversion If looking for a specific item or type specify the api version to use
      #
      # @return string API Version of the specified resource type
      def get_api_version(resource_type, options)
        logger.debug "Fetching api version for resource type #{resource_type}. Options: #{options}"

        # if an api version has been set in the options, add to the apis hashtable with
        # the resource type
        if options[:apiversion]
          logger.debug "Using api version #{options[:apiversion]} supplied by options #{options}"
          @apis[resource_type] = options[:apiversion]
        else
          # only attempt to get the api version from Azure if the resource type
          # is not present in the apis hashtable
          unless @apis.key?(resource_type)
            logger.debug "Api version not found for resource type #{resource_type} in api hash table, fetching from Azure API."

            # determine the namespace for the resource type
            namespace, type = resource_type.split(%r{/}, 2)

            client = azure_client(::Azure::Resources)
            begin
              provider = client.providers.get(namespace)
              logger.debug "Got provider for namespace #{namespace}\n#{provider.to_s}"
            rescue ::MsRestAzure::AzureOperationError => e
              logger.debug "Failed to fetch provider for namespace #{namespace}. Error: #{e}"
              raise ApiNameSpaceError.new("Unabled to fetch api namespace '#{namespace}' in api profile '#{@options[:api_profile]}'. This is most likely caused by using the incorrect api profile for your system. If you are sure this is wrong, you can overwrite this by supplying get_api_profiles with the argument `api_profile: <version>`")
            end

            # get the latest API version for the type
            # assuming that this is the first one in the list
            api_versions = (provider.resource_types.find { |v| v.resource_type.downcase == type.downcase })&.api_versions
            logger.debug "Retrieved the following valid api versions for resource type #{resource_type}.\n#{api_versions}"
            raise ApiNameSpaceError.new("Unabled to find resource type '#{type}' in namespace '#{namespace}' for api profile '#{@options[:api_profile]}'. This could mean that this api profile does not support that resource type.") if api_versions.nil?
            @apis[resource_type] = api_versions[0]
          end
        end

        # return the api version for the type
        @apis[resource_type]
      end

      def unique_identifier
        options[:subscription_id] || options[:tenant_id]
      end

      def msi_auth?
        @options[:client_id].nil? && @options[:client_secret].nil? && port_open?(@options[:msi_port])
      end

      private

      def port_open?(port, seconds = 3)
        Timeout.timeout(seconds) do
          begin
            TCPSocket.new("localhost", port).close
            true
          rescue SystemCallError
            false
          end
        end
      rescue Timeout::Error
        false
      end
    end
  end
end
