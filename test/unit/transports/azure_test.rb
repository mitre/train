# encoding: utf-8

require "helper"

# Required because this test file acesses classes under Azure::
require "azure_mgmt_resources"
require "azure_graph_rbac"
require "azure_mgmt_key_vault"

describe "azure transport" do
  def transport(options = nil)
    ENV["AZURE_TENANT_ID"] = "test_tenant_id"
    ENV["AZURE_CLIENT_ID"] = "test_client_id"
    ENV["AZURE_CLIENT_SECRET"] = "test_client_secret"
    ENV["AZURE_SUBSCRIPTION_ID"] = "test_subscription_id"
    ENV["AZURE_API_PROFILE"] = nil
    
    # CUSTOM CLOUD
    ENV["AZURE_CLOUD_NAME"] = nil
    ENV["AZURE_CLOUD_PORTAL_URL"] = nil
    ENV["AZURE_CLOUD_PUBLISHING_PROFILE_URL"] = nil
    ENV["AZURE_CLOUD_MANAGEMENT_ENDPOINT_URL"] = nil
    ENV["AZURE_CLOUD_RESOURCE_MANAGEMENT_URL"] = nil
    ENV["AZURE_CLOUD_SQL_MANAGEMENT_ENDPOINT_URL"] = nil
    ENV["AZURE_CLOUD_SQL_SERVER_HOSTNAME_SUFFIX"] = nil
    ENV["AZURE_CLOUD_GALLERY_ENDPOINT_URL"] = nil
    ENV["AZURE_CLOUD_AD_ENDPOINT_URL"] = nil
    ENV["AZURE_CLOUD_AD_RESOURCE_ID"] = nil
    ENV["AZURE_CLOUD_AD_VAULT_RESOURCE_ID"] = nil
    ENV["AZURE_CLOUD_AD_GRAPH_RESOURCE_ID"] = nil
    ENV["AZURE_CLOUD_GRAPH_API_VERSION"] = nil
    ENV["AZURE_CLOUD_STORAGE_ENDPOINT_SUFFIX"] = nil
    ENV["AZURE_CLOUD_KEY_VAULT_DNS_SUFFIX"] = nil
    ENV["AZURE_CLOUD_DATALAKE_STORE_FS_ENDPOINT_SUFFIX"] = nil
    ENV["AZURE_CLOUD_DATALAKE_ANALYTICS_CATALOG_AND_JOB_ENDPOINT_SUFFIX"] = nil

    # need to require this at here as it captures the envs on load
    require "train/transports/azure"
    Train::Transports::Azure.new(options)
  end
  let(:connection) { transport.connection }
  let(:options) { connection.instance_variable_get(:@options) }
  let(:cache) { connection.instance_variable_get(:@cache) }
  let(:credentials) { connection.instance_variable_get(:@credentials) }

  describe "options" do
    it "defaults to env options" do
      _(options[:tenant_id]).must_equal "test_tenant_id"
      _(options[:client_id]).must_equal "test_client_id"
      _(options[:client_secret]).must_equal "test_client_secret"
      _(options[:subscription_id]).must_equal "test_subscription_id"
    end

    it "allows for options override" do
      transport = transport(subscription_id: "102", client_id: "717")
      options = transport.connection.instance_variable_get(:@options)
      _(options[:tenant_id]).must_equal "test_tenant_id"
      _(options[:client_id]).must_equal "717"
      _(options[:client_secret]).must_equal "test_client_secret"
      _(options[:subscription_id]).must_equal "102"
    end

    it "allows uri parse override" do
      transport = transport(host: "999")
      options = transport.connection.instance_variable_get(:@options)
      _(options[:tenant_id]).must_equal "test_tenant_id"
      _(options[:subscription_id]).must_equal "999"
    end
  end

  describe "platform" do
    it "returns platform" do
      plat = connection.platform
      _(plat.name).must_equal "azure"
      _(plat.family_hierarchy).must_equal %w{cloud api}
    end
  end

  describe "fetch_profile" do
    it "can fetch default profile" do
      resource = Azure::Resources
      connection.instance_variable_set(:@options, { api_profile: 'Latest' })
      api_profile = connection.fetch_profile
      _(api_profile).must_equal resource::Profiles::Latest
    end

    it "can fetch graph profile" do
      resource = Azure::GraphRbac
      connection.instance_variable_set(:@options, { api_profile: 'Latest' })
      api_profile = connection.fetch_profile(resource)
      _(api_profile).must_equal resource::Profiles::Latest
    end

    it "can fetch vault profile" do
      resource = Azure::KeyVault
      connection.instance_variable_set(:@options, { api_profile: 'Latest' })
      api_profile = connection.fetch_profile(resource)
      _(api_profile).must_equal resource::Profiles::Latest
    end

    it "can fetch older profile" do
      resource = Azure::Resources
      connection.instance_variable_set(:@options, { api_profile: 'V2017_03_09' })
      api_profile = connection.fetch_profile
      _(api_profile).must_equal resource::Profiles::V2017_03_09
    end

    it "cannot load non-existant profile" do
      connection.instance_variable_set(:@options, { api_profile: 'DOESNT_EXIST' })

      assert_raises(Train::Transports::Azure::Connection::ApiProfileError) do
        connection.fetch_profile
      end
    end
  end

  describe "active_cloud" do

    custom_cloud_configuration = {
      :cloud_name => "CUSTOM_CLOUD_NAME",
      :cloud_portal_url => "CUSTOM_CLOUD_PORTAL_URL",
      :cloud_publishing_profile_url => "CUSTOM_CLOUD_PUBLISHING_PROFILE_URL",
      :cloud_management_endpoint_url => "CUSTOM_CLOUD_MANAGEMENT_ENDPOINT_URL",
      :cloud_resoruce_management_url => "CUSTOM_CLOUD_RESOURCE_MANAGEMENT_URL",
      :cloud_sql_management_endpoint_url => "CUSTOM_CLOUD_SQL_MANAGEMENT_ENDPOINT_URL",
      :cloud_sql_server_hostname_suffix => "CUSTOM_SQL_SERVER_HOSTNAME_SUFFIX",
      :cloud_gallery_endpoint_url => "CUSTOM_GALLERY_ENDPOINT_URL",
      :cloud_ad_endpoint_url => "CUSTOM_CLOUD_AD_ENDPOINT_URL",
      :cloud_ad_resource_id => "CUSTOM_CLOUD_AD_RESOURCE_ID",
      :cloud_ad_graph_resource_id => "CUSTOM_CLOUD_AD_GRAPH_RESOURCE_ID",
      :cloud_api_version => "CUSTOM_CLOUD_API_VERSION",
      :cloud_storage_endpoint_suffix => "CUSTOM_CLOUD_STORAGE_ENDPOINT_SUFFIX",
      :cloud_key_vault_dns_suffix => "CUSTOM_CLOUD_KEY_VAULT_DNS_SUFFIX",
      :cloud_datalake_store_fs_endpoint_suffix => "CUSTOM_CLOUD_DATALAKE_STORE_FS_ENDPOINT_SUFFIX",
      :cloud_datalake_analytics_catalog_and_job_endpoint_suffix => "CUSTOM_CLOUD_DATALAKE_ANALYTICS_CATALOG_AND_JOB_ENDPOINT_SUFFIX"
    }
    
    it "can create custom cloud" do
      connection.instance_variable_set(:@options, custom_cloud_configuration)

      cloud = connection.active_cloud
      _(cloud.name).must_equal 'CUSTOM_CLOUD_NAME'
      _(cloud.portal_url).must_equal 'CUSTOM_CLOUD_PORTAL_URL'
      _(cloud.publishing_profile_url).must_equal 'CUSTOM_CLOUD_PUBLISHING_PROFILE_URL'
      _(cloud.management_endpoint_url).must_equal 'CUSTOM_CLOUD_MANAGEMENT_ENDPOINT_URL'
      _(cloud.resource_manager_endpoint_url).must_equal 'CUSTOM_CLOUD_RESOURCE_MANAGEMENT_URL'
      _(cloud.sql_management_endpoint_url).must_equal 'CUSTOM_CLOUD_SQL_MANAGEMENT_ENDPOINT_URL'
      _(cloud.sql_server_hostname_suffix).must_equal 'CUSTOM_SQL_SERVER_HOSTNAME_SUFFIX'
      _(cloud.gallery_endpoint_url).must_equal 'CUSTOM_GALLERY_ENDPOINT_URL'
      _(cloud.active_directory_endpoint_url).must_equal 'CUSTOM_CLOUD_AD_ENDPOINT_URL'
      _(cloud.active_directory_resource_id).must_equal 'CUSTOM_CLOUD_AD_RESOURCE_ID'
      _(cloud.active_directory_graph_resource_id).must_equal 'CUSTOM_CLOUD_AD_GRAPH_RESOURCE_ID'
      _(cloud.active_directory_graph_api_version).must_equal 'CUSTOM_CLOUD_API_VERSION'
      _(cloud.storage_endpoint_suffix).must_equal 'CUSTOM_CLOUD_STORAGE_ENDPOINT_SUFFIX'
      _(cloud.key_vault_dns_suffix).must_equal 'CUSTOM_CLOUD_KEY_VAULT_DNS_SUFFIX'
      _(cloud.datalake_store_filesystem_endpoint_suffix).must_equal 'CUSTOM_CLOUD_DATALAKE_STORE_FS_ENDPOINT_SUFFIX'
      _(cloud.datalake_analytics_catalog_and_job_endpoint_suffix).must_equal 'CUSTOM_CLOUD_DATALAKE_ANALYTICS_CATALOG_AND_JOB_ENDPOINT_SUFFIX'
    end

    it "defaults to Azure US Cloud" do
      cloud = connection.active_cloud
      _(cloud.is_a?(MsRestAzure::AzureEnvironments::AzureEnvironment)).must_equal true
      _(cloud.name).must_equal 'AzureCloud'
    end
  end

  describe "azure_client" do
    class AzureResource
      attr_reader :hash
      def initialize(hash)
        @hash = hash
      end
    end

    it "can use azure_client with caching" do
      resource = Azure::Resources
      connection.instance_variable_set(:@credentials, {})
      client = connection.azure_client(resource)
      _(client.is_a?(resource::Profiles::Latest::Mgmt::Client)).must_equal true
      _(cache[:api_call].count).must_equal 1
    end

    it "can use azure_client without caching" do
      resource = Azure::Resources
      connection.instance_variable_set(:@credentials, {})
      connection.disable_cache(:api_call)
      client = connection.azure_client(resource)
      _(client.is_a?(resource::Profiles::Latest::Mgmt::Client)).must_equal true
      _(cache[:api_call].count).must_equal 0
    end

    it "can use azure_client default client" do
      management_api_client = Azure::Resources::Profiles::Latest::Mgmt::Client
      client = connection.azure_client
      _(client.class).must_equal management_api_client
    end

    it "can use azure_client graph client" do
      graph_api_client = Azure::GraphRbac
      client = connection.azure_client(graph_api_client)
      _(client.class).must_equal graph_api_client::Profiles::Latest::Client
    end

    it "can use azure_client vault client" do
      vault_api_client = ::Azure::KeyVault
      client = connection.azure_client(vault_api_client, vault_name: "Test Vault")
      _(client.class).must_equal vault_api_client::Profiles::Latest::Mgmt::Client
    end

    it "cannot instantiate azure_client vault client without a vault name" do
      vault_api_client = ::Azure::KeyVault::Profiles::Latest::Mgmt::Client
      assert_raises(Train::UserError) do
        connection.azure_client(vault_api_client)
      end
    end
  end

  describe "connect" do
    it "validate credentials" do
      connection.connect
      token = credentials[:credentials].instance_variable_get(:@token_provider)
      _(token.class).must_equal MsRestAzure::ApplicationTokenProvider

      _(credentials[:credentials].class).must_equal MsRest::TokenCredentials
      _(credentials[:tenant_id]).must_equal "test_tenant_id"
      _(credentials[:client_id]).must_equal "test_client_id"
      _(credentials[:client_secret]).must_equal "test_client_secret"
      _(credentials[:subscription_id]).must_equal "test_subscription_id"
    end

    it "validate msi credentials" do
      options[:client_id] = nil
      options[:client_secret] = nil
      Train::Transports::Azure::Connection.any_instance.stubs(:port_open?).returns(true)

      connection.connect
      token = credentials[:credentials].instance_variable_get(:@token_provider)
      _(token.class).must_equal MsRestAzure::MSITokenProvider

      _(credentials[:credentials].class).must_equal MsRest::TokenCredentials
      _(credentials[:tenant_id]).must_equal "test_tenant_id"
      _(credentials[:subscription_id]).must_equal "test_subscription_id"
      _(credentials[:client_id]).must_be_nil
      _(credentials[:client_secret]).must_be_nil
      _(options[:msi_port]).must_equal 50342
    end
  end

  describe "unique_identifier" do
    it "returns a subscription id" do
      _(connection.unique_identifier).must_equal "test_subscription_id"
    end

    it "returns a tenant id" do
      options = connection.instance_variable_get(:@options)
      options[:subscription_id] = nil
      _(connection.unique_identifier).must_equal "test_tenant_id"
    end
  end
end
