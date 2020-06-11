# encoding: utf-8

require "azure_graph_rbac"

# Wrapper class for ::Azure::GraphRbac::Profiles::Latest::Client allowing custom configuration,
# for example, defining additional settings for the ::MsRestAzure::ApplicationTokenProvider.
class GraphRbac
  def self.client(credentials, active_cloud, active_profile)
    credentials = credentials.clone
    credentials[:credentials] = ::MsRest::TokenCredentials.new(provider(credentials, active_cloud))
    credentials[:base_url] = api_endpoint(active_cloud)
    credentials[:active_directory_settings] = settings(credentials, active_cloud)

    active_profile::Client.new(credentials)
  end

  def self.provider(credentials, active_cloud)
    ::MsRestAzure::ApplicationTokenProvider.new(
      credentials[:tenant_id],
      credentials[:client_id],
      credentials[:client_secret],
      settings(credentials, active_cloud)
    )
  end

  def self.api_endpoint(active_cloud)
    active_cloud.active_directory_graph_resource_id
  end

  def self.settings(credentials, active_cloud)
    client_settings = MsRestAzure::ActiveDirectoryServiceSettings.get_settings(active_cloud)
    client_settings.token_audience = api_endpoint(active_cloud)
    client_settings
  end

  private_class_method :provider, :settings
end
