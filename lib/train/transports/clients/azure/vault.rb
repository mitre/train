# encoding: utf-8

require "azure_mgmt_key_vault"

# Wrapper class for ::Azure::KeyVault::Profiles::Latest::Mgmt::Client allowing custom configuration,
# for example, defining additional settings for the ::MsRestAzure::ApplicationTokenProvider.
class Vault
  RESOURCE_ENDPOINT = "https://vault.azure.net".freeze

  def self.client(vault_name, credentials, active_cloud, active_profile)
    raise ::Train::UserError, "Vault Name cannot be nil" if vault_name.nil?

    credentials = credentials.clone
    credentials[:credentials] = ::MsRest::TokenCredentials.new(provider(credentials, active_cloud))
    credentials[:base_url] = api_endpoint(vault_name, active_cloud)
    credentials[:active_directory_settings] = settings(credentials, active_cloud)

    active_profile::Mgmt::Client.new(credentials)
  end

  def self.provider(credentials, active_cloud)
    ::MsRestAzure::ApplicationTokenProvider.new(
      credentials[:tenant_id],
      credentials[:client_id],
      credentials[:client_secret],
      settings(credentials, active_cloud)
    )
  end

  def self.api_endpoint(vault_name, active_cloud)
    "https://#{vault_name}#{active_cloud.key_vault_dns_suffix}"
  end

  def self.settings(credentials, active_cloud)
    client_settings = MsRestAzure::ActiveDirectoryServiceSettings.get_settings(active_cloud)
    client_settings.token_audience = credentials[:token_audience] || RESOURCE_ENDPOINT
    client_settings
  end

  private_class_method :provider, :api_endpoint, :settings
end
