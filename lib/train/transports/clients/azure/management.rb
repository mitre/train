# encoding: utf-8

require "azure_mgmt_resources"

# Wrapper class for ::Azure::Resource::Profiles::<profile version> allowing custom configuration,
# for example, defining additional settings for the ::MsRestAzure::ApplicationTokenProvider.
class Management
  def self.client(credentials, active_cloud, active_profile)
    credentials = credentials.clone
    active_profile::Mgmt::Client.new(credentials)
  end
end
