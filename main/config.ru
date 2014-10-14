require 'bundler/setup'
Bundler.require(:default)

require_relative '../authentication/authentication_app'
require_relative 'cool_app'

map '/' do
  run CoolApp
end

map '/auth' do
  run AuthenticationApp
end

