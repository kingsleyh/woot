require 'rack/test'
require_relative '../authentication_app'

def app
  AuthenticationApp.new
end

RSpec.configure do |config|
  config.color = true
  config.include Rack::Test::Methods
end

def jl(v)
  Oj.load(v)
end