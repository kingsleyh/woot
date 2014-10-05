require 'totally_lazy'
require 'lazy_records'
require 'sinatra/base'
require 'oj'
require_relative 'providers/facebook'
require_relative 'providers/twitter'


class AuthenticationApp < Sinatra::Application

  enable :sessions
  set :session_secret, 'super secret'

  use OmniAuth::Builder do
    provider :facebook, '780005678689514', '983ad6fed1974d2ca64924659e218dac'
    provider :twitter, 'jdPJky59w2iRXIBlTcMJPKYY5', '3mGxCs7iwIOs6CB6ZXRGvHjVIhyhaBG4SU5RFZcgzD2PTnZSTC'
  end

  get '/' do
    content_type :json
    j(server_name: 'Authentication Server')
  end

  get '/auth/facebook/callback' do
    Facebook.info(request.env['omniauth.auth'])
  end

  get '/auth/twitter/callback' do
    Twitter.info(request.env['omniauth.auth'])
  end

  private

  def j(v)
    Oj.dump(v)
  end


end