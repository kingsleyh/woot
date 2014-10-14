require 'totally_lazy'
require 'lazy_records'
require 'sinatra/base'
require 'oj'
require_relative 'providers/facebook'
require_relative 'providers/twitter'
require_relative '../model/user'


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

  get '/signup' do
    <<-html
     <form method="post" action="/auth/signup">
     email:<input type="text" name="email" id="email">
     password:<input type="password" name="password" id="password">
     password_confirmation:<input type="password" name="password_confirmation" id="password_confirmation">
    <input type="submit" value="Submit">
    </form>
    html
  end

  get '/signin' do
    <<-html
   <form method="post" action="/auth/signin">
   email:<input type="email" name="email" id="email">
   password:<input type="password" name="password" id="password">
   <input type="submit" value="Submit">
   </form>
    html
  end

  post '/signup' do
    email = params[:email]
    password = params[:password]
    password_confirmation = params[:password_confirmation]
    user = User.new(:email,email,:password,password,:password_confirmation,password_confirmation)
    if user.save
      halt 201, j(status:'success')
    else
      j(errors:user.errors)
    end
  end

  post '/signin' do
    email = params[:email]
    password = params[:password]

    user = User.find(where(email:equals(email)))
    if user.is_some? &&  user.get.head.password_hash == BCrypt::Engine.hash_secret(password, user.get.head.password_salt)
     halt 200, j(user.get.head.get_hash)
    else
      halt 401, j(status:'unauthorised',message:'Invalid email or password')
    end
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