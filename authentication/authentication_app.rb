require 'totally_lazy'
require 'lazy_records'
require 'sinatra/base'
require 'oj'
require 'encrypted_cookie'
require 'rack/csrf'
require_relative 'providers/facebook'
require_relative 'providers/twitter'
require_relative 'repository/users'
require_relative 'repository/identities'
require_relative 'repository/sessions'
require_relative 'model/aggregates/session_detail'
require_relative 'model/aggregates/user_detail'
require_relative 'util/utils'

class AuthenticationApp < Sinatra::Application

  enable :sessions
  set :session_secret, 'e60bef57fddde8683fa6376252087472b4b5be170909c50cbb5201fde1688a37'

  # cookie_settings = {
  #     :key => 'rack.session',
  #     :path => '/',
  #     :expire_after => 86400, # In seconds, 1 day.
  #     :secret => 'e60bef57fddde8683fa6376252087472b4b5be170909c50cbb5201fde1688a37',
  #     :secure => true,
  #     :httponly => true
  # }
  # AES encryption of session cookies
  # use Rack::Session::EncryptedCookie, cookie_settings
  # use Rack::Session::Cookie, cookie_settings
  # use Rack::Csrf, raise: true

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

  get '/update' do
    <<-html
     <form method="post" action="/auth/update">
     email:<input type="text" name="email" id="email">
     password:<input type="password" name="password" id="password">
     password_confirmation:<input type="password" name="password_confirmation" id="password_confirmation">
    <input type="submit" value="Submit">
    </form>
    html
  end

  get '/identities/remove' do
    <<-html
      <form method="post" action="/auth/identities">
      provider:<input type="text" name="provider" id="provider">
       <input type="submit" value="Remove">
      </form>
    html
  end

  get '/sessions/remove' do
    <<-html
      <form method="post" action="/auth/sessions">
      session_id:<input type="text" name="session_id" id="session_id">
       <input type="submit" value="Remove">
      </form>
    html
  end

  post '/signup' do
    u = Users.create(params[:email], params[:password], params[:password_confirmation])
    # user.is_valid? ? halt(201, j(status: 'success')) : j(errors: user.errors)
    if u.is_valid?
      user = Users.find(where(email: equals(params[:email])))
      session[:user_session] = Utils.generate_session_id
      ip_address = option(request.ip).get_or_else('')
      user_agent = option(request.user_agent).get_or_else('')
      Sessions.create(user.get.head.id, session[:user_session], Time.now.to_i, ip_address, user_agent, 'form')
      halt 200, j(for_user(UserDetail.new(user.get.head.id)))
    else
      halt(201, j(status: 'error', errors: u.errors))
    end
  end

  post '/signin' do
    if already_logged_in?
      halt(401, j(status: 'error', message: 'Already logged in'))
    else
      email = params[:email]
      password = params[:password]

      user = Users.find(where(email: equals(email)))
      if user.is_some? && user.get.head.password_hash == BCrypt::Engine.hash_secret(password, user.get.head.password_salt)
        session[:user_session] = Utils.generate_session_id
        ip_address = option(request.ip).get_or_else('')
        user_agent = option(request.user_agent).get_or_else('')
        Sessions.create(user.get.head.id, session[:user_session], Time.now.to_i, ip_address, user_agent, 'form')
        halt 200, j(for_user(UserDetail.new(user.get.head.id)))
      else
        halt 401, j(status: 'unauthorised', message: 'Invalid email or password')
      end
    end
  end

  get '/whoami' do
    error_if_not_logged_in
    user_detail = find_user
    if user_detail.user.empty?
      halt 401, j(status: 'unauthorised', message: 'Not logged in')
    else
      halt 200, j(for_user(user_detail))
    end
  end

  get '/signout' do
    error_if_not_logged_in
    user = find_user.user
    if user.empty?
      halt 401, j(status: 'unauthorised', message: 'Not logged in')
    else
      Sessions.remove(where(session_id: equals(session[:user_session])))
      halt 200, j(status: 'logged out')
    end
  end

  def find_user
    user_session = Sessions.find(where(session_id: equals(session[:user_session])))
    user_session.is_some? ? UserDetail.new(user_session.get.head.user_id) : empty
  end

  post '/update' do
    error_if_not_logged_in
    user = find_user.user
    if user.empty?
      halt 401, j(status: 'unauthorised', message: 'Not logged in')
    else
      u = Users.update(user.head.id, option(params[:email]), option(params[:password]), option(params[:password_confirmation]))
      u.is_valid? ? halt(201, j(status: 'success', message: 'updated user')) : halt(401, j(status: 'error', errors: u.errors))
    end
  end

  get '/destroy' do
    error_if_not_logged_in
    user = find_user.user
    user.empty? ?
        halt(401, j(status: 'unauthorised', message: 'Not logged in')) :
        halt(200, j(status: 'not implemented yet!'))
  end

  get '/identities' do
    error_if_not_logged_in
    user_detail = find_user
    if user_detail.user.empty?
      halt 401, j(status: 'unauthorised', message: 'Not logged in')
    else
      halt 200, j(identities: user_detail.identities.map { |i| i.provider }.entries)
    end
  end

  get '/sessions' do
    error_if_not_logged_in
    user_detail = find_user
    if user_detail.user.empty?
      halt 401, j(status: 'unauthorised', message: 'Not logged in')
    else
      halt 200, j(sessions: user_detail.sessions.map { |s| {session_id: s.session_id,
                                                            start_time: Time.at(s.start_time.to_i).to_s,
                                                            ip_address: s.ip_address,
                                                            user_agent: s.user_agent,
                                                            login_method: s.login_method} }.entries,
                  current_session: session[:user_session])
    end
  end

  post '/identities' do
    error_if_not_logged_in
    user = find_user.user
    provider = params[:provider]
    if user.empty?
      halt 401, j(status: 'unauthorised', message: 'Not logged in')
    else
      if Identities.find(where(provider: equals(provider), user_id: equals(user.head.id))).is_some?
        Identities.remove(where(provider: equals(provider)))
        Identities.find(where(provider: equals(provider), user_id: equals(user.head.id))).is_none? ? halt(201, j(status: 'success')) : halt(401, j(errors: 'Could not remove identity for provier: ' + provider))
      else
        halt(401, j(status: 'error', message: 'unknown provider: ' + provider))
      end
    end
  end

  post '/sessions' do
    error_if_not_logged_in
    user = find_user.user
    session_id = params[:session_id]
    if user.empty?
      halt 401, j(status: 'unauthorised', message: 'Not logged in')
    else
      if Sessions.find(where(session_id: equals(session_id), user_id: equals(user.head.id))).is_some?
        Sessions.remove(where(session_id: equals(session_id)))
        Sessions.find(where(session_id: equals(session_id), user_id: equals(user.head.id))).is_none? ? halt(201, j(status: 'success')) : halt(401, j(errors: 'Could not remove session with session id: ' + session_id))
      else
        halt(401, j(status: 'error', message: 'unknown session id: ' + session_id))
      end
    end
  end

  get '/auth/facebook/callback' do
    add_social_login(Facebook.info(request.env['omniauth.auth']))
  end

  get '/auth/twitter/callback' do
    add_social_login(Twitter.info(request.env['omniauth.auth']))
  end

  private

  def already_logged_in?
    Sessions.find(where(session_id: equals(session[:user_session]))).is_some?
  end

  def error_if_not_logged_in
    halt 401, j(status: 'unauthorised', message: 'Not logged in') unless already_logged_in?
  end

  def for_user(ud)
    h = ud.user.head.get_hash
    {id: h[:id],
     email: h[:email],
     session_id: ud.current_session(session[:user_session]),
     sessions: ud.sessions.map { |s| {session_id: s.session_id, start_time: Time.at(s.start_time.to_i).to_s,
                                      ip_address: s.ip_address,
                                      user_agent: s.user_agent,
                                      login_method: s.login_method} }.entries,
     identities: ud.identities.map { |i| i.provider }.entries
    }
  end

  def j(v)
    Oj.dump(v)
  end

  def add_social_login(info)
    if already_logged_in?
      add_provider(info)
    else
      identity, provider, uid = find_existing_identity(info)
      if identity.is_some?
        login_existing_user(identity, provider)
      else
        create_identity(info, provider, uid)
      end
    end
  end

  def add_provider(info)
    provider = info[:provider]
    uid = info[:uid]
    identity = Identities.find(where(provider: equals(provider), uid: equals(uid)))
    if identity.is_none?
      user = find_user.user
      Identities.create(user.head.id, provider, uid)
      halt(201, j(status: 'success', message: 'added ' + provider))
    else
      halt(401, j(status: 'error', message: 'The provider ' + provider + ' is already linked to an account'))
    end
  end

  def login_existing_user(identity, provider)
    user = Users.find(where(id: equals(identity.get.head.user_id)))
    if user.is_none?
      halt 401, j(status: 'unauthorised', message: 'Invalid user')
    else
      session[:user_session] = Utils.generate_session_id
      ip_address = option(request.ip).get_or_else('')
      user_agent = option(request.user_agent).get_or_else('')
      Sessions.create(user.get.head.id, session[:user_session], Time.now.to_i, ip_address, user_agent, provider)
      halt 200, j(for_user(UserDetail.new(user.get.head.id)))
    end
  end

  def find_existing_identity(info)
    provider = info[:provider]
    uid = info[:uid]
    identity = Identities.find(where(provider: equals(provider), uid: equals(uid)))
    return identity, provider, uid
  end

  def create_identity(info, provider, uid)
    user = Users.create(info[:email], uid, uid)
    if user.is_valid?
      u = Users.find(where(email: equals(info[:email])))
      Identities.create(u.get.head.id, provider, uid)
      session[:user_session] = Utils.generate_session_id
      ip_address = option(request.ip).get_or_else('')
      user_agent = option(request.user_agent).get_or_else('')
      Sessions.create(user.get.head.id, session[:user_session], Time.now.to_i, ip_address, user_agent, provider)
      halt 200, j(for_user(UserDetail.new(user.get.head.id)))
    else
      halt 401, j(status: 'unauthorised', message: 'Not logged in')
    end
  end

end