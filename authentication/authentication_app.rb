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

  post '/signup' do
    user = Users.create(params[:email], params[:password], params[:password_confirmation])
    user.is_valid? ? halt(201, j(status: 'success')) : j(errors: user.errors)
  end

  post '/signin' do
    if already_logged_in?
      halt(401, j(status: 'error', message: 'Already logged in'))
    else
      email = params[:email]
      password = params[:password]

      user = Users.find(where(email: equals(email)))
      if user.is_some? && user.get.head.password_hash == BCrypt::Engine.hash_secret(password, user.get.head.password_salt)
        # session[:user_id] = user.get.head.id
        session[:user_session] = Utils.generate_session_id
        Sessions.create(user.get.head.id, session[:user_session], Time.now.to_i)
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

  # def find_session
  #   Sessions.find(where(session_id: equals(session[:user_session])))
  # end

  def find_user
    user_session = Sessions.find(where(session_id: equals(session[:user_session])))
    user_session.is_some? ? UserDetail.new(user_session.get.head.user_id) : empty

    # user_session = find_session
    # if user_session.is_some?
    #   user = Users.find(where(id: equals(user_session.get.head.user_id)))
    #   user.is_some? ? user : none
    # else
    #   none
    # end
  end

  post '/update' do
    error_if_not_logged_in
    user = find_user.user
    if user.empty?
      halt 401, j(status: 'unauthorised', message: 'Not logged in')
    else
      u = Users.update(user.head.id, option(params[:email]), option(params[:password]), option(params[:password_confirmation]))
      u.is_valid? ? halt(201, j(status: 'success')) : j(errors: u.errors)
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
      halt 200, j(identities: user_detail.identities.entries)
    end
  end

  get '/sessions' do
    error_if_not_logged_in
    user_detail = find_user
    if user_detail.user.empty?
      halt 401, j(status: 'unauthorised', message: 'Not logged in')
    else
      halt 200, j(sessions: user_detail.sessions.entries, current_session: session[:user_session])
    end
  end

  get '/auth/facebook/callback' do
    if already_logged_in? # TODO - remove this and if already logged in then just add facebook to the identities for this user but dont try to login again with it
      halt(401, j(status: 'error', message: 'Already logged in'))
    else
      info = Facebook.info(request.env['omniauth.auth'])
      provider = info[:provider]
      uid = info[:uid]
      identity = Identities.find(where(provider: equals(provider), uid: equals(uid)))
      if identity.is_some?
        # login with existing user
        user = find_user.user
        if user.empty?
          halt 401, j(status: 'unauthorised', message: 'Invalid user')
        else
          session[:user_id] = user.head.id
          halt 200, j(user.head.get_hash)
        end
      else
        # create new user from social details
        user = Users.create(info[:email], uid, uid)
        if user.is_valid?
          u = Users.find(where(email: equals(info[:email])))
          Identities.create(u.get.head.id, provider, uid)
          session[:user_id] = u.get.head.id
          halt 200, j(u.get.head.get_hash)
        else
          halt 401, j(status: 'unauthorised', message: 'Not logged in')
        end
      end
    end
  end

  get '/auth/twitter/callback' do
    Twitter.info(request.env['omniauth.auth'])
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
     sessions: ud.sessions.map{|s| {session_id:s.session_id,start_time:Time.at(s.start_time.to_i).to_s}}.entries,
     identities: ud.identities.map{|i| i.provider }.entries
    }
  end

  def j(v)
    Oj.dump(v)
  end


end