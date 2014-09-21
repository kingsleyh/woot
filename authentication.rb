require 'sinatra'
require 'json_store'
require 'totally_lazy'

db = JsonStore.new('sessions.json')

get '/' do
  content_type :json
  Oj.dump({server_name: 'Authentication Server'})
end

post '/create' do
  content_type :json
  begin
  db.pull
  user = Oj.load(request.body.read.to_s)
  halt 500,Oj.dump({error: 'you must supply the correct parameters'}) unless user.keys.include?('nick')
  if option(db.get(user['nick'])).is_none?
    session = Any.string(15)
    db.set(user['nick'], session)
    db.merge
    db.push
    status 201
    Oj.dump({nick: user['nick'], session: session})
  else
    halt 412, Oj.dump({error: 'Nick was already authenticated'})
  end
  rescue => e
    halt 500,Oj.dump({error: e.message})
  end
end

get '/authenticated' do
  db.pull
  Oj.dump({status:option(db.get(params['nick'])).is_some?})
end

get '/remove' do
  db.pull
  db.remove(params['nick'])
  db.write ; db.pull
  Oj.dump({status:option(db.get(params['nick'])).is_none?})
end
