require_relative '../authentication_app'
require 'rack/test'
require_relative 'spec_helper'

describe 'Authentication' do

  it 'should get server status at root' do
    get '/'
    expect(jl(last_response.body)).to eq(server_name:'Authentication Server')
  end

  it 'should allow signup' do

  end

end