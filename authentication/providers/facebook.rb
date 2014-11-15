require 'totally_lazy'
require 'lazy_records'
require 'adapters/sqlite3'

class Facebook
 
  def self.info(data)
    {provider: option(data.provider).get_or_else(''),
    uid: option(data.uid).get_or_else(''),
    email: option(data.info.email).get_or_else(''),
    full_name: option(data.info.name).get_or_else(''),
    first_name: option(data.info.first_name).get_or_else(''),
    last_name: option(data.info.last_name).get_or_else(''),
    image: option(data.info.image).get_or_else(''),
    url: option(data.info.urls.Facebook).get_or_else(''),
    verified: option(data.info.verified).get_or_else(''),
    token: option(data.credentials.token).get_or_else(''),
    token_expiry: option(data.credentials.expires_at).get_or_else(''),
    token_expires: option(data.credentials.expires).get_or_else(''),
    id: option(data.extra.raw_info.id).get_or_else(''),
    gender: option(data.extra.raw_info.gender).get_or_else(''),
    timezone: option(data.extra.raw_info.timezone).get_or_else(''),
    locale: option(data.extra.raw_info.locale).get_or_else(''),
    updated_time: option(data.extra.raw_info.updated_time).get_or_else('')}
  end


end
