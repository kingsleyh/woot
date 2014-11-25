require_relative '../repository/sessions'

class User < Record

  def initialize(email, password_hash, password_salt)
    super(email: email, password_hash: password_hash, password_salt: password_salt)
  end

  def self.def
    definition(:users, keyword(:email), keyword(:password_hash), keyword(:password_salt))
  end

end
